import {RSAKeyPair} from 'crypto-ld'
import {documentLoaders} from 'jsonld'
import jsigs from './jsonld-signatures-6.0.0/jsonld-signatures.js'
import { resolveKey } from './resolver';

const {RsaSignature2018} = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const {node: documentLoader} = documentLoaders;

import JSZip from 'jszip'

import securityV1Context from './context/security-v1.json'
import securityV2Context from './context/security-v2.json'
import securityV3Context from './context/security-v3.json'

import {vaccinationContext as divocContext, 
        vaccinationContextV2 as divocContextV2} from "./context/vaccination-context"

import credentialsV1Context from './context/credentials.json'
import mattrVaccinationContext from './context/vaccination.v1.json'

import pathogen from './context/pathogen-v1.json'
import dgc from './context/dgc-v1.json'

const NOT_SUPPORTED = "not_supported";                  // QR Standard not supported by this algorithm
const INVALID_ENCODING = "invalid_encoding";            // could not decode Base45 for DCC, Base10 for SHC
const INVALID_COMPRESSION = "invalid_compression";      // could not decompress the byte array
const INVALID_SIGNING_FORMAT = "invalid_signing_format";// invalid COSE, JOSE, W3C VC Payload
const KID_NOT_INCLUDED = "kid_not_included";            // unable to resolve the issuer ID
const ISSUER_NOT_TRUSTED = "issuer_not_trusted";        // issuer is not found in the registry
const TERMINATED_KEYS = "terminated_keys";              // issuer was terminated by the registry
const EXPIRED_KEYS = "expired_keys";                    // keys expired
const REVOKED_KEYS = "revoked_keys";                    // keys were revoked by the issuer
const INVALID_SIGNATURE = "invalid_signature";          // signature doesn't match
const VERIFIED = "verified";                            // Verified content.

function customLoader(url) {
    const cached = {
      "https://w3id.org/security/v1": securityV1Context,
      "https://w3id.org/security/v2": securityV2Context,
      'https://www.w3.org/2018/credentials#': credentialsV1Context,
      "https://www.w3.org/2018/credentials/v1": credentialsV1Context,
      "https://cowin.gov.in/credentials/vaccination/v1": divocContext,
      "https://divoc.prod/vaccine/credentials/vaccination/v1": divocContextV2,
      "https://divoc.lgcc.gov.lk/credentials/vaccination/v1": divocContextV2,
      "https://w3id.org/vaccination/v1": mattrVaccinationContext,
      "https://w3id.org/security/v3-unstable": securityV3Context, 
      "https://w3id.org/pathogen/v1": pathogen,
      "https://w3id.org/dgc/v1": dgc
    };
    let context = cached[url];
    if (context !== undefined) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: context
      };
    }
    if (url.startsWith("{")) {
      return JSON.parse(url);
    }
    console.log("Fallback url lookup for document: " + url);
    //return documentLoader()(url);
}

export async function sign(certificate, privateKeyPem, publicKeyPem) {
    const copyCert = JSON.parse(JSON.stringify(certificate));
    
    const privateKey = {
      '@context': jsigs.SECURITY_CONTEXT_URL,
      id: 'did:india',
      type: 'RsaVerificationKey2018',
      controller: 'https://cowin.gov.in/',
      privateKeyPem: privateKeyPem,
      publicKeyPem: publicKeyPem
    };
    const controller = {
      '@context': jsigs.SECURITY_CONTEXT_URL,
      id: 'https://cowin.gov.in/',
      privateKey: [privateKey],
      publicKey: [privateKey],
      // this authorizes this key to be used for making assertions
      assertionMethod: [privateKey.id]
    };

    const key = new RSAKeyPair(privateKey);

    const signed = await jsigs.sign(copyCert, {
      documentLoader: customLoader,
      suite: new RsaSignature2018({key}),
      purpose: new AssertionProofPurpose({
        controller: controller
      }),
      compactProof: false
    });

    return signed;
}

async function doVerify(signed, Public_Key) {
    try {
        const signedJSON = signed;
        const didID = signed.proof.verificationMethod;
        const publicKey = {
            '@context': jsigs.SECURITY_CONTEXT_URL,
            id: didID,
            type: 'RsaVerificationKey2018',
            controller: 'https://cowin.gov.in/',
            publicKeyPem: Public_Key
        };
        const controller = {
            '@context': jsigs.SECURITY_CONTEXT_URL,
            id: 'https://cowin.gov.in/',
            publicKey: [publicKey],
            // this authorizes this key to be used for making assertions
            assertionMethod: [publicKey.id]
        };
        const key = new RSAKeyPair({...publicKey});
        
        return await jsigs.verify(signedJSON, {
            suite: new RsaSignature2018({key}),
            purpose: new AssertionProofPurpose({controller}),
            documentLoader: customLoader,
            compactProof: false
        });
    } catch (e) {
        console.log('Invalid data', e);
    }
}

export async function verify(signed, publicKey) {
  var issuer = undefined;

  var kid = signed.proof ? signed.proof.verificationMethod : undefined;

  if (!kid) return { status: KID_NOT_INCLUDED, contents: signed, raw: signed }

  if (publicKey) {
    issuer = { didDocument: publicKey, status: "current" }
  } else {
    issuer = await resolveKey(kid) 
  }

  if (!issuer) return { status: ISSUER_NOT_TRUSTED, contents: signed, raw: signed }

  switch (issuer.status) {
    case "revoked": return    { status: REVOKED_KEYS, contents: signed, issuer: issuer, raw: signed }
    case "terminated": return { status: TERMINATED_KEYS, contents: signed, issuer: issuer, raw: signed }
    case "expired": return    { status: EXPIRED_KEYS, contents: signed, issuer: issuer, raw: signed }
  }

  const result = await doVerify(signed, issuer.didDocument)

  if (result.error) {
    return { status: INVALID_SIGNING_FORMAT, contents: signed, issuer: issuer, raw: signed }
  }

  if (result.verified) {
    return { status: VERIFIED, contents: signed, issuer: issuer, raw: signed }
  } else {
    return { status: INVALID_SIGNATURE, contents: signed, issuer: issuer, raw: signed }
  }
}

export async function pack(signedData) {
    let certFile = JSON.stringify(signedData);
    var zip = new JSZip();

    zip.file("certificate.json", certFile, {
        compression: "DEFLATE",
        compressionOptions: {
            level: 9
        }
    });

    return await zip.generateAsync({type: "binarystring"});
}

export async function unpack(binary) {
  if (binary.includes("@context")) {
    return JSON.parse(binary);
  }

  try {
    var zip = new JSZip();
    const dirContents = await zip.loadAsync(binary);
    const fileContents = await dirContents.files["certificate.json"].async('text')
    return JSON.parse(fileContents);
  } catch (err) {
    console.log(err)
    return
  }
}    

export async function signAndPack(payload, privateKeyPem, publicKeyPem) {
  return await pack(await sign(payload, privateKeyPem, publicKeyPem));
}

export async function unpackAndVerify(uri, publicKeyPem) {
  const json = await unpack(uri);

  if (!json) { 
    return { status: INVALID_COMPRESSION, qr: uri };
  }

  const verified = await verify(json, publicKeyPem);
  return {...verified, qr: uri} ;
}