import {RSAKeyPair} from 'crypto-ld'
import {documentLoaders} from 'jsonld'
import jsigs from './jsonld-signatures-6.0.0/jsonld-signatures.js'

const {RsaSignature2018} = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const {node: documentLoader} = documentLoaders;

import JSZip from 'jszip'

import securityV1Context from './context/security-v1.json'
import securityV2Context from './context/security-v2.json'
import securityV3Context from './context/security-v3.json'
import {vaccinationContext as divocContext} from "vaccination-context"

import credentialsV1Context from './context/credentials.json'
import mattrVaccinationContext from './context/vaccination.v1.json'

import pathogen from './context/pathogen-v1.json'
import dgc from './context/dgc-v1.json'

// did:india keys
const INDIA_PROD_PUBLIC_KEY_PEM = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0i7R4XsyG3m6KD36qKEVxE+odCh68W2O4vLqh6SnsgItzvLYvJKPai+jEkf22FlPn0QnGo+Znyi6dw1lhvg9FGXqodv33yrqKhGLkQPeURaMnJidxktK/3QLXuv9HiKq9fSDLJyPBJEFCCCiZNTGgWM0dqq43/XRi+7IX3gWU68U6v/7EyOW3U4ZgYUVlfwbUh6eKRan68/TObQua39oeUfDMhJa0NHnMXb1lq/vQIjEgGkOK5LLyz+X8ETUEhn8Qdx2SIORmftCPW4XO0UZmMHuGw9t+UUgniy5BL8kmvtjpVRWFUliJFGBTvBZCO6gcoX5eXi8LytCg+mJ6EDO+QIDAQAB\n-----END PUBLIC KEY-----'

// did:srilanka:moh key
const SRILANKA_PROD_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnhht8e5qjjnzcpA8fWbdv7whEbseWdvDcwEptGqyGpLGen2bLUZ2KeKloF1+BxeNOHyd8/Po79uogLVs5TvlJvjYCyj668ZjNaqsqvvNz27izQuvUDsaDIawFO10o7QqBC1YhCeRzSfjpbzQr3bcCJ4+hdNH30os6jBa7TMlNJk+N297bQ+vI1TDl6AR3bl/bYIDx56aKIyK6APi5mdZUPyYbVw+gHv/4FTTnuWH76XQHkQBHOWvCSH1JTmB+HjX9xtDBt9BBW7z00H3sAf0gsYauDgjfNxKhm/boHdjJxUGDwxIkYIrz85fJCjL3sNvHI0l4kn4IrREsTUKZ1cBEwIDAQAB\n-----END PUBLIC KEY-----";

// did:philippines keys
const PHILIPPINES_PROD_PUBLIC_KEY_PEM = "";

function customLoader(url) {
    const cached = {
      "https://w3id.org/security/v1": securityV1Context,
      "https://w3id.org/security/v2": securityV2Context,
      'https://www.w3.org/2018/credentials#': credentialsV1Context,
      "https://www.w3.org/2018/credentials/v1": credentialsV1Context,
      "https://cowin.gov.in/credentials/vaccination/v1": divocContext,
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
    console.log("Fallback url lookup for document: " + url, cached);
    //return documentLoader()(url);
}

async function verifyHack(signed, Public_Key) {
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
        
        const result = await jsigs.verify(signedJSON, {
            suite: new RsaSignature2018({key}),
            purpose: new AssertionProofPurpose({controller}),
            documentLoader: customLoader,
            compactProof: false
        });
        return result.verified;
    } catch (e) {
        console.log('Invalid data', e);
    }
}

export async function verify(signed, publicKey) {
  return await verifyHack(signed, INDIA_PROD_PUBLIC_KEY_PEM) 
     ||  await verifyHack(signed, SRILANKA_PROD_PUBLIC_KEY_PEM)
     ||  (publicKey ? await verifyHack(signed, publicKey) : false);
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

export async function unpack(binary) {
    if (binary.startsWith("PK")) {
      var zip = new JSZip();
      const dirContents = await zip.loadAsync(binary);
      const fileContents = await dirContents.files["certificate.json"].async('text')
      return JSON.parse(fileContents);
    } else if (binary.includes("did:india") || binary.includes("did:srilanka")) {
      return JSON.parse(binary);
    } 

    return undefined;
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

export async function signAndPack(payload, privateKeyPem, publicKeyPem) {
  return await pack(await sign(payload, privateKeyPem, publicKeyPem));
}

export async function unpackAndVerify(uri, publicKeyPem) {
  try {
    const json = await unpack(uri);
    if (await verify(json, publicKeyPem)) {
      return json;
    }
    return undefined;
  } catch (err) {
    console.log(err);
    return undefined;
  }
}