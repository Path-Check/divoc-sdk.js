const {sign, verify, pack, unpack, signAndPack, unpackAndVerify} = require('../lib/index');
const expect = require('chai').expect; 

const TEST_PAYLOAD = {
  "@context":["https://www.w3.org/2018/credentials/v1","https://cowin.gov.in/credentials/vaccination/v1"],
  "type":["VerifiableCredential","ProofOfVaccinationCredential"],
  "issuer":"https://cowin.gov.in/",
  "issuanceDate":"2021-04-14T04:00:00.000Z",
  "nonTransferable":"true",
  "credentialSubject":{
    "type":"Person",
    "id":"did:in.gov.uidai.aadhaar:2342343334",
    "refId":"12346",
    "name":
    "Bhaya Mitra",
    "gender":"Male",
    "age":"27",
    "nationality":
    "Indian",
    "address":{
      "streetAddress":
      "101-102, Mangal Ashirwad",
      "streetAddress2":"S V Road",
      "district":"Santacruz West",
      "city":"Mumbai",
      "addressRegion":
      "Maharashtra",
      "addressCountry":"IN",
      "postalCode":"400054"}
    },
    "evidence":[{
      "id":"https://cowin.gov.in/vaccine/undefined",
      "feedbackUrl":"https://cowin.gov.in/?undefined",
      "infoUrl":"https://cowin.gov.in/?undefined",
      "type":["Vaccination"],
      "batch":"MB3428BX",
      "vaccine":"CoVax",
      "manufacturer":
      "COVPharma",
      "date":"20210414",
      "effectiveStart":"20201202",
      "effectiveUntil":"20251202",
      "dose":"1",
      "totalDoses":"1",
      "verifier":{
        "name":"Sooraj Singh"
      },
      "facility":{
        "name":"ABC Medical Center",
        "address":{
          "streetAddress":"123, Koramangala",
          "streetAddress2":"",
          "district":"Bengaluru South",
          "city":"Bengaluru",
          "addressRegion":"Karnataka",
          "addressCountry":"IN",
          "postalCode":""}
        }
      }
    ]
  };

const JSON_PAYLOAD = '{"@context":["https://www.w3.org/2018/credentials/v1","https://cowin.gov.in/credentials/vaccination/v1"],"type":["VerifiableCredential","ProofOfVaccinationCredential"],"credentialSubject":{"type":"Person","id":"did:in.gov.uidai.aadhaar:2342343334","refId":"12346","name":"Bhaya Mitra","gender":"Male","age":"27","nationality":"Indian","address":{"streetAddress":"","streetAddress2":"","district":"","city":"","addressRegion":"","addressCountry":"IN","postalCode":""}},"issuer":"https://cowin.gov.in/","issuanceDate":"2021-01-15T17:21:13.117Z","evidence":[{"id":"https://cowin.gov.in/vaccine/undefined","feedbackUrl":"https://cowin.gov.in/?undefined","infoUrl":"https://cowin.gov.in/?undefined","type":["Vaccination"],"batch":"MB3428BX","vaccine":"CoVax","manufacturer":"COVPharma","date":"2020-12-02T19:21:18.646Z","effectiveStart":"2020-12-02","effectiveUntil":"2025-12-02","dose":"","totalDoses":"","verifier":{"name":"Sooraj Singh"},"facility":{"name":"ABC Medical Center","address":{"streetAddress":"123, Koramangala","streetAddress2":"","district":"Bengaluru South","city":"Bengaluru","addressRegion":"Karnataka","addressCountry":"IN","postalCode":""}}}],"nonTransferable":"true","proof":{"type":"RsaSignature2018","created":"2021-01-15T17:21:13Z","verificationMethod":"did:india","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mJlHZZRD7VQwVJchfI21ZavjxNKglbf3LSaF1SAjELOWn9MARALkugsmOzG0mBon9R7zXSVPkPM8EDbUZxR4FsRlAFFszFv-0BjyAeIqRv-9MRnlm4cScQi8aCBgBnvsWfNIE175cGNbPUluVv5n6G66tVinioL5IL6uCZNQnSGp4jJrEAZa0t5s3jXfq7soHz1LTfQbLs7cH5-fDi3JW1-WeF4_ELy_9l_OxAc2CoACqYLOLJB-NnPsnz2bwAvH8yXHsjZJphzaBNqpn8DmJvcRHzhz7OjpGfhyouiOyGo_XncadFmftqwfilJkC1EISkSb6QVsyhHLOudY4PTTaA"}}';  

describe('DIVOC crypto', function() {

  it('should Sign the json', async () => {
    const signed = await sign(TEST_PAYLOAD);
    expect(signed).to.not.be.null;
    expect(signed.proof).to.not.be.null;
  });

  it('should Verify the json', async () => {
    const signed = '{"@context":["https://www.w3.org/2018/credentials/v1","https://cowin.gov.in/credentials/vaccination/v1"],"type":["VerifiableCredential","ProofOfVaccinationCredential"],"issuer":"https://cowin.gov.in/","issuanceDate":"2021-04-15T04:00:00.000Z","nonTransferable":"true","credentialSubject":{"type":"Person","id":"did:in.gov.uidai.aadhaar:2342343334","refId":"12346","name":"Bhaya Mitra","gender":"Male","age":"27","nationality":"Indian","address":{"streetAddress":"101-102, Mangal Ashirwad","streetAddress2":"S V Road","district":"Santacruz West","city":"Mumbai","addressRegion":"Maharashtra","addressCountry":"IN","postalCode":"400054"}},"evidence":[{"id":"https://cowin.gov.in/vaccine/undefined","feedbackUrl":"https://cowin.gov.in/?undefined","infoUrl":"https://cowin.gov.in/?undefined","type":["Vaccination"],"batch":"MB3428BX","vaccine":"CoVax","manufacturer":"COVPharma","date":"20210415","effectiveStart":"20201202","effectiveUntil":"20251202","dose":"1","totalDoses":"1","verifier":{"name":"Sooraj Singh"},"facility":{"name":"ABC Medical Center","address":{"streetAddress":"123, Koramangala","streetAddress2":"","district":"Bengaluru South","city":"Bengaluru","addressRegion":"Karnataka","addressCountry":"IN","postalCode":""}}}],"proof":{"type":"RsaSignature2018","created":"2021-04-15T00:03:21Z","verificationMethod":"did:india","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..H1bsf6gBgPKpmjPsQ19D0KkLPp-USYFcYzq1J1mqelC_jzVne_4tmevyp8X6Rxs05afzm-OFb8nUQkK0oJprZZjdayoCVKFMKU3ckthMz1_4_Zh3Xz8LLe-kEenpyNXL8Y7HvLMNLcsEu3OF0SGc80TEQ6fttj1JvwepeuiM7xbcPkUOpTXjS9I9ng07_hKJLLW7yEEhdoKIhfIC2swpdMm6jU10ckxnFmPiBHATyxTiajwMSQRWaDLaoTv_mNdQki6L0XPbD8hlEdNlt4ulc9kM2GObjJCw2DbsWFzSvkMy4gSWqB39Weyb2yadWCs555_bE1RcSnHLkDLCFd-XoA"}}';
    const result = await verify(JSON.parse(signed));

    expect(result).to.be.true;
  });

  it('should Verify w/ Production Key', async () => {
    const signed = '{"@context":["https://www.w3.org/2018/credentials/v1","https://cowin.gov.in/credentials/vaccination/v1"],"type":["VerifiableCredential","ProofOfVaccinationCredential"],"credentialSubject":{"type":"Person","id":"did:Passport:Dummy256","refId":"39791185041847","name":"Third March User One","gender":"Male","age":"65","nationality":"Indian","address":{"streetAddress":"","streetAddress2":"","district":"Chamba","city":"","addressRegion":"Himachal","addressCountry":"IN","postalCode":176207}},"issuer":"https://cowin.gov.in/","issuanceDate":"2021-03-03T04:28:46.012Z","evidence":[{"id":"https://cowin.gov.in/vaccine/92047670169","feedbackUrl":"https://cowin.gov.in/?92047670169","infoUrl":"https://cowin.gov.in/?92047670169","certificateId":"92047670169","type":["Vaccination"],"batch":"Dummy-TGN-Chamba","vaccine":"COVISHIELD","manufacturer":"Serum Institute of India","date":"2021-03-03T04:28:43.134Z","effectiveStart":"2021-03-03","effectiveUntil":"2021-03-03","dose":1,"totalDoses":2,"verifier":{"name":"Dummy Vaccinator"},"facility":{"name":"Himachal Site Name 176207","address":{"streetAddress":"Address Of Site 176207","streetAddress2":"","district":"Chamba","city":"","addressRegion":"Himachal","addressCountry":"IN","postalCode":""}}}],"nonTransferable":"true","proof":{"type":"RsaSignature2018","created":"2021-03-03T04:28:46Z","verificationMethod":"did:india","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..nE-3iYDcKok-CmTm3pbpyZQheqpVDor_f0YQt4ukWDGyZuqtZuu8NROtJjOZ-LNAavN-JZtCAdunofe19-mcC2HC20W_yxzGfB1Idft15CruJWOuvkkKXX0UoezZhsk_Cd-HmeHeCCUgoyLiDtpSqzXd9WqiHG_XN39PUMvIHnZAPo54sodtzAEX88L1GSSd37JBrOlKoeMMJaC0JDIEDSFV-SaVk_vH5e06Vq86WrkMj5oj4pqmgnql7W_qt3NAgNqQQgUUNhsMOHwHXKBr5j80yjp1LRMidB81u0SQJvbxQVxLnphUbPcTI4h6nLJeZJjOiecOLESgIELpC2_SDg"}}'
    const result = await verify(JSON.parse(signed));

    expect(result).to.be.true;
  });

  it('should Sign and Verify a json', async () => {
    const signed = await sign(TEST_PAYLOAD);
    const result = await verify(signed);
    expect(result).to.be.true;
  });

  it('should Pack And Unpack', async () => {
    const binaryData = "Test Packing Data";
    const packed = await pack(binaryData);
    const unpacked = await unpack(packed);
    expect(unpacked).to.eql(binaryData);
  });

  it('should Sign Pack And Unpack Verify JSON', async () => {
    const signed = await signAndPack(TEST_PAYLOAD);
    const resultJSON = await unpackAndVerify(signed);
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });

  it('should Unpack Verify JSON (not binary)', async () => {
    const resultJSON = await unpackAndVerify(JSON_PAYLOAD);
    expect(resultJSON).to.eql(JSON_PAYLOAD);
  });

});