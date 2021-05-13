# Verifiable QR SDK for DIVOC Credentials

JavaScript Implementation of [DIVOC's COWIN Credentials for India](https://divoc.egov.org.in/), a W3C VC-based Verifiable QR Credentials. 

# Install

```sh
npm install divoc.sdk --save
```

# Usage

With the keys: 

```js
const PRIVATE_KEY_PEM= `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnXQalrgztecTpc+INjRQ8s73FSE1kU5QSlwBdICCVJBUKiuQUt7s+Z5epgCvLVAOCbP1mm5lV7bfgV/iYWDio7lzX4MlJwDedWLiufr3Ajq+79CQiqPaIbZTo0i13zijKtX7wgxQ78wT/HkJRLkFpmGeK3za21tEfttytkhmJYlwaDTEc+Kx3RJqVhVh/dfwJGeuV4Xc/e2NH++ht0ENGuTk44KpQ+pwQVqtW7lmbDZQJoOJ7HYmmoKGJ0qt2hrj15uwcD1WEYfY5N7N0ArTzPgctExtZFDmituLGzuAZfv2AZZ9/7Y+igshzfB0reIFdUKw3cdVTzfv5FNrIqN5pwIDAQABAoIBAHPILMUoLt5UTd5f/YnebqgeCRNAmGOBcwk7HtbMqQoGF93qqvZFd30XOAJZ/ncTpz77Vl95ToxxrWk1WQLCe+ZpOK3Dgk5sFSm8zXx1T64UBNPUSnWoh37C1D39+b9rppCZScgnxlyPdSLy3h3q8Hyoy+auqUEkm/ms5W2lT3fJscyN1IAyHrhsOBWjl3Ilq5GxBo5tbYv/Fb1pQiP/p2SIHA1+2ASXNYQP100F5Vn0V6SFtBXTCQnwcvbP083NvlGxs9+xRs3MCUcxCkKepWuzYwOZDmu/2yCz1/EsP6wlsYEHmCZLdIb0tQt0caqzB/RoxfBpNRIlhOtqHvBzUgECgYEAzIRn5Y7lqO3N+V29wXXtVZjYWvBh7xUfOxAwVYv0rKI0y9kHJHhIrU+wOVOKGISxBKmzqBQRPvXtXW8E0/14Zz82g60rRwtNjvW0UoZAY3KPouwruUIjAe2UnKZcQ//MBTrvds8QGpL6nxvPsBqU0y2K+ySAOxBtNtGEjzv8nxUCgYEAxRbMWukIbgVOuQjangkfJEfA1UaRFQqQ8jUmT9aiq2nREnd4mYP8kNKzJa9L7zj6Un6yLH5DbGspZ2gGODeRw3uVFN8XSzRdLvllNEyiG/waiysUtXfG2DPOR6xD8tXXDMm/tl9gTa8cbkvqYy10XT9MpfOAsusEZVmc0/DBBMsCgYAYdAxoKjnThPuHwWma5BrIjUnxNaTADWp6iWj+EYnjylE9vmlYNvmZn1mWwSJV5Ce2QwQ0KJIXURhcf5W4MypeTfSase3mxLc1TLOO2naAbYY3GL3xnLLK3DlUsZ9+kes3BOD097UZOFG3DIA8sjDxPxTLCoY6ibBFSa/r4GRIMQKBgQCranDCgPu79RHLDVBXM0fKnj2xQXbd/hqjDmcL+Xnx7E7S6OYTXyBENX1qwVQh9ESDi34cBJVPrsSME4WVT3+PreS0CnSQDDMfr/m9ywkTnejYMdgJHOvtDuHSpJlUk3g+vxnm3H0+E5d+trhdGiOjFnLrwyWkd5OTMqWcEEFQkQKBgFfXObDz/7KqeSaAxI8RzXWbI3Fa492b4qQUhbKYVpGn98CCVEFJr11vuB/8AXYCa92OtbwgMw6Ah5JOGzRScJKdipoxo7oc2LJ9sSjjw3RB/aWl35ChvnCJhmfSL8Usbj0nWVTrPwRLjMC2bIxkLtnm9qYXPumW1EjEbusjVMpN
-----END RSA PRIVATE KEY-----`

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnXQalrgztecTpc+INjRQ8s73FSE1kU5QSlwBdICCVJBUKiuQUt7s+Z5epgCvLVAOCbP1mm5lV7bfgV/iYWDio7lzX4MlJwDedWLiufr3Ajq+79CQiqPaIbZTo0i13zijKtX7wgxQ78wT/HkJRLkFpmGeK3za21tEfttytkhmJYlwaDTEc+Kx3RJqVhVh/dfwJGeuV4Xc/e2NH++ht0ENGuTk44KpQ+pwQVqtW7lmbDZQJoOJ7HYmmoKGJ0qt2hrj15uwcD1WEYfY5N7N0ArTzPgctExtZFDmituLGzuAZfv2AZZ9/7Y+igshzfB0reIFdUKw3cdVTzfv5FNrIqN5pwIDAQAB
-----END PUBLIC KEY-----`;
```

And a Payload 

```js
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
```

Call the signAndPack to create the URI for the QR Code: 

```js
const qrUri = await signAndPack(TEST_PAYLOAD, PRIVATE_KEY_PEM);
```

And call the unpack and verify to convert the URI into the payload: 

```js
const json = await unpackAndVerify(qrUri);
```

# Development

```sh
npm install
``` 

# Test

```sh
npm test
```
