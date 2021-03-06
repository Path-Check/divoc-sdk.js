/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const api = {};
module.exports = api;

// TODO: only require dynamically as needed or according to build
api.suites = {
  Ed25519Signature2018: require('./suites/Ed25519Signature2018'),
  JwsLinkedDataSignature: require('./suites/JwsLinkedDataSignature'),
  LinkedDataProof: require('./suites/LinkedDataProof'),
  LinkedDataSignature: require('./suites/LinkedDataSignature'),
  RsaSignature2018: require('./suites/RsaSignature2018')
};
