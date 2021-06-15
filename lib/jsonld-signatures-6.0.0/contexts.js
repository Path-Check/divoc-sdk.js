/*
 * Copyright (c) 2017-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const constants = require('./constants');

module.exports = {
  [constants.SECURITY_CONTEXT_V1_URL]: require('../context/security-v1.json'),
  [constants.SECURITY_CONTEXT_V2_URL]: require('../context/security-v2.json')
};
