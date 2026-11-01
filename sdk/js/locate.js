'use strict';
// RFC 0026: where the N-API addon is.
const SUPPORTED = [];

function platform() {
  throw new Error('rfc 0026');
}

function locate() {
  throw new Error('rfc 0026');
}

module.exports = { locate, platform, SUPPORTED };
