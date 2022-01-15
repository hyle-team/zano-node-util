module.exports = require('bindings')('cryptonote.node')

const bignum  = require('bignum');

module.exports.baseDiff = function() {
  return bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);
};