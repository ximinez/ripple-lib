var sjcl    = require('./utils').sjcl;

var KeyPair    = require('./keypair').KeyPair;
var Seed    = require('./seed').Seed;

// {seed : KeyPair}
var cache = {}
var ecdsa = null;

try {
  ecdsa = require('secp256k1')
} catch (e) {
  console.warn("Can't use speed up functionality");
}

if (ecdsa != null) {
  KeyPair.prototype.secretBuffer = function() {
    var cached = this._secretBuffer;

    if (!cached) {
      var hex = sjcl.codec.hex.fromBits(this._secret._exponent.toBits());
      cached = this._secretBuffer = new Buffer(hex, 'hex');
    }

    return cached;
  }

  KeyPair.prototype.signHex = function(hash) {
    var hashHex = new Buffer(hash, 'hex');
    return ecdsa.sign(this.secretBuffer(), hashHex).toString('hex');
  }
} else {
  var old_sign = KeyPair.prototype.sign;

  KeyPair.prototype.signHex = function(message) {
    return sjcl.codec.hex.fromBits(old_sign.call(this, message)).toUpperCase();
  }
}

module.exports.get = function(seed) {
  var cached = cache[seed];

  if (cached == null) {
    var the_seed = Seed.from_json(seed);
    cached = cache[seed] = the_seed.get_key();
  };

  return cached;
}