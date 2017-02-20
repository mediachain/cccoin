const {sha256, ecsign} = require('ethereumjs-util');

module.exports = exports = {
  get_nonce () {
    return Math.floor(Date.now());
  },

  weak_random (N) {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for ( let i=0; i < N; i++ ) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }

    return text;
  },

  sign_string (str, privateKeyHex) {
    return ecsign(sha256(new Buffer(str)), new Buffer(privateKeyHex, 'hex'))
  },

  sig_to_json (sig) {
    return {sig_v: sig.v,
      sig_r: sig.r.toString('hex'),
      sig_s: sig.s.toString('hex'),
    }
  }
}
