const {sha256, ecsign} = require('ethereumjs-util');
const moment = require('moment');

const JUST_NOW_THRESHOLD = 45000; // < 45 seconds is considered "just now"

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
  },

  timeAgoString(unixTimestamp) {
    const m = moment.unix(unixTimestamp);
    const diff = Math.abs(moment().diff(m));
    if (diff < JUST_NOW_THRESHOLD) {
      return 'just now';
    }
    return m.fromNow();
  }
}
