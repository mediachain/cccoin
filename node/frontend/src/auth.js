const $ = require('jquery');
const ethUtils = require('ethereumjs-util');

const SESSION_DATA_KEY = 'session_data';
const AUTH_COOKIE_KEY = 'auth';

const { get_nonce, sign_string, sig_to_json, weak_random } = require('./util');
const { blind_something } = require('./api');

/**
 * @module auth
 * @description Authorization, login / logout, session persistence, etc.
 */

module.exports = exports = {
  ALL_ROLES: ['owner', 'active', 'posting', 'private_messages', 'witness'],
  DEFAULT_ROLES: ['owner', 'active', 'posting', 'private_messages'],

  setCookie (key, value) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (1 * 24 * 60 * 60 * 1000));
    document.cookie = key + '=' + value + ';expires=' + expires.toUTCString();
  },

  getCookie (key) {
    const keyValue = document.cookie.match(new RegExp('(^|;) ?' + key + '=([^;]*)(;|$)'));
    return keyValue ? keyValue[2] : null;
  },

  delete_cookie(name) {
    document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  },

  delete_auth_cookie() {
    exports.delete_cookie(AUTH_COOKIE_KEY);
  },

  /**
   * Remove all session info from localStorage and delete auth cookie
   */
  do_logout () {
    console.log('do_logout()');
    localStorage.removeItem(SESSION_DATA_KEY);
    exports.delete_auth_cookie();
    //check_session();
    location.reload();
  },

  /**
   * @typedef {Object} UserKeys
   * @property {string} privateKey - hex encoded private key for user
   * @property {string} publicKey - hex-encoded public key for user
   * @property {string} address - hex-encoded ethereum address for public key, prefixed with 'CC'
   * @property {string} role - role used when generating the key
   */

  /**
   * Generate keypair from role + secret.
   * @param {string} role - a string
   * @param {string} password
   * @returns {UserKeys}
   */
  gen_key (role, password) {
    console.log('gen_key()');

    const priv = ethUtils.sha256(new Buffer(role + '|' + password));
    const pub = ethUtils.privateToPublic(priv);

    const privateKey = priv.toString('hex');
    const publicKey = pub.toString('hex');
    const address = 'CC' + ethUtils.publicToAddress(pub).toString('hex');

    return {publicKey, privateKey, address, role};
  },

  /**
   * @typedef {object} LocalSessionData
   * @property {string} username
   *  Username for logged in user
   * @property {string} owner_addr
   *  The ethereum address of the 'owner' role for the user
   * @property {string} posting_priv
   *  Hex-encoded private key for 'posting' role
   * @property {string} posting_pub
   *  Hex-encoded public key for 'posting' role
   */

  /**
   *
   * @returns {?LocalSessionData}
   */
  grab_keys () {
    console.log('grab_keys()');

    const rawData = localStorage.getItem(SESSION_DATA_KEY);

    if (!rawData) {
      console.log('grab_keys_failed');
      exports.delete_auth_cookie();
      return null;
    }

    let data
    try {
      data = JSON.parse(new Buffer(rawData, 'hex').toString('utf-8'))
    } catch (err) {
      console.log('grab_keys failed to decode stored data');
      exports.delete_auth_cookie();
    }

    if (!data.username && data.owner_addr) {
      data.username = data.owner_addr.slice(0, 8);
    }
    console.log('grab_keys: ', data);

    return data;
  },

  /**
   * Store the users keys in localStorage
   * @param {LocalSessionData} data
   */
  store_keys (data) {
    const str = new Buffer(JSON.stringify(data), 'utf-8').toString('hex')
    localStorage.setItem(SESSION_DATA_KEY, str)
  },

  /**
   * Delete keys from localStorage
   */
  forget_keys () {
    localStorage.removeItem(SESSION_DATA_KEY);
  },

  /**
   * Requests a username to be reserved while logging in.
   * Fails fast if username is known to be taken. See {@link auth#login}.
   */

  signup (passphrase, username, cb) {
    console.log('signup()', passphrase, username);
    exports.login(passphrase, username, cb);
  },

  /**
   *
   * Login with password, optionally requesting to be assigned a particular username.
   *
   * Note: decided not to add blinded-reservation of usernames for now, for user convenience.
   *
   * Returns JSON containing:
   *  - success: `false` to indicate general failure.
   *  - username_success: `false` to indicate immediate username collision.
   *  - password_success: `false` to indicate a bad password.
   *  - got_username: string of your username to use for this session. See below.
   *  - message: string of optional failure message.
   *
   * Note that due to concurrency issues, your `got_username` may take forms such as:
   * - `bob` - you registered long ago and got what you wanted.
   * - `bob-unconfirmed-123` - didn't immediately fail but no idea if you'll win it.
   * - `bob-collision-123` - failed to win username you previously requested due to concurrency conflict or attempted attack. You can try requesting another.
   *
   * @param password
   * @param requested_username
   * @param success_callback - called when login completes successfully
   */
  login(password, requested_username, success_callback, tos_prompt_callback){
      console.log('finish()', password, requested_username);

    if (typeof requested_username === 'undefined'){
      requested_username = "";
    }

    if (typeof success_callback === 'undefined') {
      console.warn('login called without callback');
      success_callback = () => {};
    }

      if (requested_username){
	  // Request username:
	  
	  const {publicKey: posting_pub, privateKey: posting_priv} = exports.gen_key('posting', password);
	  
	  const un_string = JSON.stringify({
	      username: requested_username,
	      rand: weak_random(16), // Mitigate replay detection attacks.
	  });
	  
	  blind_something(un_string,
			  1,
			  'username',
			  posting_priv,
			  posting_pub,
			  function(){exports.login_finish(password, requested_username, success_callback)}
			 );
      }
      else {
	  exports.login_finish(password, requested_username, success_callback);
      }
      
  },
    login_finish(password, requested_username, the_callback){
	console.log('login_finish()', password, requested_username);

    const {address: owner_addr} = exports.gen_key('owner', password);
    const {publicKey: posting_pub, privateKey: posting_priv} = exports.gen_key('posting', password);

    exports.forget_keys();

    /*
     - Server makes challenge: `random_bytes(16)`
     - User signs challenge.
     - Server verifies signed challenge.
     - Server returns:
     + encrypted session cookie: `encrypt({"created":timestamp,"pub":user_id}, server_password)`
     + working username
     */

    // Get challenge:

    console.log('request_challenge');

    const request1 = $.ajax({
      dataType: "json",
      url: "/login_1",
      method: "POST",
      data: JSON.stringify({the_pub: posting_pub})
    });
      
    request1.done(function( hh ) {
      console.log('login.request1.done()');

      console.log('got_challenge', JSON.stringify(hh));

      const dd = hh['challenge'];

      const sig = ethUtils.ecsign(ethUtils.sha256(new Buffer(dd)), new Buffer(posting_priv, 'hex'));

      // Send challenge response:
      const request2 = $.ajax({
        dataType: "json",
        url: "/login_2",
        method: "POST",
        data: JSON.stringify({
          the_pub: posting_pub,
          challenge: dd,
          requested_username: requested_username,
          sig: {
            sig_v: sig.v,
            sig_r: sig.r.toString('hex'),
            sig_s: sig.s.toString('hex'),
          },
        })
      });

      request2.done(function( msg2 ) {
        console.log('login.request2.done()', JSON.stringify(msg2));

        //console.log('challenge_done',msg2);

        if (!msg2['success']){
          console.log('Failed Login.', msg2);
          the_callback(msg2);
          return;
        }
        const username = msg2['got_username'];

        // FIXME: remove once backend is sending prompt_tos field!
        msg2['prompt_tos'] = true;

        // Success:
        console.log('login success:', username);
        exports.store_keys({username, posting_priv, posting_pub, owner_addr})

        the_callback(msg2);
      });

      request2.fail(function( jqXHR, textStatus ) {
        console.log('login.request2.fail()', jqXHR, textStatus);
        the_callback({"success":false,
          "username_success":true,
          "password_success":true,
          "got_username":"",
          "message":'Connection fail: login.request2.fail()',
        });
      });

    });

    request1.fail(function( jqXHR, textStatus ) {
      console.log('login.request1.fail()', textStatus);
      // alert( "Request1 failed: " + textStatus );
      the_callback({"success":false,
        "username_success":true,
        "password_success":true,
        "got_username":"",
        "message":'Connection fail: login.request1.fail()',
      });
    });
    }
}
