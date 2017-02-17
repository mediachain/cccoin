const $ = require('jquery');
const ethUtils = require('ethereumjs-util');

const { get_nonce, sign_string, sig_to_json, weak_random } = require('./util');

module.exports = exports = {
  /**
   * Send stuff to blockchain with 2-phase blind & reveal process.
   * Currently used for votes and posts.
   **
   * @param {string} item_string
   *  The content you want to submit, as a string.
   *  @important Be sure to include some random data in the input string to mitigate replay detection attacks.
   *
   * @param {number} num_items
   *  allows placing a cost on blind actions, so they're not just a free option.
   *
   * @param {string} item_type
   *  Should be either 'posts' or 'votes'
   *
   * @param {string} posting_priv
   *  Hex-encoded private key for users's 'posting' role
   *
   * @param {string} posting_pub
   *  Hex-encoded public key corresponding to posting_priv
   *
   * @param {Function=} callback
   *  Will be called with an `Error` if something fails, or undefined on success.
   */
  blind_something(item_string, num_items, item_type, posting_priv, posting_pub, callback){
    console.log('START blind_something()', num_items, item_type);

    if (typeof callback === 'undefined') {
      callback = () => {};
    }

    const blind_hash = ethUtils.sha256(new Buffer(item_string));

    const dd2 = JSON.stringify({
      command: 'blind',
      item_type: item_type,
      blind_hash: blind_hash.toString('hex'),
      num_items: num_items,
      nonce: get_nonce(),
    });

    const sig2 = sign_string(dd2, posting_priv);

    // Send blind:

    console.log('post_blind');

    const request1 = $.ajax({
      dataType: "json",
      url: "/blind",
      method: "POST",
      data: JSON.stringify({
        payload: dd2,
        sig: sig_to_json(sig2),
        pub: posting_pub,
      })
    });

    request1.always(function (jqXHR) {
      console.log('STATUS1:', jqXHR.status);
    })

    request1.fail(function (jqXHR, textStatus, error_thrown) {
      console.log('blind_something.request1.fail()', jqXHR);
      let msg;
      if (jqXHR.status && jqXHR.status == 400) {
        msg = "Blinding failed:" + jqXHR.responseText;
      }
      else {
        msg = "Blinding failed with code: " + jqXHR.status;
      }
      callback(new Error(msg));
    });

    request1.done(function (msg) {
      console.log('blind_something.request1.done()');

      // Send unblind, server will automatically wait neccessary number of blocks:

      // Doesn't strictly need to be signed again, because the hash can just be looked up in the DB...:
      // But we sign it anyway, in case DB lookups become problematic:

      console.log('sign_unblind');

      const dd3 = JSON.stringify({
        command: 'unblind',
        item_type: item_type,
        blind_hash: blind_hash.toString('hex'),
        blind_reveal: item_string,
        nonce: get_nonce()
      });

      const sig3 = sign_string(dd3, posting_priv);

      console.log('send_unblind');

      const request2 = $.ajax({
        dataType: "json",
        url: "/unblind",
        method: "POST",
        data: JSON.stringify({
          payload: dd3,
          sig: sig_to_json(sig3),
          pub: posting_pub
        })
      });

      request2.always(function (jqXHR) {
        console.log('STATUS2:', jqXHR.status);
      })

      request2.done(function (msg) {
        console.log('blind_something.request2.done()');

        if (item_type == 'posts') {
          //creator_addr = ethUtils.pubToAddress(new Buffer(posting_pub, 'hex')).toString('hex');

          const creator_addr = posting_pub.slice(0, 20);

          window.location.href = '/?user=' + creator_addr + '&sort=new'; // TODO - ajax refresh listing?

          console.log('DONE unblind item_type ' + item_type);

          callback();
        }
      });

      request2.fail(function (jqXHR, textStatus, error_thrown) {
        console.log('blind_something.request2.fail()', jqXHR);
        let msg;
        if (jqXHR.status && jqXHR.status == 400) {
          msg = "Unblinding failed:" + jqXHR.responseText;
        }
        else {
          msg = "Unblinding failed with code: " + jqXHR.status;
        }
        callback(new Error(msg));
      });
    });
  },

  /**
   * Submit one or more posts to the blockchain.
   *
   * @param {Object | Array.<Object>} posts
   *  Either a post to submit as a JS object, or an array of post objects
   * @param {string} posting_priv
   *  Hex-encoded private key for user's "posting" role
   * @param {string} posting_pub
   *  Hex-encoded public key for posting_priv
   * @param {Function=} callback
   *  Will be called with `Error` if something fails, undefined on success
   */
  submit_posts(posts, posting_priv, posting_pub, callback) {
    if (!Array.isArray(posts)) {
      posts = [posts];
    }

    const the_string = JSON.stringify({
      posts,
      rand: weak_random(16), // Mitigate replay detection attacks.
    });

    exports.blind_something(the_string, posts.length, 'posts', posting_priv, posting_pub, callback);
  },


  submit_votes(votes, posting_priv, posting_pub, callback) {
    if (!Array.isArray(votes)) {
      votes = [votes];
    }

    const votes_string = JSON.stringify({
      votes,
      rand: weak_random(16), // Mitigate replay detection attacks.
    });

    exports.blind_something(votes_string, votes.length, 'votes', posting_priv, posting_pub, callback);
  }
}
