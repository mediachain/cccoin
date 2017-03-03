'use strict';

const $ = require('jquery');
require('materialize-css')

const { grab_keys, do_logout, login } = require('./auth');
const { submit_posts, submit_votes, send_tos_confirmation } = require('./api');
const UI = require('./ui');
const {
  init_css,
  init_login_modal,
  init_submit_form,
  init_tos_modal,
  show_login_modal,
  update_card_for_vote,
  update_card_timestamps,
  update_login_button,
  money_update
} = UI;

function do_post(image_url, image_title, license_type, artist_name){
  console.log('do_post()', image_url, image_title);

  const keys = grab_keys();
  if (!keys) {
    show_login_modal();
    return;
  }

  const {posting_priv, posting_pub} = keys;
  const post = {image_url:image_url, image_title:image_title, license_type: license_type, artist_name: artist_name};
  submit_posts(post, posting_priv, posting_pub, (err) => {
    if (err) {
      console.log("Error submitting post", err);
    }
  });
}

function do_vote(item_id, direction){
  console.log('do_vote()', item_id, direction);
  const keys = grab_keys();

  if (!keys) {
    show_login_modal();
    return;
  }
  const {posting_priv, posting_pub} = keys;

  const my_pow = 0.0;
  console.log('do_vote', item_id, direction, my_pow);
  let direction_out = update_card_for_vote(item_id, direction, my_pow);

  // Create blinded votes:
  console.log('submitting vote');
  const vote = {
    item_id: item_id,
    direction: direction_out
  };

  submit_votes(vote, posting_priv, posting_pub, (err) => {
    if (err) {
      console.log('Error submitting vote: ', err);
    }
  });
}


// Login form:

function check_session(){
  console.log('check_session()');
  const keys = grab_keys() || {};
  const {username} = keys;
  update_login_button(username);
}

/* START INITIALIZATION STUFF */

$(document).ready(function () {
  init_css();
  init_login_modal(login);
  init_submit_form(do_post);
  init_tos_modal(
    // TOS accepted callback
    () => {
      console.log('TOS accepted');
      send_tos_confirmation();
      location.reload();
    },
    // TOS rejected
    () => {
      console.log('TOS rejected');
      do_logout();
    });

  check_session();

  // periodically update timestamps, card money values
  setInterval(update_card_timestamps, 3000);
  setInterval(money_update, 2100);
})

/* END INITIALIZATION STUFF */


// export things to the global namespace for onclick handlers, etc
// TODO: namespace these, or add click handlers from code
window.do_logout = do_logout;
window.do_post = do_post;
window.do_vote = do_vote;
window.toggle_fixed = UI.toggle_fixed_navbar;
window.toggle_stats = UI.toggle_stats;
