const $ = jQuery = require('jquery');

const BUTTON_ACTIVE_CLASS = 'active';
const BUTTON_INACTIVE_CLASS = 'inactive';

module.exports = exports = {
  get_button_state (elem) {
    return $(elem).hasClass(BUTTON_ACTIVE_CLASS);
  },

  set_button_state (elem, active) {
    const $elem = $(elem)
    const toAdd = active ? BUTTON_ACTIVE_CLASS : BUTTON_INACTIVE_CLASS;
    const toRemove = active ? BUTTON_INACTIVE_CLASS : BUTTON_ACTIVE_CLASS;
    $elem.removeClass(toRemove);
    $elem.addClass(toAdd);
  },

  toggle_button_state (elem) {
    const state = exports.get_button_state(elem);
    exports.set_button_state (elem, !state);
  },

  set_vote_pow (elem, pow) {
    const $elem = $(elem);
    const powText = (typeof pow === 'number')
      ? pow.toFixed(2)
      : pow;

    $elem.text(powText);
  },

  get_vote_pow (elem) {
    return parseFloat($(elem).text());
  },

  flash_trend_icon (containerElem, direction, showDuration = 1000, fadeDuration = 100) {
    containerElem = $(containerElem);
    const upIcon = $('.trend-up', containerElem);
    const downIcon = $('.trend-down', containerElem);

    if (direction === 'up' || direction === 1) {
      upIcon.show().delay(showDuration).fadeOut(fadeDuration);
      downIcon.hide();
    } else {
      downIcon.show().delay(showDuration).fadeOut(fadeDuration);
      upIcon.hide();
    }
  },

  update_card_for_vote (postId, vote_direction, pow) {
    const $upvoteButton = $(`#vote_${postId}_1`);
    const $downvoteButton = $(`#vote_${postId}_-1`);
    const $flagButton = $(`#vote_${postId}_2`);
    const $powSpan = $(`#vote_${postId}_pow`);
    const $trendContainer = $powSpan.parent();

    if ($upvoteButton.length === 0 || $downvoteButton.length === 0 ||
        $flagButton.length === 0 || $powSpan.length === 0) {
      console.warn(`Couldn't get UI elements for ${postId}, bailing out.`);
      return;
    }

    let out_direction = vote_direction;
    let current_pow = exports.get_vote_pow($powSpan);
    let new_pow = current_pow;

    switch (vote_direction) {
      case -1: {
        // downvote button clicked
        exports.set_button_state($upvoteButton, false);
        exports.toggle_button_state($downvoteButton);
        if (exports.get_button_state($downvoteButton)) {
          new_pow -= pow;
        } else {
          out_direction = 0;
          new_pow += pow;
        }
        break;
      }

      case 1: {
        // upvote button clicked
        exports.set_button_state($downvoteButton, false);
        exports.toggle_button_state($upvoteButton)
        if (exports.get_button_state($upvoteButton)) {
          new_pow += pow;
        } else {
          out_direction = 0;
          new_pow -= pow;
        }
        break;
      }

      case 2: {
        // flag button clicked
        exports.toggle_button_state($flagButton)
        if (exports.get_button_state($flagButton) === false) {
          out_direction = -2;
        }
      }
    }

    if (new_pow > current_pow) {
      exports.set_vote_pow($powSpan, new_pow);
      exports.flash_trend_icon($trendContainer, 'up');
    } else if (new_pow < current_pow) {
      exports.set_vote_pow($powSpan, new_pow);
      exports.flash_trend_icon($trendContainer, 'down');
    }

    return out_direction;
  }
}
