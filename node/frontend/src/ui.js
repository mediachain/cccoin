const $ = jQuery = require('jquery');
const savvior = require('savvior');
const { generatePassphrase } = require('./key_generation');
const { timeAgoString } = require('./util');
const { grab_keys, do_logout, login } = require('./auth');

const BUTTON_ACTIVE_CLASS = 'active';
const BUTTON_INACTIVE_CLASS = 'inactive';

function display_error (elem, message) {
  const $elem = $(elem);
  if (message == null || message === false) {
    $elem.text('');
    $elem.css('display', 'none');
    return;
  }

  $elem.text(message);
  $elem.css('display', 'block');
}

module.exports = exports = {
  isScrolledIntoView(el) {
    const bounds = el.getBoundingClientRect();
    const elemTop = bounds.top;
    const elemBottom = bounds.bottom;

    const isVisible = (elemTop >= 0) && (elemBottom <= window.innerHeight);
    return isVisible;
  },

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
      console.warn("Couldn't get UI elements for " + postId + ", bailing out.");
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
  },

  update_card_timestamps () {
    return;
    if (document.hidden) return;

    $('.card-time-ago').each(function () {
      const $element = $(this);
      const timestamp = $element.data('time-created');
      $element.text(timeAgoString(timestamp));
    })
  },

  update_login_button (username) {
    if (username) {
      $('#login_or_username_outer').css('display','list-item');
      $('#login_button').css('display','none');
      $('#login_error_text').css('display','none');
      $('#login_or_username').text(username);
    } else {
      $('#login_or_username_outer').css('display','none');
      $('#login_button').css('display','inline-block');
    }
  },

  show_login_modal() {
    $('#modal2').modal('open');
  },

  money_update() {
    return;
    if (!document.hidden){
      $('.card-money-outer').each(function (index, value) {
        if (Math.random() < 0.1){
          if (exports.isScrolledIntoView(this)){
            const powSpan = $('span', this);
            const amt = (Math.random() * Math.random() * 10) - (Math.random() * Math.random() * 5);
            const newPow = exports.get_vote_pow(powSpan) + amt;
            exports.set_vote_pow(powSpan, newPow);

            if (amt > 0) {
              exports.flash_trend_icon(this, 'up', 2000, 200);
            }
            else {
              exports.flash_trend_icon(this, 'down', 2000, 200);
            }
          }
        }
      });
    }
  },

  init_css () {
    // Materialize-css initializers
    $('ul.tabs').tabs();
    $('.materialboxed').materialbox();
    $('select').material_select();

    
    // savvior masonry grid init

    $('.card_item').css('display','block'); // hack to avoid startup thrashing, for now.
      
    savvior.init('#card-grid', {
      "screen and (max-width: 40em)": { columns: 1 },
      "screen and (min-width: 40em) and (max-width: 60em)": { columns: 2 },
      "screen and (min-width: 60em) and (max-width: 80em)": { columns: 3 },
      "screen and (min-width: 80em)": { columns: 4 },
    });

    // do initial timestamp update
    exports.update_card_timestamps();
  },

  init_login_modal(apiLogin) {
    $('#login_or_username').dropdown({
      inDuration: 300,
      outDuration: 225,
      constrainWidth: true, // Does not change width of dropdown to that of the activator
      hover: false, // Activate on hover
      gutter: 0, // Spacing from edge
      belowOrigin: true, // Displays dropdown below the button
      alignment: 'left', // Displays dropdown with edge aligned to the left of button
      stopPropagation: false // Stops event propagation
    });

    const signupPassphrase = generatePassphrase();
    $("#signup_passphrase").val(signupPassphrase);
    Materialize.updateTextFields();

    $('#login_form').submit(function(e){
      e.preventDefault();

      const username = $('#login_or_username').val();
      const password = $('#login_password').val();
      const $error = $('#login_error_text');
      display_error($error, false);

      function cb (rr){
        if (! rr['username_success']){
          display_error($error, 'ERROR: Username too short.');
          $("#login_or_username").focus();
        }

        if (! rr['password_success']){
          display_error($error, 'ERROR: Invalid passphrase.');
          $("#login_password").focus();
        }

        if (rr['success']){
          if (rr['prompt_tos']) {
            exports.show_tos_modal();
            return;
          }
          location.reload();
        }
        else {
          display_error($error, 'ERROR: ' + rr['message']);
          return false;
        }
      }

      apiLogin(password, username, cb);
    });

    $('#signup_form').submit(function(e) {
      e.preventDefault();

      const $username = $('#signup_username');
      const $error = $('#signup_error_text');
      const username = $username.val();
      const warningAccepted = $('#password_warning_accepted').is(':checked')

      if (!warningAccepted) {
        $error.text('ERROR: You must accept the passphrase warning!');
        $error.css('display', 'block');
        return false;
      }

      if (username.length < 2) {
        $error.text('ERROR: Requested username is too short.');
        $error.css('display', 'block');
        return false;
      }

      display_error($error, false);
      const passphrase =  $('#signup_passphrase').val();

      function cb(rr){
        if (! rr['username_success']){
          display_error($error, 'ERROR: username taken or invalid.')
          $username.focus();
        }

        if (! rr['password_success']){
          display_error($error, 'ERROR: Invalid passphrase.');
          $('#signup_passphrase').focus();
        }

        if (rr['success']){
          if (rr['prompt_tos']) {
            exports.show_tos_modal();
            return;
          }
          location.reload();
        }
        else {
          display_error($error, 'ERROR: ' + rr['message']);
          $username.focus();
        }
      }

      apiLogin(passphrase, username, cb);
    });

    $('#modal2').modal({
      dismissible: true, // Modal can be dismissed by clicking outside of the modal
      opacity: .5, // Opacity of modal background
      inDuration: 300, // Transition in duration
      outDuration: 0, // Transition out duration
      startingTop: '4%', // Starting top style attribute
      endingTop: '10%', // Ending top style attribute
      ready: function(modal, trigger) { // Callback for Modal open. Modal and trigger parameters available.
         //alert("Ready");
        //console.log(modal, trigger);
        $('#login_form_tabs').tabs('select_tab', 'signup');
        $("#signup_username").focus();
      },
      complete: function() {
        //
      }
    });
  },

  init_submit_form(submitPostFn) {
    const $modal = $('#modal1');
    const $urlField = $('#image_url');
    const $titleField = $('#image_title');
    const $artistField = $('#artist_name');
    const $licenseField = $('#image_license_type');
    const $agreedCheckbox = $('#image_licence_agreed');
    const $error = $('#submit_error_text');

    $modal.modal({
      dismissible: true, // Modal can be dismissed by clicking outside of the modal
      opacity: .5, // Opacity of modal background
      inDuration: 300, // Transition in duration
      outDuration: 200, // Transition out duration
      startingTop: '4%', // Starting top style attribute
      endingTop: '10%', // Ending top style attribute
      ready: function(modal, trigger) { // Callback for Modal open. Modal and trigger parameters available.
        const keys = grab_keys();
        if (!keys) {
           $modal.modal('close');
           exports.show_login_modal();
           return;
         }
        else {
           $titleField.focus();
         }
      },
      //complete: function() { alert('Closed'); } // Callback for Modal close
    });

    $('#submit_form').submit(function(e){
      e.preventDefault();
      console.log('START submit_form');

      const image_url = $urlField.val();
      const image_title = $titleField.val();
      const artist = $artistField.val();


      if (image_url.length < 3){
        display_error($error, 'Image URL is invalid.');
        $urlField.focus();
        return false;
      }

      if (image_title.length == 0){
        display_error($error, 'Image title required.')
        $titleField.focus();
        return false;
      }

      const agreed = $agreedCheckbox.is(':checked');
      if (!agreed) {
        display_error($error, 'You must agree that you have the right to submit this image.');
        return false;
      }

      const license_type = $licenseField.find(':selected').val();
      console.log('license element', $licenseField);
      console.log('license val: ', license_type);
      if (!license_type) {
        display_error($error, 'You must choose a license.');
        return false;
      }

      console.log('submitting post', image_url, image_title, license_type, artist);
      display_error($error, false);
      submitPostFn(image_url, image_title, license_type, artist);
      $modal.modal('close');
    });
  },

  init_tos_modal(tos_accepted_cb, tos_rejected_cb) {
    if (typeof tos_accepted_cb !== 'function') {
      tos_accepted_cb = () => {}
    }
    if (typeof tos_rejected_cb !== 'function') {
      tos_rejected_cb = () => {}
    }
    const tos_modal = $('#tos_modal');

    tos_modal.modal({
      dismissible: false, // need to explicitly agree / disagree
      opacity: .5, // Opacity of modal background
      inDuration: 300, // Transition in duration
      outDuration: 200, // Transition out duration
      startingTop: '4%', // Starting top style attribute
      endingTop: '10%', // Ending top style attribute
      ready: function () {
        $('#tos_form').submit((e) => {
          e.preventDefault();

          const $error = $('#tos_error_text');
          const agreed = $('#tos_agree_checkbox').is(':checked');
          if (!agreed) {
            display_error($error, 'ERROR: You must agree to the terms of service before proceeding');
            return false;
          }
          display_error($error, false);
          tos_accepted_cb();
        })

        $('#tos_reject_button').on('click', () => {
          tos_rejected_cb();
        })
      }
    });
  },

  show_tos_modal() {
    $('#tos_modal').modal('open');
  },

  toggle_fixed_navbar(which){
    console.log('toggle_fixed()');

    if (which == 1) {
      $('#main_nav').addClass('fixednav');
      $('#main_row').addClass('fixednav');
      $('#stats_panel').addClass('fixednav');
      $('#show_fixed_button').hide();
      $('#hide_fixed_button').show();
    }
    else {
      $('#main_nav').removeClass('fixednav');
      $('#main_row').removeClass('fixednav');
      $('#stats_panel').removeClass('fixednav');
      $('#show_fixed_button').show();
      $('#hide_fixed_button').hide();
    }
  },

  toggle_stats(which){
    console.log('toggle_stats()');

    if (which == 1) {
      $('#stats_panel').show();
      $('#show_stats_button').hide();
      $('#hide_stats_button').show();
      $('#main_panel').addClass('l9');
      $('#main_panel').addClass('m8');
      $('.card_item').removeClass('l2');
      $('.card_item').addClass('l3');
    }
    else {
      $('#stats_panel').hide();
      $('#show_stats_button').show();
      $('#hide_stats_button').hide();
      $('#main_panel').removeClass('l9');
      $('#main_panel').removeClass('m8');
      $('.card_item').removeClass('l3');
      $('.card_item').addClass('l2');
    }
  },

  init_stats_panel () {
    // -- Round timer
    let count_start = 60 * 2.5;
    let count = count_start;

    function zpad(num, size) {
      const s = "000000000" + num;
      return s.substr(s.length-size);
    }

    function the_timer() {
      count = count - 1;
      if (count == -1) {
        count = count_start;
        return;
      }

      var seconds = count % 60;
      var minutes = Math.floor(count / 60);
      var hours = Math.floor(minutes / 60);
      minutes %= 60;
      hours %= 60;

      if (!hours){
        document.getElementById("round_timer").innerHTML = minutes + ":" + zpad(seconds, 2);
      }
      else {
        document.getElementById("round_timer").innerHTML = hours + ":" + zpad(minutes, 2) + ":" + zpad(seconds, 2);
      }
    }

    setInterval(the_timer, 1000);


    // -- Transactions table

    // Change the selector if needed
    let $table = $('.transactions-table'),
      $bodyCells = $table.find('tbody tr:first').children(),
      colWidth;

    // Get the tbody columns width array
    colWidth = $bodyCells.map(function() {
      return $(this).width();
    }).get();

    // Set the width of thead columns
    $table.find('thead tr').children().each(function(i, v) {
      $(v).width(colWidth[i]);
    });

    // -- Event log

    $("#events_log").scrollTop(9999);
    //$("#events_log").scrollTop(0);

    let clone_count = 32;
    setInterval(function(){
      if (!document.hidden){
        let num = Math.floor(Math.random()*5);
        $( "#event_" + num ).clone().attr('id', 'event_' + clone_count++).prependTo( "#events_log" );
        $( "#event_" + (clone_count - 1) + " .blocknum a").html("#" + clone_count);
        //var od = $("#events_log");
        //od.scrollTop(od[0].scrollHeight);

        if ($("#events_log")[0].scrollHeight >= 9000){
          $("#events_log tr:nth-child(10)")[0].remove();
        }

        let scrollToBottom = false;
        if (($("#events_log")[0].scrollHeight - $("#events_log").scrollTop()) <= $("#events_log").outerHeight() * 2) {
          scrollToBottom = true;
        }
        //console.log("A " + $("#events_log").scrollTop() + " B " + $("#events_log").outerHeight());
        if (scrollToBottom) {
          //$("#events_log").scrollTop(9999);
        }
      }

    }, 2100);
  }
}
