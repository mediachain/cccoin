/*

 - check localstorage for login status
 - show username if logged in
 - ajax to get user info (balance, alerts, etc)

 TYPES OF KEYS:
 owner, active, posting, private_messages, witness

 NEW:
 owner, posting, memo, wallet, witness
 */

const all_roles = ['owner', 'active', 'posting', 'private_messages', 'witness'];
const default_roles = ['owner', 'active', 'posting', 'private_messages'];

const $ = require('jquery');
require('materialize-css')
const ethUtils = require('ethereumjs-util');
const moment = require('moment');
const savvior = require('savvior')

function setCookie(key, value) {
  const expires = new Date();
  expires.setTime(expires.getTime() + (1 * 24 * 60 * 60 * 1000));
  document.cookie = key + '=' + value + ';expires=' + expires.toUTCString();
}

function getCookie(key) {
  const keyValue = document.cookie.match('(^|;) ?' + key + '=([^;]*)(;|$)');
  return keyValue ? keyValue[2] : null;
}

function delete_cookie(name) {
  document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

function gen_key(username, role, password){
  /* Gen public key from secret. */
  console.log('gen_key()');

  const priv = ethUtils.sha256(new Buffer(username + '|' + role + '|' + password));
  const pub = ethUtils.privateToPublic(priv);

  const priv_h = priv.toString('hex');
  const pub_h = pub.toString('hex');
  const addr_h = 'CC' + ethUtils.publicToAddress(pub).toString('hex');

  return [pub_h, priv_h, addr_h];
}

function do_logout(){
  console.log('do_logout()');
  localStorage.removeItem('session_data3');
  delete_cookie('auth');
  //check_session();
  location.reload();
}


function toggle_fixed(which){
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
}

function toggle_stats(which){
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
}

function login(username, password){
  console.log('login()', username, password);

  /* Save session info. */

  // TODO: check with server that this user exists.

  const [owner_pub, owner_priv, owner_addr] = gen_key(username, 'owner', password);
  const [posting_pub, posting_priv, posting_addr] = gen_key(username, 'posting', password);

  localStorage.removeItem('session_data3');

  const data_ls = new Buffer(`${username}\t${owner_addr || ''}\t${posting_priv || ''}\t${posting_pub || ''}`).toString('hex');

  /*
   - Server makes challenge: `random_bytes(16)`
   - User signs challenge.
   - Server verifies signed challenge.
   - Server gives secure cookie: `encrypt(username + expiration, server_password)`
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
      data: JSON.stringify({the_pub: posting_pub,
        challenge: dd,
        sig: {sig_v: sig.v,
          sig_r: sig.r.toString('hex'),
          sig_s: sig.s.toString('hex'),
        },
      })
    });

    request2.done(function( msg2 ) {
      console.log('login.request2.done()', JSON.stringify(msg2));

      //console.log('challenge_done',msg2);

      if (!msg2['success']){
        alert('Failed challenge-response.');
        return;
      }

      if (!msg2['is_new']){
        alert('New account created for "' + username + '".');
      }

      // Success:

      console.log('login success:', username);

      localStorage.setItem('session_data3', data_ls);

      //check_session();

      location.reload();

    });

    request2.fail(function( jqXHR, textStatus ) {
      console.log('login.request2.fail()', jqXHR, textStatus);
      alert( "Request2 failed: " + textStatus );
      return false;
    });

  });

  request1.fail(function( jqXHR, textStatus ) {
    console.log('login.request1.fail()', textStatus);
    alert( "Request1 failed: " + textStatus );
    return false;
  });

}

function grab_keys(){
  console.log('grab_keys()');

  const data = localStorage.getItem('session_data3');

  if (!data){
    console.log('grab_keys_failed');
    delete_cookie('auth');
    return false;
  }

  [username, owner_addr, posting_priv, posting_pub] = new Buffer(data, 'hex').toString().split('\t');

  //owner_addr = clean(owner_addr);
  //posting_priv = clean(posting_priv);

  console.log('grab_keys: username:', username);
  console.log('grab_keys: owner_addr:', owner_addr);
  console.log('grab_keys: posting_priv:', posting_priv);
  console.log('grab_keys: posting_pub:', posting_pub);

  return [username, owner_addr, posting_priv, posting_pub];

}

function get_nonce(){
  return Math.floor(Date.now());
}

//btn-floating

function weak_random(N)
{
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for( let i=0; i < N; i++ )
    text += possible.charAt(Math.floor(Math.random() * possible.length));

  return text;
}


function do_post(image_url, image_title){
  console.log('do_post()', image_url, image_title);

  // Create blinded post:

  console.log('sign_blind');

  const keys = grab_keys();

  if (!keys) {
    $('#modal2').modal('open');
    return;
  }

  const [username, owner_addr, posting_priv, posting_pub] = keys;

  const the_string = JSON.stringify({
    posts:[ {image_url:image_url, image_title:image_title} ],
    rand: weak_random(16), // Mitigate known plaintext attacks.
  });

  blind_something(the_string, 1, 'posts', posting_priv, posting_pub);
}

function blind_something(votes_string, num_items, item_type, posting_priv, posting_pub){
  /*
   Send stuff to blockchain with 2-phase blind & reveal process.
   Currently used for votes and posts.

   - `num_items` allows placing a cost on blind actions, so they're not just a free option.
   - Be sure to include some random data in the input string to mitigate known plaintext attacks.
   */

  console.log('START blind_something()', num_items, item_type);

  const blind_hash = ethUtils.sha256(new Buffer(votes_string));

  const dd2 = JSON.stringify({command:'blind',
    item_type: item_type,
    blind_hash: blind_hash.toString('hex'),
    num_items: num_items,
    nonce: get_nonce(),
  });

  const sig2 = ethUtils.ecsign(ethUtils.sha256(new Buffer(dd2)), new Buffer(posting_priv, 'hex'));

  // Send blind:

  console.log('post_blind');

  const request1 = $.ajax({
    dataType: "json",
    url: "/blind",
    method: "POST",
    data: JSON.stringify({payload:dd2,
      sig: {sig_v:sig2.v,
        sig_r:sig2.r.toString('hex'),
        sig_s:sig2.s.toString('hex'),
      },
      pub: posting_pub,
    })
  });

  request1.always(function (jqXHR) {
    console.log('STATUS1:',jqXHR.status);
  })

  request1.done(function( msg ) {
    console.log('blind_something.request1.done()');

    // Send unblind, server will automatically wait neccessary number of blocks:

    // Doesn't strictly need to be signed again, because the hash can just be looked up in the DB...:
    // But we sign it anyway, in case DB lookups become problematic:

    console.log('sign_unblind');

    const dd3 = JSON.stringify({command:'unblind',
      item_type: item_type,
      blind_hash: blind_hash.toString('hex'),
      blind_reveal: votes_string,
      nonce: get_nonce()
    });

    const sig3 = ethUtils.ecsign(ethUtils.sha256(new Buffer(dd3)), new Buffer(posting_priv, 'hex'));

    console.log('send_unblind');

    const request2 = $.ajax({
      dataType: "json",
      url: "/unblind",
      method: "POST",
      data: JSON.stringify({ payload:dd3,
        sig: {sig_v: sig3.v,
          sig_r: sig3.r.toString('hex'),
          sig_s: sig3.s.toString('hex'),
        },
        pub: posting_pub
      })
    });

    request2.always(function (jqXHR) {
      console.log('STATUS2:',jqXHR.status);
    })

    request2.done(function( msg ) {
      console.log('blind_something.request2.done()');

      //voteobj.removeClass('white');

      if (item_type == 'posts'){
        //creator_addr = ethUtils.pubToAddress(new Buffer(posting_pub, 'hex')).toString('hex');

        const creator_addr = posting_pub.slice(0, 20);

        window.location.href = '/?user=' + creator_addr + '&sort=new'; // TODO - ajax refresh listing?

        console.log('DONE unblind item_type ' + item_type);

      }


    });

    request2.fail(function( jqXHR, textStatus, error_thrown ) {
      console.log('blind_something.request2.fail()', jqXHR);

      //alert( "Unblinding failed: " + jqXHR.responseText );

      if(jqXHR.status && jqXHR.status == 400){
        alert("Unblinding failed:" + jqXHR.responseText);
      }
      else{
        alert("Unblinding failed with code: " + jqXHR.status);
      }

      //voteobj.removeClass('white');
      //voteobj.addClass(inactive_class);
    });

  });

  request1.fail(function( jqXHR, textStatus, error_thrown ) {
    console.log('blind_something.request1.fail()', jqXHR);

    if(jqXHR.status && jqXHR.status==400){
      alert("Blinding failed:" + jqXHR.responseText);
    }
    else{
      alert("Blinding failed with code: " + jqXHR.status);
    }

    //alert( "Blinding failed: " + jqXHR.responseText);
    //voteobj.removeClass('white');
    //voteobj.addClass(inactive_class);
  });

}


function do_vote(item_id, direction){
  console.log('do_vote()', item_id, direction);

  /*
   For V1, we'll send the blinded and unblinded signed messages to the Web
   node simultaneously.
   */

  const my_pow = 1.23;

  //var inactive_class = 'grey';
  const inactive_class = 'white';

  console.log('do_vote', item_id, direction, my_pow);

  const keys = grab_keys();

  if (!keys) {
    $('#modal2').modal('open');
    return;
  }

  const [username, owner_addr, posting_priv, posting_pub] = keys;

  //

  const voteobj_neg = $('#vote_' + item_id + '_' + -1);
  const voteobj_pos = $('#vote_' + item_id + '_' + 1);
  const voteobj_flag = $('#vote_' + item_id + '_' + 2);

  const voteobjpow = $('#vote_' + item_id + '_pow');

  //voteobj.removeClass('grey');
  //voteobj.addClass('white');

  let is_flagged = 0;
  let is_neg = 0;
  let is_pos = 0;

  if (voteobj_flag.hasClass('yellow-text')){
    is_flagged = 1;
  }
  if (voteobj_pos.hasClass('red')){
    is_pos = 1;
  }
  if (voteobj_neg.hasClass('blue')){
    is_neg = 1;
  }

  console.log('is_flagged',is_flagged,'is_pos',is_pos,'is_neg',is_neg,'direction',direction);

  let direction_out = direction;

  if (direction == -1){
    if (is_neg){
      console.log('aa');
      direction_out = 0;
      voteobj_pos.removeClass('red');
      voteobj_pos.addClass(inactive_class);
      voteobj_neg.removeClass('blue');
      voteobj_neg.addClass(inactive_class);
      voteobjpow.html((parseFloat(voteobjpow.text()) + my_pow).toFixed(2));
      $('.trend-up',voteobjpow.parent()).show().delay(1000).fadeOut();
      $('.trend-down',voteobjpow.parent()).hide();
    }
    else {
      console.log('bb');
      voteobj_pos.removeClass('red');
      voteobj_pos.addClass(inactive_class);
      voteobj_neg.removeClass(inactive_class);
      voteobj_neg.addClass('blue');
      voteobjpow.html((parseFloat(voteobjpow.text()) - my_pow).toFixed(2));
      $('.trend-up',voteobjpow.parent()).hide();
      $('.trend-down',voteobjpow.parent()).show().delay(1000).fadeOut();
    }
  }
  else if (direction == 1){
    if (is_pos){
      console.log('cc');
      direction_out = 0;
      voteobj_pos.removeClass('red');
      voteobj_pos.addClass(inactive_class);
      voteobj_neg.removeClass('blue');
      voteobj_neg.addClass(inactive_class);
      voteobjpow.html((parseFloat(voteobjpow.text()) - my_pow).toFixed(2));
      $('.trend-up',voteobjpow.parent()).hide();
      $('.trend-down',voteobjpow.parent()).show().delay(1000).fadeOut();
    }
    else {
      console.log('dd');
      voteobj_pos.removeClass(inactive_class);
      voteobj_pos.addClass('red');
      voteobj_neg.removeClass('blue');
      voteobj_neg.addClass(inactive_class);
      voteobjpow.html((parseFloat(voteobjpow.text()) + my_pow).toFixed(2));
      $('.trend-up',voteobjpow.parent()).show().delay(1000).fadeOut();
      $('.trend-down',voteobjpow.parent()).hide();
    }
  }
  else {
    direction = 2;
    if (is_flagged){
      direction_out = -2;
      console.log('ee');
      voteobj_flag.removeClass('yellow-text');
      voteobj_flag.addClass('text-lighten-3');
      voteobj_flag.addClass('grey-text');
    }
    else {
      console.log('ff');
      voteobj_flag.removeClass('grey-text');
      voteobj_flag.removeClass('text-lighten-3');
      voteobj_flag.addClass('yellow-text');
    }
  }


  // Create blinded votes:

  console.log('sign_blind');

  const votes_string = JSON.stringify({votes:[{item_id:item_id,
    direction:direction_out,
  }],
    rand: weak_random(16), // Mitigate known plaintext attacks.
  });

  blind_something(votes_string, 1, 'votes', posting_priv, posting_pub);

  return;

  const blind_hash = ethUtils.sha256(new Buffer(votes_string));

  const dd2 = JSON.stringify({command:'vote_blind',
    blind_hash: blind_hash.toString('hex'),
    num_items: 1,
    nonce: get_nonce(),
  });

  const sig2 = ethUtils.ecsign(ethUtils.sha256(new Buffer(dd2)), new Buffer(posting_priv, 'hex'));

  // Send blind:

  console.log('send_blind');

  const  request1 = $.ajax({
    dataType: "json",
    url: "/vote_blind",
    method: "POST",
    data: JSON.stringify({payload:dd2,
      sig: {sig_v:sig2.v,
        sig_r:sig2.r.toString('hex'),
        sig_s:sig2.s.toString('hex'),
      },
      pub: posting_pub,
    })
  });

  request1.done(function( msg ) {
    console.log('do_vote.request1.done()');

    // Send unblind, server will automatically wait neccessary number of blocks:

    // Doesn't strictly need to be signed again, because the hash can just be looked up in the DB...:
    // But we sign it anyway, in case DB lookups become problematic:

    console.log('sign_unblind');

    const dd3 = JSON.stringify({command:'vote_unblind',
      blind_hash: blind_hash.toString('hex'),
      blind_reveal: votes_string,
      nonce: get_nonce()
    });

    const sig3 = ethUtils.ecsign(ethUtils.sha256(new Buffer(dd3)), new Buffer(posting_priv, 'hex'));

    console.log('send_unblind');

    const request2 = $.ajax({
      dataType: "json",
      url: "/vote_unblind",
      method: "POST",
      data: JSON.stringify({ payload:dd3,
        sig: {sig_v: sig3.v,
          sig_r: sig3.r.toString('hex'),
          sig_s: sig3.s.toString('hex'),
        },
        pub: posting_pub
      })
    });

    request2.done(function( msg ) {
      console.log('do_vote.request2.done()');


      console.log('vote_done');

      //voteobj.removeClass('white');

    });

    request2.fail(function( jqXHR, textStatus ) {
      console.log('do_vote.request2.fail()');

      alert( "Request2 failed: " + textStatus );
      //voteobj.removeClass('white');
      //voteobj.addClass(inactive_class);
    });

  });

  request1.fail(function( jqXHR, textStatus ) {
    console.log('do_vote.request1.fail()');

    alert( "Request1 failed: " + textStatus );
    //voteobj.removeClass('white');
    //voteobj.addClass(inactive_class);
  });
}


// Login form:

function check_session(){
  console.log('check_session()');

  const keys = grab_keys();

  if (!keys) {
    $('#login_or_username_outer').css('display','none');
    $('#login_button').css('display','inline-block');
    return;
  }

  const [username, owner_addr, posting_priv, posting_pub] = keys;


  $('#login_or_username_outer').css('display','list-item');
  $('#login_button').css('display','none');
  $('#login_error_text').css('display','none');

  $('#login_or_username').text(username);

}

function show_login(){
  console.log('show_login()');
  //$('#modal2').modal('close');
  //$('#modal2').modal('open');
}

function setup_login_modal(){

  $('#login_form').submit(function(e){
    e.preventDefault();

    const uu = $('#login_username').val();
    const pw = $('#login_password').val();

    if (uu.length < 3){
      $('#login_error_text').text('ERROR: Username too short.')
      $('#login_error_text').css('display','block');
      $("#login_username").focus();
      return false;
    }

    if (pw.length < 6){
      $('#login_error_text').text('ERROR: Password too short.')
      $('#login_error_text').css('display','block');
      $("#login_password").focus();
      return false;
    }

    $('#login_error_text').css('display','none');

    login(uu, pw);
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
      $("#login_username").focus();
    },
    complete: function() {
      //
    }
  });
}



/* START INITIALIZATION STUFF */

$(document).ready(function(){
  $('#submit_form').submit(function(e){
    e.preventDefault();

    console.log('START submit_form')

    const image_url = $('#image_url').val();
    //license = $('#license').val();
    //artist_name = $('#artist_name').val();
    const image_title = $('#image_title').val();

    if (image_url.length < 3){
      $('#submit_error_text').text('Invalid image URL.')
      $('#submit_error_text').css('display','block');
      $("#image_url").focus();
      return false;
    }

    if (image_title.length == 0){
      $('#submit_error_text').text('Image title required.')
      $('#submit_error_text').css('display','block');
      $("#image_title").focus();
      return false;
    }

    $('#submit_error_text').css('display','none');

    do_post(image_url, image_title);
  });


});

$(document).ready(function(){

  check_session();

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

});


$(document).ready(function(){
  setup_login_modal();

});


$(document).ready(function(){
  $('ul.tabs').tabs();
});

$(document).ready(function(){
  $('.materialboxed').materialbox();
});

$(document).ready(function(){
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
});



$(document).ready(function(){
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
});


$(document).ready(function(){
  $('#modal1').modal({
    dismissible: true, // Modal can be dismissed by clicking outside of the modal
    opacity: .5, // Opacity of modal background
    inDuration: 300, // Transition in duration
    outDuration: 200, // Transition out duration
    startingTop: '4%', // Starting top style attribute
    endingTop: '10%', // Ending top style attribute
    ready: function(modal, trigger) { // Callback for Modal open. Modal and trigger parameters available.
      //alert("Ready");
      //console.log(modal, trigger);
      $("#image_url").focus();
    },
    //complete: function() { alert('Closed'); } // Callback for Modal close
  });
});




// $(document).ready(function(){
//   $('.dropdown-button').dropdown({
//       inDuration: 300,
//       outDuration: 225,
//       constrainWidth: false, // Does not change width of dropdown to that of the activator
//       hover: true, // Activate on hover
//       gutter: 0, // Spacing from edge
//       belowOrigin: false, // Displays dropdown below the button
//       alignment: 'left' // Displays dropdown with edge aligned to the left of button
//       stopPropagation: false // Stops event propagation
//     }
//   );
// });

$(document).ready(function(){
  var count_start = 60 * 2.5;
  var count = count_start;

  function zpad(num, size) {
    var s = "000000000" + num;
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

  var counter = setInterval(the_timer, 1000);

});


function isScrolledIntoView(el) {
  var elemTop = el.getBoundingClientRect().top;
  var elemBottom = el.getBoundingClientRect().bottom;

  var isVisible = (elemTop >= 0) && (elemBottom <= window.innerHeight);
  return isVisible;
}

function update_card_timestamps () {
  if (document.hidden) return;

  $('.card-time-ago').each(function () {
    const $element = $(this);
    const createdMillis = $element.data('time-created');
    const timeString = moment.unix(createdMillis).fromNowCustom();
    $element.text(timeString);
  })
}

function money_update() {
  if (!document.hidden){
    $('.card-money-outer').each(function (index, value) {
      if (Math.random() < 0.1){
        if (isScrolledIntoView(this)){
          var amt = (Math.random() * Math.random() * 10) - (Math.random() * Math.random() * 5);
          $('span',this).html((parseFloat($('span',this).text()) + amt).toFixed(2));
          //$(this).effect("highlight", {color: "#ddd"}, 2000);

          if (amt > 0) {
            $('.trend-up',this).show().delay(2000).fadeOut(200);
            $('.trend-down',this).hide();
          }
          else {
            $('.trend-up',this).hide();
            $('.trend-down',this).show().delay(2000).fadeOut(200);
          }
        }
      }
    });
  }
}

function setup_card_grid () {
  savvior.init('#card-grid', {
    "screen and (max-width: 40em)": { columns: 1 },
    "screen and (min-width: 40em) and (max-width: 60em)": { columns: 2 },
    "screen and (min-width: 60em) and (max-width: 80em)": { columns: 3 },
    "screen and (min-width: 80em)": { columns: 4 },
  });
}

$(document).ready(function () {
  moment.fn.fromNowCustom = function (a) {
    if (Math.abs(moment().diff(this)) < 45000) {
      return 'just now';
    }
    return this.fromNow(a);
  }

  update_card_timestamps();
  setInterval(update_card_timestamps, 3000);
  setInterval(money_update, 2100);

  setup_card_grid();
})

$(document).ready(function() {
  $('select').material_select();
});

/* END INITIALIZATION STUFF */


// export things to the global namespace for onclick handlers, etc
// TODO: namespace these, or add click handlers from code
window.do_logout = do_logout;
window.do_post = do_post;
window.do_vote = do_vote;
window.toggle_fixed = toggle_fixed;
window.toggle_stats = toggle_stats;
window.moment = moment;
window.savvior = savvior;
