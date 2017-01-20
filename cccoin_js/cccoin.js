module.exports = (function() {
    'use strict';

    var crypto  = require('crypto'),
        request = require('request'),
        nonce   = require('nonce')();
    
    var version         = '0.0.1',
        API_URL  = 'http://127.0.0.1/api:50000',
        USER_AGENT      = 'cccoin.js ' + version;
    
    function CCCoin(key, secret) {
	
        this._getAuthHeaders = function(params) {
            var paramString, signature;

            if (!key || !secret) {
                throw 'Secret and key required.';
            }

            paramString = Object.keys(params).map(function(param) {
                return encodeURIComponent(param) + '=' + encodeURIComponent(params[param]);
            }).join('&');

            signature = crypto.createHmac('sha512', secret).update(paramString).digest('hex');

            return {
                Key: key,
                Sign: signature
            };
        };
    }
    
    CCCoin.STRICT_SSL = true;
    
    CCCoin.USER_AGENT = USER_AGENT;

    CCCoin.prototype = {
        constructor: CCCoin,

        _request: function(options, callback) {
            if (!('headers' in options)) {
                options.headers = {};
            }

            options.headers['User-Agent'] = CCCoin.USER_AGENT;
            options.strictSSL = CCCoin.STRICT_SSL;
            options.json = true;

            request(options, function(err, response, body) {
		    // Empty response
		    if (!err && (typeof body === 'undefined' || body === null)){
			err = 'Response is empty';
		    }

		    callback(err, body);
		});

            return this;
        },

        _noauth: function(command, params, callback) {
            var options;

            if (typeof params === 'function') {
                callback = params;
                params = {};
            }

            params || (params = {});
            params.command = command;
            options = {
                method: 'POST',
                url: API_URL,
                qs: params
            };

            options.qs.command = command;
            return this._request(options, callback);
        },

        _yesauth: function(command, params, callback) {
            var options;

            if (typeof params === 'function') {
                callback = params;
                params = {};
            }

            params || (params = {});
            params.command = command;
            params.nonce = nonce();

            options = {
                method: 'POST',
                url: API_URL,
                form: params,
                headers: this._getAuthHeaders(params)
            };

            return this._request(options, callback);
        },

        
        create_account: function(dict, callback) {
            return this._noauth('create_account', dict, callback);
        },
	
        list: function(dict, callback) {
            return this._noauth('list', dict, callback);
        },


        login: function(dict, callback) {
            return this._yesauth('login', dict, callback);
        },

	submit: function(dict, callback) {
            return this._yesauth('submit', dict, callback);
        },

	vote: function(dict, callback) {
            return this._yesauth('vote', dict, callback);
        },
    };
    
    return CCCoin;
})();
