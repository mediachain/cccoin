#!/usr/bin/env python

from node_core import (CCCoinCore,
                       solidity_string_encode,
                       solidity_string_decode,
                       dumps_compact,
                       loads_compact,
                       client_post,
                       client_vote,
                       client_create_blind,
                       pub_to_address,
                       )

from node_generic import htime_ago

import multiprocessing
from random import randint, choice
from os import urandom

from os import mkdir, listdir, makedirs, walk, rename, unlink
from os.path import exists,join,split,realpath,splitext,dirname
import binascii

import bitcoin as btc

from node_temporal import T_ANY_FORK

##
#### Utils:
##


def intget(x,
           default = False,
           ):
    try:
        return int(x)
    except:
        return default

def floatget(x,
             default = False,
             ):
    try:
        return float(x)
    except:
        return default


##
### Web frontend:
##


import json
import ujson
import tornado.ioloop
import tornado.web
from time import time

import tornado
import tornado.options
import tornado.web
import tornado.template
import tornado.gen
import tornado.auth
from tornado.web import RequestHandler
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.options import define, options

##
#### Authentication:
##

import hmac
import hashlib
import urllib
import urllib2
import json
from time import time

from urllib import quote
import tornado.web
import tornado.gen

import pipes


def auth_test(rq,
              user_key,
              secret_key,
              api_url = 'http://127.0.0.1:50000/api',
              ):
    """
    HMAC authenticated calls, with nonce.
    """
    rq['nonce'] = int(time()*1000)
    #post_data = urllib.urlencode(rq)
    post_data = dumps_compact(rq)
    sig = hmac.new(secret_key, post_data, hashlib.sha512).hexdigest()
    headers = {'Sig': sig,
               'Key': user_key,
               }
    
    print ("REQUEST:\n\ncurl -S " + api_url + " -d " + pipes.quote(post_data) + ' -H ' + pipes.quote('Sig: ' + headers['Sig']) + ' -H ' + pipes.quote('Key: ' + headers['Key']))

    return

    ret = urllib2.urlopen(urllib2.Request(api_url, post_data, headers))
    hh = json.loads(ret.read())
    return hh


def vote_helper(api_url = 'http://big-indexer-1:50000/api',
                via_cli = False,
                ):
    """
    USAGE: python offchain.py vote_helper user_pub_key user_priv_key vote_secret vote_json
    """
    
    user_key = sys.argv[2]
    secret_key = sys.argv[3]
    vote_secret = sys.argv[4]
    rq = sys.argv[5]
    
    rq = json.loads(rq)
    
    num_votes = len(rq['votes'])
        
    sig1 = hmac.new(vote_secret, dumps_compact(rq), hashlib.sha512).hexdigest()
    
    post_data = dumps_compact({'command':'vote_blind', 'sig':sig1, 'num_votes':num_votes, 'nonce':int(time()*1000)})
    
    sig2 = hmac.new(secret_key, post_data, hashlib.sha512).hexdigest()
    
    print ('REQUEST:')
    print ("curl -S " + api_url + " -d " + pipes.quote(post_data) + ' -H ' + pipes.quote('Sig: ' + sig2) + ' -H ' + pipes.quote('Key: ' + user_key))


def sig_helper(user_key = False,
               secret_key = False,
               rq = False,
               via_cli = False,
               ):
    """
    CLI helper for authenticated requests. Usage: api_call user_key secret_key json_string
    """
    #print sys.argv
    
    if via_cli:
        user_key = sys.argv[2]
        secret_key = sys.argv[3]
        rq = sys.argv[4]
    
    rq = json.loads(rq)
    
    print ('THE_REQUEST', rq)
    
    rr = auth_test(rq,
                   user_key,
                   secret_key,
                   api_url = 'http://127.0.0.1:50000/api',
                   )
    
    print json.dumps(rr, indent = 4)


import functools
import urllib
import urlparse


from uuid import uuid4
from ujson import loads,dumps
from time import time
from urllib import urlencode

class AuthState:
    def __init__(self):
        pass
        
    def login_and_init_session(self,
                               caller,
                               session,
                               ):
        print ('login_and_init_session()')
        assert session
        
        session['last_updated'] = time()
        session = dumps(session)
        caller.set_secure_cookie('auth',session)
        
    def logout(self,
               caller,
               ):
        caller.set_secure_cookie('auth','false')
        
    def update_session(self,
                       caller,
                       session,
                       ):
        print ('update_session()')
        assert session
        
        session['last_updated'] = int(time())
        session = dumps(session)
        caller.set_secure_cookie('auth',session)
    



def lookup_session(self,
                   public_key,
                   ):
    return USER_DB.get(public_key, False)


def check_auth_shared_secret(auth = True,
                             ):
    """
    Authentication via HMAC signatures, nonces, and a local keypair DB.
    """
    
    def decorator(func):
        
        def proxyfunc(self, *args, **kw):

            user_key = dict(self.request.headers).get("Key", False)
            
            print ('AUTH_CHECK_USER',user_key)
            
            self._current_user = lookup_session(self, user_key)
            
            print ('AUTH_GOT_USER', self._current_user)

            print ('HEADERS', dict(self.request.headers))
            
            if auth:
                
                if self._current_user is False:
                    self.write_json({'error':'USER_NOT_FOUND', 'message':user_key})
                    #raise tornado.web.HTTPError(403)
                    return

                post_data = self.request.body
                sig = dict(self.request.headers).get("Sig", False)
                secret_key = self._current_user['private_key']

                if not (user_key or sig or secret_key):
                    self.write_json({'error':'AUTH_REQUIRED'})
                    #raise tornado.web.HTTPError(403)
                    return

                r1, r2 = validate_api_call(post_data,
                                           user_key,
                                           secret_key,
                                           sig,
                                           )
                if not r1:

                    self.write_json({'error':'AUTH_FAILED', 'message':r2})
                    #raise tornado.web.HTTPError(403)
                    return
            
            func(self, *args, **kw)

            return
        return proxyfunc
    return decorator


def check_auth_asymmetric(needs_read = False,
                          needs_write = False,
                          cookie_expiration_time = 999999999,
                          ):
    """
    Authentication based on digital signatures or encrypted cookies.
    
    - Write permission requires a signed JSON POST body containing a signature and a nonce.
    
    - Read permission requires either write permission, or an encrypted cookie that was created via the
      login challenge / response process. Read permission is intended to allow a user to read back his 
      own blinded information that has not yet been unblinded, for example to allow the browser to 
      immediately display recently submitted votes and posts.
    
    TODO: Resolve user's multiple keys into single master key or user_id?
    """
            
    def decorator(func):
        
        def proxyfunc(self, *args, **kw):
            
            self._current_user = {}
            
            #
            ## Get read authorization via encrypted cookies.
            ## Only for reading pending your own pending blind data:
            #

            if not needs_write: ## Don't bother checking for read if write is needed.
                
                cook = self.get_secure_cookie('auth')
                
                if cook:
                    h2 = json.loads(cook)
                    if (time() - h2['created'] <= cookie_expiration_time):
                        self._current_user = {'pub':h2['pub'],
                                              'has_read': True,
                                              'has_write': False,
                                              }
            
            #   
            ## Write authorization, must have valid monotonically increasing nonce:
            #
            
            try:
                hh = json.loads(self.request.body)
            except:
                hh = False
            
            if hh:
                print ('AUTH_CHECK_USER', hh['pub'][:32])

                hh['payload_decoded'] = json.loads(hh['payload'])
                
                if (hh['pub'] in self.cccoin.DBL['LATEST_NONCE']) and \
                   ('nonce' in hh['payload_decoded']) and \
                   (hh['payload_decoded']['nonce'] <= self.cccoin.DBL['LATEST_NONCE'][hh['pub']]
                   ):
                    print ('OUTDATED NONCE')
                    self.write_json({'error':'AUTH_OUTDATED_NONCE'})
                    return
                
                #LATEST_NONCE[user_key] = hh['payload_decoded']['nonce']
                
                is_success = btc.ecdsa_raw_verify(btc.sha256(hh['payload'].encode('utf8')),
                                                  (hh['sig']['sig_v'],
                                                   btc.decode(hh['sig']['sig_r'],16),
                                                   btc.decode(hh['sig']['sig_s'],16),
                                                  ),
                                                  hh['pub'],
                                                  )
                
                if is_success:
                    ## write auth overwrites read auth:
                    self._current_user = {'pub':hh['pub'],
                                          'has_read': True,
                                          'has_write': True,
                                          'write_data': hh,
                                          }
            
            if needs_read and not self._current_user.get('has_read'):
                print ('AUTH_FAILED_READ')
                self.write_json({'error':'AUTH_FAILED_READ'})
                #raise tornado.web.HTTPError(403)
                return
            
            if needs_write and not self._current_user.get('has_write'):
                print ('AUTH_FAILED_READ')
                self.write_json({'error':'AUTH_FAILED_READ'})
                #raise tornado.web.HTTPError(403)
                return
            
            ## TODO: per-public-key sponsorship rate throttling:
            
            self.add_header('X-RATE-USED','0')
            self.add_header('X-RATE-REMAINING','100')
            
            print ('AUTH_FINISHED', self._current_user)
            
            func(self, *args, **kw)
            
            return
        return proxyfunc
    return decorator

check_auth = check_auth_asymmetric


##
#### Web core:
##

class Application(tornado.web.Application):
    def __init__(self,
                 cccoin,
                 image_proxy_path,
                 web_node_flag_accounts,
                 web_node_approval_accounts,
                 ):

        self.the_cccoin = cccoin
        self.image_proxy_path = image_proxy_path
        self.web_node_flag_accounts = web_node_flag_accounts
        self.web_node_approval_accounts = web_node_approval_accounts
        static_dir = join(dirname(__file__), 'frontend', 'static')

        handlers = [(r'/',handle_front,),
                    (r'/demo',handle_front,),
                    (r'/login_1',handle_login_1,),
                    (r'/login_2',handle_login_2,),
                    (r'/blind',handle_blind,),
                    (r'/unblind',handle_unblind,),
                    #(r'/submit',handle_submit_item,),
                    (r'/track',handle_track,),
                    (r'/api',handle_api,),
                    (r'/echo',handle_echo,),
                    #(r'.*', handle_notfound,),
                    (r'/fonts/(.*)', tornado.web.StaticFileHandler, {'path': join(static_dir, 'fonts')}),
                    ]
        
        settings = {'template_path':join(dirname(__file__), 'templates_cccoin'),
                    'static_path': static_dir,
                    'xsrf_cookies':False,
                    'cookie_secret':'1234',
                    }
        
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    
    def __init__(self, application, request, **kwargs):
        RequestHandler.__init__(self, application, request, **kwargs)
        
        self._current_user_read = False
        self._current_user_write = False
        
        self.loader = tornado.template.Loader('frontend/')

        #self.auth_state = False
        
    @property
    def io_loop(self,
                ):
        if not hasattr(self.application,'io_loop'):
            self.application.io_loop = IOLoop.instance()
        return self.application.io_loop
        
    def get_current_user(self,):
        return self._current_user
    
    @property
    def auth_state(self):
        if not self.application.auth_state:
            self.application.auth_state = AuthState()
        return self.application.auth_state

    @property
    def cccoin(self,
               ):
        return self.application.the_cccoin
        
    @tornado.gen.engine
    def render_template(self,template_name, kwargs):
        """
        Central point to customize what variables get passed to templates.        
        """
        
        t0 = time()
        
        if 'self' in kwargs:
            kwargs['handler'] = kwargs['self']
            del kwargs['self']
        else:
            kwargs['handler'] = self

        from random import choice, randint
        kwargs['choice'] = choice
        kwargs['randint'] = randint
        kwargs['pub_to_address'] = pub_to_address
        kwargs['all_dbs'] = self.cccoin.DBL['all_dbs']
        kwargs['time'] = time
        kwargs['htime_ago'] = htime_ago
        kwargs['urlencode'] = urlencode
        kwargs['T_ANY_FORK'] = T_ANY_FORK
        
        #print 'START_STORE'
        #self.cccoin.tdb.store('user_id_to_username','DIRECT','test','test2')
        #print 'END_STORE'
        
        r = self.loader.load(template_name).generate(**kwargs)
        
        print ('TEMPLATE TIME',(time()-t0)*1000)
        
        self.write(r)
        self.finish()
    
    def render_template_s(self,template_s,kwargs):
        """
        Render template from string.
        """
        
        t=Template(template_s)
        r=t.generate(**kwargs)
        self.write(r)
        self.finish()

    def get_image_proxy(self, url, width = '-', height = '-', crop_height=False):
        if not self.application.image_proxy_path:
            rr = url
        else:
            if crop_height:
                rr = self.application.image_proxy_path + 'ch/' + str(height) + '/' + url
            else:
                #rr = urlencode({'w':width,'h':height,'u':url})
                #rr = self.application.image_proxy_path + str(width) + '/' + str(height) + '/' + url
                rr = self.application.image_proxy_path + 'h/' + str(height) + '/' + url
        return rr
        
    def write_json(self,
                   hh,
                   sort_keys = True,
                   indent = 4, #Set to None to do without newlines.
                   ):
        """
        Central point where we can customize the JSON output.
        """

        print ('WRITE_JSON',hh)
        
        if 'error' in hh:
            print ('ERROR',hh)
        
        self.set_header("Content-Type", "application/json")

        if False:
            zz = json.dumps(hh,
                            sort_keys = sort_keys,
                            indent = 4,
                            ) + '\n'
        else:
            zz = json.dumps(hh, sort_keys = True)

        print ('WRITE_JSON_SENDING', zz)
            
        self.write(zz)
                       
        self.finish()
        

    def disabled_write_error(self,
                             status_code,
                             **kw):

        import traceback, sys, os
        try:
            ee = '\n'.join([str(line) for line in traceback.format_exception(*sys.exc_info())])
            print (ee)
        except:
            print ('!!!ERROR PRINTING EXCEPTION')
        self.write_json({'error':'INTERNAL_EXCEPTION','message':ee})

    
class handle_front(BaseHandler):
    @check_auth()
    @tornado.gen.coroutine
    def get(self):

        session = self.get_current_user()
        filter_users = [x for x in self.get_argument('user','').split(',') if x]
        filter_ids = [x for x in self.get_argument('ids','').split(',') if x]
        offset = intget(self.get_argument('offset','0'), 0)
        increment = intget(self.get_argument('increment','50'), 50) or 50
        sort_by = self.get_argument('sort', 'trending')
        
        if session and ('address' not in session):
            session['address'] = pub_to_address(session['pub'])
        
        the_items = self.cccoin.get_sorted_posts(filter_users = filter_users,
                                                 filter_ids = filter_ids,
                                                 sort_by = sort_by,
                                                 offset = offset,
                                                 increment = 1000,
                                                 )
        
        num_items = len(the_items['items'])
        
        self.render_template('index.html',locals())
        



class handle_login_1(BaseHandler):
    #@check_auth(auth = False)
    @tornado.gen.coroutine
    def post(self):

        hh = json.loads(self.request.body)

        the_address = pub_to_address(hh['the_pub'])
        
        challenge = self.cccoin.DBL['CHALLENGES_DB'].get(the_address, False)
        
        if challenge is False:
            challenge = binascii.hexlify(urandom(16))
            self.cccoin.DBL['CHALLENGES_DB'][the_address] = challenge

        self.write_json({'challenge':challenge})


WEB_TOS = """THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""
        
class handle_login_2(BaseHandler):
    #@check_auth(auth = False)
    @tornado.gen.coroutine
    def post(self):

        hh = json.loads(self.request.body)
        
        """
        {the_pub: the_pub,
	 challenge: dd,
	 sig_v: sig.v,
	 sig_r: sig.r.toString('hex'),
	 sig_s: sig.s.toString('hex')
	}
        """

        the_pub = hh['the_pub']
        the_address = pub_to_address(the_pub)
        
        challenge = self.cccoin.DBL['CHALLENGES_DB'].get(the_address, False)
        
        if challenge is False:
            print ('LOGIN_2: ERROR UNKNOWN CHALLENGE', challenge)
            self.write_json({"success":False,
	                     "username_success":False,
	                     "password_success":False,
	                     "got_username":"",
	                     "message":'Unknown or expired challenge during login.',
	                     })
            return
        
        print 'GOT=============='
        print json.dumps(hh, indent=4)
        print '================='
        
        ## Check challenge response, i.e. if password is good:
        
        password_success = btc.ecdsa_raw_verify(btc.sha256(challenge.encode('utf8')),
                                                (hh['sig']['sig_v'],
                                                 btc.decode(hh['sig']['sig_r'],16),
                                                 btc.decode(hh['sig']['sig_s'],16)),
                                                the_pub,
                                                )
        
        ## Check for immediate rejection of username request:
        
        username_success = True
        if hh['requested_username'] and (hh['requested_username'] in self.cccoin.DBL['TAKEN_USERNAMES_DB']):
            username_success = False
        
        if hh['requested_username'] and self.cccoin.sdb.lookup('username_to_user_id',
                                                               hh['requested_username'],
                                                               default = False,
                                                               at_hash = 'latest'
                                                               ):
            username_success = False
        
        ## Check if user already registered a username before:
        
        uu = self.cccoin.tdb.lookup('user_id_to_username',
                                    the_address,
                                    default = False,
                                    at_hash = 'latest'
                                    )
        
        if uu:
            got_username = hh['requested_username']
            username_success = True
        else:
            got_username = hh['requested_username']
        
        self.cccoin.sdb.store('user_id_to_username',
                              the_address,
                              hh['requested_username'],
                              is_pending = True,
                              )
                
        ## Check if previously unseen user ID:
        
        is_new = self.cccoin.DBL['SEEN_USERS_DB'].get(the_pub, False)
        
        ## Write out results:
        
        print ('LOGIN_2_RESULT','username_success:', username_success, 'password_success:', password_success)
        
        if (username_success and password_success):
            self.set_secure_cookie('auth', json.dumps({'created':int(time()),
                                                       'pub':the_pub,
                                                       'address':pub_to_address(the_pub),
                                                       }))
            self.cccoin.DBL['SEEN_USERS_DB'][the_pub] = True
        
        self.write_json({"success":password_success,
	                 "username_success":username_success,
	                 "password_success":password_success,
	                 "got_username":got_username,
	                 "message":'',
                         'is_new':is_new,
	                 })
        


        




class handle_echo(BaseHandler):
    #@check_auth()
    @tornado.gen.coroutine
    def post(self):
        data = self.request.body
        print ('ECHO:')
        print (json.dumps(json.loads(data), indent=4))
        print
        self.write('{"success":true}')


from tornado.httpclient import AsyncHTTPClient

class handle_api(BaseHandler):

    #@check_auth()
    @tornado.gen.coroutine
    def post(self):

        data = self.request.body
        
        hh = json.loads(data)
        
        print ('THE_BODY', data)
                
        forward_url = 'http://127.0.0.1:50000/' + hh['command']

        print ('API_FORWARD', forward_url)
        
        response = yield AsyncHTTPClient().fetch(forward_url,
                                                 method = 'POST',
                                                 connect_timeout = 30,
                                                 request_timeout = 30,
                                                 body = data,
                                                 headers = dict(self.request.headers),
                                                 #allow_nonstandard_methods = True,
                                                 )
        d2 = response.body

        print ('D2', d2)
        
        self.write(d2)
        self.finish()
        

class handle_blind(BaseHandler):
    @check_auth(needs_write = True)
    @tornado.gen.coroutine
    def post(self):
        session = self.get_current_user()
        rr = self.cccoin.submit_blind_action(session['write_data'])
        self.write_json(rr)


class handle_unblind(BaseHandler):
    @check_auth(needs_write = True)
    @tornado.gen.coroutine
    def post(self):
        session = self.get_current_user()
        rr = self.cccoin.submit_unblind_action(session['write_data'])
        self.write_json(rr)

        
class handle_track(BaseHandler):

    @check_auth()
    @tornado.gen.coroutine
    def post(self):
        
        tracking_id = intget(self.get_argument('tracking_id',''), False)
        
        self.write_json({'success':True, 'tracking_id':tracking_id, 'status':False})
        

def inner_start_web(cccoin,
                    image_proxy_path = False,
                    web_node_flag_accounts = [],
                    web_node_approval_accounts = [],
                    port = 50000,
                    ):
    
    print ('BINDING', port)
    
    try:
        tornado.options.parse_command_line()
        http_server = HTTPServer(Application(cccoin,
                                             image_proxy_path,
                                             web_node_flag_accounts,
                                             web_node_approval_accounts,
                                             ),
                                 xheaders=True,
                                 )
        http_server.bind(port)
        http_server.start(1) # Forks multiple sub-processes
        tornado.ioloop.IOLoop.instance().set_blocking_log_threshold(0.5)
        IOLoop.instance().start()
        
    except KeyboardInterrupt:
        print 'Exit'
    
    print ('WEB_STARTED')
