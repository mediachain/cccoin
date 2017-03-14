#!/usr/bin/env python

from node_temporal import TemporalDB, T_ANY_FORK
from node_mc import MediachainQueue

import bitcoin as btc
import ethereum.utils ## Slow...
import ethereum.abi
import struct
import binascii
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from collections import Counter

from os import urandom
from time import time

import multiprocessing

##
#### Serialization & Utils:
##

from Crypto.Hash import keccak

sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()

def web3_sha3(seed):
    return '0x' + (sha3_256(str(seed)).encode('hex'))

#assert web3_sha3('').encode('hex') == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
assert web3_sha3('') == '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

def consistent_hash(h):
    ## Not using `dumps_compact()`, in case we want to change that later.
    return web3_sha3(json.dumps(h, separators=(',', ':'), sort_keys=True))

def dumps_compact(h):
    #print ('dumps_compact',h)
    return json.dumps(h, separators=(',', ':'), sort_keys=True)

def loads_compact(d):
    #print ('loads_compact',d)
    r = json.loads(d)#, separators=(',', ':'))
    return r

def create_long_id(sender, data):
    """
    Use first 20 bytes of hash of sender's public key and data that was signed, to create a unique ID.

    TODO - Later, after ~15 confirmations, contract owner can mine short IDs.
    """
    ss = sender + data
    if type(ss) == unicode:
        ss = ss.encode('utf8')
    xx = btc.sha256(ss)[:20]
    xx = btc.changebase(xx, 16, 58)
    xx = 'i' + xx
    return xx

def solidity_string_decode(ss):
    if ss.startswith('{'):
        ## TODO: some versions of testrpc returning decoded `data`, some not?
        return ss
    ss = binascii.unhexlify(ss[2:])
    ln = struct.unpack(">I", ss[32:][:32][-4:])[0]
    return ss[32:][32:][:ln]

def solidity_string_encode(ss):
    rr = ('\x00' * 31) + ' ' + ('\x00' * 28) + struct.pack(">I", len(ss)) + ss    
    rem = 32 - (len(rr) % 32)
    if rem != 0:
        rr += ('\x00' * (rem))
    rr = '0x' + binascii.hexlify(rr)
    return rr


class SharedCounter(object):
    def __init__(self, n=0):
        self.count = multiprocessing.Value('i', n)

    def increment(self, n=1):
        """ Increment the counter by n (default = 1) """
        with self.count.get_lock():
            self.count.value += n
            r = self.count.value
        return r

    def decrement(self, n=1):
        """ Decrement the counter by n (default = 1) """
        with self.count.get_lock():
            self.count.value -= n
            r = self.count.value
        return r

    @property
    def value(self):
        """ Return the value of the counter """
        return self.count.value

def client_vote(item_id,
                direction,
                priv,
                pub,
                ):
    return client_create_blind({'votes':[{'item_id':item_id,
					'direction':direction,
                                        }],
                                'rand': binascii.hexlify(urandom(16)),
                                },
                               item_type = 'votes',
                               priv = priv,
                               pub = pub,
                               )
    
def client_post(image_url,
                image_title,
                priv,
                pub,
                use_id = False,
                ):
    inner = {'image_url':image_url,
	     'image_title':image_title,
             }
    if use_id is not False:
        inner['use_id'] = use_id
    return client_create_blind({'posts':[inner],
                                'rand': binascii.hexlify(urandom(16)),
                                },
                               item_type = 'posts',
                               priv = priv,
                               pub = pub,
                               )
    
def client_create_blind(inner,
                        item_type,
                        priv = False,
                        pub = False,
                       ):
    """
    Simulates blind call from frontend.
    """
    
    hidden = dumps_compact(inner)
    
    blind_hash = btc.sha256(hidden)

    payload_1 = dumps_compact({'command':'blind',
                               'item_type':item_type,
                               'num_items':1,
                               'blind_hash':blind_hash,
                               'nonce':int(time() * 1000),
                               })
    
    V, R, S = btc.ecdsa_raw_sign(btc.sha256(payload_1), priv)
    
    r_blind = {'payload':payload_1,
               'sig':{'sig_s':btc.encode(S,16),
                      'sig_r':btc.encode(R,16),
                      'sig_v':V,
                      },
              'pub':pub,
              }
    
    payload_2 = dumps_compact({'command':'unblind',
                               'item_type':item_type,
                               'num_items':1,
                               'blind_hash':blind_hash,
                               'blind_reveal':hidden,
                               'nonce':int(time() * 1000),
                               })
    
    V, R, S = btc.ecdsa_raw_sign(btc.sha256(payload_2), priv)
    
    r_unblind = {'payload':payload_2,
                 'sig':{'sig_s':btc.encode(S,16),
                        'sig_r':btc.encode(R,16),
                        'sig_v':V,
                        },
                 'pub':pub,
                 }
    
    return r_blind, r_unblind


def pub_to_address(pub):
    return '0x' + sha3_256(str(pub))[-20:].encode('hex')

def event_sig_to_topic_id(sig):
    name = sig[:sig.find('(')]
    types = [x.strip().split()[0] for x in sig[sig.find('(')+1:sig.find(')')].split(',')]
    return ethereum.utils.int_to_hex(ethereum.abi.event_id(name,types))

class CCCoinCore:
    
    def __init__(self,
                 state_manager,
                 #contract_wrapper = False,
                 mode = 'web',
                 settings_rewards = {},
                 genesis_users = [],
                 mediachain_api_url = False,
                 ):
        """
        Note: Either `the_code` or `the_address` should be supplied to the contract.

        Args:
        - the_code: solidity code for contract that should be deployed, prior to any operations.
        - the_address: address of already-deployed main contract.
        - fake_id_testing_mode: Convenience for testing, uses `use_id` values as the IDs.
        - mode: Mode with which run this node:
          + web: web node that computes the state of the system and serves it to web browsers.
          + rewards: rewards node that mints new ERC20 tokens based on the rewards system.
        - genesis_users: Give these users free genesis LOCK, to bootstrap rewards.
        """
        
        assert mode in ['web', 'rewards', 'audit']
        
        assert settings_rewards
        
        self.rw = settings_rewards

        if mediachain_api_url:
            self.mcq = MediachainQueue(mc_api_url=mediachain_api_url, default_namespace = 'cccoin')
        else:
            self.mcq = False
        
        self.mode = mode

        self.genesis_users = genesis_users

        
        ## Local state for this web node, that shouldn't be written to the blockchain:
        
        manager = multiprocessing.Manager()
        
        self.DBL = {}
        
        self.DBL['RUN_ID'] = get_random_bytes(32).encode('hex')
        
        self.DBL['TRACKING_NUM'] = SharedCounter()
        
        self.DBL['LATEST_NONCE'] = manager.dict() ## {api_key:nonce}
        
        self.DBL['CHALLENGES_DB'] = manager.dict() ## {'address':challenge}

        self.DBL['SEEN_USERS_DB'] = manager.dict() ## {'address':1}
        
        self.DBL['all_dbs'] = {}
        
        """
        self.fake_id_testing_mode = fake_id_testing_mode
        
        self.offline_testing_mode = offline_testing_mode

        self.cw = contract_wrapper

        assert not offline_testing_mode, 'offline_testing_mode no longer used'
        
        if not offline_testing_mode:
            assert contract_wrapper is not False                
            self.cw.events_callback = self.process_event
            self.cw.reorg_callback = self.process_reorg
        
        ##
        #### Tracks the local fork of the blockchain, plus some extra convenience tracking:
        ##
        
        manager = multiprocessing.Manager()
        
        self.DBL = {}
        
        self.DBL['RUN_ID'] = get_random_bytes(32).encode('hex')
        
        self.DBL['TRACKING_NUM'] = SharedCounter()
        
        self.DBL['LATEST_NONCE'] = manager.dict() ## {api_key:nonce}
        
        self.DBL['CHALLENGES_DB'] = manager.dict() ## {'public_key':challenge}
        
        self.DBL['SEEN_USERS_DB'] = manager.dict() ## {'public_key':1}
        
        self.DBL['TAKEN_USERNAMES_DB'] = manager.dict() ## {'username':1}
        
        self.DBL['all_dbs'] = {}

        for which in ['BLOCKCHAIN_CONFIRMED',
                      'BLOCKCHAIN_PENDING',
                      'DIRECT',
                      ]:
            self.DBL['all_dbs'][which] = {'votes':manager.dict(),  ## {(pub_key, item_id):direction},
                                          'flags':manager.dict(),  ## {(pub_key, item_id):direction},
                                          'posts':manager.dict(),  ## {post_id:post}
                                          'scores':manager.dict(), ## {item_id:score}
                                          'tok':manager.dict(),    ## {pub_key:amount_tok}
                                          'lock':manager.dict(),   ## {pub_key:amount_lock}
                                          }

            
        ##
        self.all_users = {}
        
        ###
        
        self.latest_rewarded_block_number = -1
        
        self.posts_by_post_id = {}        ## {post_id:post}
        self.post_ids_by_block_num = {}   ## {block_num:[post_id,...]}
        self.votes_lookup = {}            ## {(user_id, item_id): direction}
        
        self.blind_lookup = {}            ## {block_number:[block_hash, ...]}
        self.blind_lookup_rev = {}        ## {blind_hash:block_number}

        self.old_actions = {}             ## {block_num:[action,...]}
        self.old_lock_balances = {}       ## {block_num:}
        
        self.block_info = {}              ## {block_number:{info}}
        
        self.balances_tok = {}            ## {user_id:amount}
        self.balances_lock = {}           ## {user_id:amount}
        
        self.voting_bandwidth = {}        ## {user_id:amount}
        self.posting_bandwidth = {}       ## {user_id:amount}

        self.num_votes = Counter()        ## {(user_id,block_num):num}

        self.prev_block_number = -1
        
        
        #### TESTING VARS FOR test_feed_round():
        
        self.map_fake_to_real_user_ids = {}
        self.map_real_to_fake_user_ids = {}
        self.feed_history = []
        
        self.latest_block_number = -1

        ####
        
        self.block_details = {}
        """
        
        #### STATE SNAPSHOTS FOR OLD BLOCKS:

        ## Combine these all together in order of blocks to get full state snapshot:
        
        ## {block_num: {blind_hash:(voter_id, item_id)}}
        
        self.sdb = state_manager
        
        self.sdb.setup_tables(table_names = ['unblinded_votes',
                                             'unblinded_flags',
                                             'unblinded_approvals',
                                             'min_lock_per_user',
                                             'lock_per_item',
                                             'posts',
                                             'post_voters_0',
                                             'post_voters_-1',
                                             'post_voters_1',
                                             'post_voters_2',
                                             'post_voters_-2',
                                             'post_voters_3',
                                             'post_voters_-3',
                                             'paid_rewards_lock',
                                             'owed_rewards_lock',
                                             'user_id_to_username',
                                             'username_to_user_id',
                                             'scores',
                                             'scores_per_user',
                                             'blind_lookup',
                                             'blind_lookup_rev',
                                             ],
                              )
        
        self.sdb.setup_logic_callback(logic_callback = self.process_event)
        
            
    def process_lockup(self,
                       is_pending,
                       block_hash,
                       recipient,
                       amount_tok,
                       final_tok,
                       final_lock,
                       ):
        """
        event LockupTokEvent(address recipient, uint amount_tok, uint final_tok, uint final_lock);
        """

        ## Update minimal LOCK at each block:
        
        self.sdb.store('min_lock_per_user',
                       recipient,
                       min(final_lock,
                           self.sdb.lookup('min_lock_per_user',
                                           recipient,
                                           default = maxint,
                                           at_hash = block_hash,
                                           #block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                           allow_pending = is_pending,
                                           )[0],
                           ),
                       cur_hash = block_hash,
                       is_pending = is_pending,
                       )
    
    def process_mint(self,
                     is_pending,
                     msg_block_num,
                     reward_tok,
                     reward_lock,
                     recipient,
                     block_num,
                     rewards_freq,
                     tot_tok,
                     tot_lock,
                     current_tok,
                     current_lock,
                     minted_tok,
                     minted_lock,
                     ):
        """
        Received minting event.

        event MintEvent(uint reward_tok, uint reward_lock, address recipient, uint block_num, uint rewards_freq, uint tot_tok, uint tot_lock, uint current_tok, uint current_lock, uint minted_tok, uint minted_lock);
        """
        self.sdb.store('paid_rewards_lock',
                       user_id,
                       max(minted_lock,
                           self.sdb.lookup('paid_rewards_lock',
                                           user_id,
                                           default = 0,
                                           #block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                           at_hash = block_hash,
                                           allow_pending = is_pending,
                                           )[0],
                           ),
                       cur_hash = block_hash,
                       is_pending = is_pending,
                       )
    
    def process_event(self, msg, *args, **kw):
        """
        Proxy event to appropriate handler based on topic id.
        """

        if 'topics' not in msg:
            return self.process_thelog(msg, *args, **kw)
            
        
        if msg['topics']:
            assert len(msg['topics']) == 1, msg['topics']

        if msg['topics'][0] == '0x27de6db42843ccfcf83809e5a91302efd147c7514e1f7566b5da6075ad2ef4df':
            ## event_sig_to_topic_id('TheLog(bytes)')
            return self.process_thelog(msg, *args, **kw)
        
        elif msg['topics'][0] == '0x1f9e803538b221c54457d8f3287da41cc1cf9a49bfd8b838d15c3d86c3f4a704':
            ## event_sig_to_topic_id('MintEvent(uint,uint,address,uint,uint);')
            ## TODO: convert msg to a bunch of args:
	    return self.process_mint(msg, *args, **kw)
            
        elif msg['topics'][0] == '0xf9066a9b8e7a2ee9afab4894c00a535cc03e07674693fab39a2ba7119e626d0c':
            ## event_sig_to_topic_id('LockupTokEvent(address recipient, uint amount_tok, uint final_tok, uint final_lock)')
            ## TODO: convert msg to a bunch of args:
            return self.process_lockuptok(msg, *args, **kw)
        else:
            assert False, ('UNKNOWN_TOPICS', msg['topics'])
                 
        
    def process_thelog(self,
                       msg,
                       is_noop = False,                      ## New block received, but had no event logs of any type.
                       is_pending = False,                   ## Update came from pending transaction.
                       do_verify = True,
                       ):
        """
        ethereum.utils.int_to_hex(event_id('TheLog',['bytes']))
        = 
        
        - Update internal state based on new messages.
        - Compute rewards for confirmed blocks, every N hours.
           + Distribute rewards if synced to latest block.
           + Otherwise read in and subtract old rewards, to compute outstanding rewards.
        
        === Example msg:
        {
            "type": "mined", 
            "blockHash": "0xebe2f5a6c9959f83afc97a54d115b64b3f8ce62bbccb83f22c030a47edf0c301", 
            "transactionHash": "0x3a6d530e14e683e767d12956cb54c62f7e8aff189a6106c3222b294310cd1270", 
            "data": "{\"has_read\":true,\"has_write\":true,\"pub\":\"f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1\",\"write_data\":{\"payload\":\"{\\\"command\\\":\\\"unblind\\\",\\\"item_type\\\":\\\"votes\\\",\\\"blind_hash\\\":\\\"59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471\\\",\\\"blind_reveal\\\":\\\"{\\\\\\\"votes\\\\\\\":[{\\\\\\\"item_id\\\\\\\":\\\\\\\"1\\\\\\\",\\\\\\\"direction\\\\\\\":0}],\\\\\\\"rand\\\\\\\":\\\\\\\"tLKFUfvh0McIDUhr\\\\\\\"}\\\",\\\"nonce\\\":1485934064181}\",\"payload_decoded\":{\"blind_hash\":\"59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471\",\"blind_reveal\":\"{\\\"votes\\\":[{\\\"item_id\\\":\\\"1\\\",\\\"direction\\\":0}],\\\"rand\\\":\\\"tLKFUfvh0McIDUhr\\\"}\",\"command\":\"unblind\",\"item_type\":\"votes\",\"nonce\":1485934064181},\"pub\":\"f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1\",\"sig\":{\"sig_r\":\"9f074305e710c458ee556f7c6ba236cc57869ad9348c75ce1a47094b9dbaa6dc\",\"sig_s\":\"7d0e0d70f1d440e86487881893e27f12192dd23549daa4dc89bb4530aee35c3b\",\"sig_v\":28}}}", 
            "topics": [
                "0x27de6db42843ccfcf83809e5a91302efd147c7514e1f7566b5da6075ad2ef4df"
            ], 
            "blockNumber": "0x68", 
            "address": "0x88f93641a96cb032fd90120520b883a657a6f229", 
            "logIndex": "0x00", 
            "transactionIndex": "0x00"
        }
        
        === Example loads_compact(msg['data']):
        
        {
            "pub": "f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1", 
            "sig": {
                "sig_s": "7d0e0d70f1d440e86487881893e27f12192dd23549daa4dc89bb4530aee35c3b", 
                "sig_r": "9f074305e710c458ee556f7c6ba236cc57869ad9348c75ce1a47094b9dbaa6dc", 
                "sig_v": 28
            }, 
            "payload": "{\"command\":\"unblind\",\"item_type\":\"votes\",\"blind_hash\":\"59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471\",\"blind_reveal\":\"{\\\"votes\\\":[{\\\"item_id\\\":\\\"1\\\",\\\"direction\\\":0}],\\\"rand\\\":\\\"tLKFUfvh0McIDUhr\\\"}\",\"nonce\":1485934064181}", 
        }
        
        ==== Example loads_compact(loads_compact(msg['data'])['payload'])
        
        {
            "nonce": 1485934064181, 
            "item_type": "votes", 
            "blind_hash": "59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471", 
            "blind_reveal": "{\"votes\":[{\"item_id\":\"1\",\"direction\":0}],\"rand\":\"tLKFUfvh0McIDUhr\"}", 
            "command": "unblind"
        }
        
        """
        
        if is_pending:
            payload_decoded = loads_compact(msg['payload'])
            msg_data = msg
            msg = {'data':msg}
            msg['blockNumber'] = False
        else:
            msg_data = loads_compact(msg['data'])
            payload_decoded = loads_compact(msg_data['payload'])
                
        print ('====PROCESS_EVENT:', is_pending)
        print json.dumps(msg, indent=4)

        #payload_decoded['nonce'] = False ## TODO, make nonce in user's browser.
        assert 'nonce' in payload_decoded

        if do_verify:
            is_success = btc.ecdsa_raw_verify(btc.sha256(msg_data['payload'].encode('utf8')),
                                              (msg_data['sig']['sig_v'],
                                               btc.decode(msg_data['sig']['sig_r'],16),
                                               btc.decode(msg_data['sig']['sig_s'],16),
                                              ),
                                              msg_data['pub'],
                                              )
            assert is_success, 'MESSAGE_VERIFY_FAILED'
        
        item_ids = [] ## For commands that create new items.

        creator_pub = msg_data['pub']

        #creator_address = btc.pubtoaddr(msg_data['pub'])

        #creator_address = '0x' + sha3_256(msg_data['pub'])[-20:].encode('hex')
        #creator_address = msg_data['pub'][:20]
        creator_address = pub_to_address(creator_pub)
        #creator_address = msg_data['pub']
        creator_pub = msg_data['pub']
        
        if payload_decoded['command'] == 'balance':
            
            ## Record balance updates:
            
            assert False, 'TODO - confirm that log was written by contract.'
            
            self.balances_tok[payload['addr']] += payload['amount']
            
        elif payload_decoded['command'] == 'blind':
            
            self.sdb.store('blind_lookup',
                           payload_decoded['blind_hash'],
                           msg['blockHash'], #msg['blockNumber'],
                           is_pending = is_pending,
                           cur_hash = msg['blockHash'],
                           nonce = payload_decoded['nonce'],
                           #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                           #is_pending_timeout = False,
                           #is_pending_replaces_nonce = False,
                           )
        
        elif payload_decoded['command'] == 'unblind':
            
            print ('====COMMAND_UNBLIND:', payload_decoded)
            
            payload_inner = loads_compact(payload_decoded['blind_reveal'])
            
            ## Check that reveal matches supposed blind hash:

            hsh = btc.sha256(payload_decoded['blind_reveal'].encode('utf8'))
            
            hash_fail = False
            
            if payload_decoded['blind_hash'] != hsh:
                
                print ('HASH_MISMATCH', payload_decoded['blind_hash'], hsh)

                hash_fail = True

                payload_decoded['blind_hash'] = hsh

            ##
            #### Unblind credit:
            ##   Get block_num to credit the unblind to. If blind was never seen, just credit to current block:
            ##   TODO: limit how far back blinding can go?
            ##   TODO: if rewards period for that block already passed, move credit to later block?

            blind_credit_block_hash = self.sdb.lookup('blind_lookup',
                                                      payload_decoded['blind_hash'],
                                                      at_hash = msg['blockHash'],
                                                      default = msg['blockNumber'],
                                                      allow_pending = True,
                                                      )#[0]
            
            print ('PAYLOAD_INNER:', payload_inner)

            if payload_decoded['item_type'] == 'username':
                
                print ('====USERNAME_REQUEST', is_pending, payload_inner['username'])

                username_norm = payload_inner['username'].strip()[:25]
                
                if len(username_norm) < 2:
                    print ('REFUSING_USERNAME', payload_inner['username'])
                    
                else:
                    with self.sdb.the_lock:

                        ## check that no one's confirmed it:

                        tm = self.sdb.lookup('user_id_to_username',
                                             creator_address,
                                             at_hash = msg['blockHash'],
                                             default = False,
                                             allow_pending = True,
                                             )#[0]

                        if tm is False:
                            self.sdb.store('user_id_to_username',
                                           creator_address,
                                           username_norm,
                                           cur_hash = blind_credit_block_hash, #msg['blockHash'],
                                           nonce = payload_decoded['nonce'],
                                           is_pending = is_pending,
                                           #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                           #is_pending_timeout = False,
                                           #is_pending_replaces_nonce = False,
                                           )
                        #print 'PUB', msg_data['pub']
            
            elif payload_decoded['item_type'] == 'posts':
                
                print ('====COMMAND_UNBLIND_POSTS:', payload_inner)
                
                #### FROM PENDING:
                
                #assert False, 'WIP'
                
                ## Cache post:
                
                for post in payload_inner['posts']:
                    
                    ## Update local caches:
                    
                    if self.fake_id_testing_mode:
                        post_id = post['use_id']
                    else:
                        post_id = create_long_id(creator_pub, dumps_compact(post))
                    
                    item_ids.append(post_id)
                    
                    post['post_id'] = post_id
                    post['status'] = {'confirmed':False,
                                      'created_time': int(time()),
                                      'created_block_num':False, ## Filled in when confirmed via blockchain
                                      #'score':1,
                                      #'score_weighted':1,
                                      'creator_address':creator_address,#creator_pub[:20], ## TEMP
                                      'creator_pub':creator_pub,
                                      }
                    
                    self.posts_by_post_id[post_id] = post                        
                    
                    if not is_pending:
                        
                        post['status']['confirmed'] = True
                        post['status']['created_block_hash'] = blind_credit_block_hash
                        post['status']['created_time'] = self.sdb.block_details.get(blind_credit_block_hash,
                                                                                    {'timestamp':int(time())},
                                                                                    )['timestamp']
                        
                    self.sdb.store('posts',
                                   post['post_id'],
                                   post,
                                   cur_hash = blind_credit_block_hash, #msg['blockHash'],
                                   nonce = payload_decoded['nonce'],
                                   is_pending = is_pending,
                                   #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                   #is_pending_timeout = False,
                                   #is_pending_replaces_nonce = False,                                      
                                   )
                    
                    ## Write to mediachain:
                    
                    if not is_pending:
                        if self.mcq is not False:
                            self.mcq.push(data = msg,
                                          refs = post['post_id'],
                                          )
                        
            elif payload_decoded['item_type'] == 'votes':
                
                for vote in payload_inner['votes']:
                    
                    ## Record {(voter, item_id) -> direction} present lookup:
                    
                    if (int(vote['direction']) in [-1, 1, 0]):
                        
                        with self.sdb.the_lock:
                            
                            cur_dir = self.sdb.lookup('post_voters_' + str(int(vote['direction'])),
                                                      creator_address + '|' + vote['item_id'],
                                                      default = 0,
                                                      at_hash = msg['blockHash'],
                                                      allow_pending = True,
                                                      )#[0]
                            
                            if cur_dir == -1:
                                if vote['direction'] == -1:
                                    out_dir = 0
                                elif vote['direction'] == 0:
                                    out_dir = 1
                                elif vote['direction'] == 1:
                                    out_dir = 2
                            if cur_dir == 0:
                                if vote['direction'] == -1:
                                    out_dir = -1
                                elif vote['direction'] == 0:
                                    out_dir = 0
                                elif vote['direction'] == 1:
                                    out_dir = 1
                            if cur_dir == 1:
                                if vote['direction'] == -1:
                                    out_dir = -2
                                elif vote['direction'] == 0:
                                    out_dir = 1
                                elif vote['direction'] == 1:
                                    out_dir = 0
                            
                            cur_score = self.sdb.lookup('scores',
                                                        creator_address + '|' + vote['item_id'],
                                                        default = 0,
                                                        at_hash = msg['blockHash'],
                                                        allow_pending = True,
                                                        )#[0]
                            
                            self.sdb.store('scores',
                                           vote['item_id'],
                                           cur_score + out_dir,
                                           cur_hash = msg['blockHash'],
                                           nonce = False,
                                           is_pending = is_pending,
                                           #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                           #is_pending_timeout = False,
                                           #is_pending_replaces_nonce = False,
                                           )
                            
                            cur_score_user = self.sdb.lookup('scores_per_user',
                                                             creator_address,
                                                             default = 0,
                                                             at_hash = msg['blockHash'],
                                                             allow_pending = True,
                                                             )#[0]
                            
                            self.sdb.store('scores_per_user',
                                           creator_address,
                                           cur_score_user + out_dir,
                                           cur_hash = msg['blockHash'],
                                           nonce = False,
                                           is_pending = is_pending,
                                           #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                           #is_pending_timeout = False,
                                           #is_pending_replaces_nonce = False,
                                           )
                    
                    ## Record {item_id -> voters} historic lookup:
                    
                    print ('MSG', is_pending, msg)
                    
                    self.sdb.store('post_voters_' + str(int(vote['direction'])),
                                   vote['item_id'],
                                   creator_address,
                                   cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                   nonce = payload_decoded['nonce'],
                                   is_pending = is_pending,
                                   as_set_op = True,
                                   #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                   #is_pending_timeout = False,
                                   #is_pending_replaces_nonce = False,
                                   )
                    
                    if vote['direction'] == -1:
                        try:
                            self.sdb.remove('post_voters_' + str(1),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            print ('WARN: UNDO VOTE THAT DID NOT EXIST', vote)
                    elif vote['direction'] == 1 :
                        try:
                            self.sdb.remove('post_voters_' + str(-1),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            pass
                    elif vote['direction'] == 0:
                        #try:
                        self.sdb.remove('post_voters_' + str(-1),
                                        vote['item_id'],
                                        creator_address,
                                        cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                        nonce = payload_decoded['nonce'],
                                        is_pending = is_pending,
                                        as_set_op = True,
                                        #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                        #is_pending_timeout = False,
                                        #is_pending_replaces_nonce = False,
                                        )
                        #except KeyError:
                        #    pass
                        #try:
                        self.sdb.remove('post_voters_' + str(1),
                                        vote['item_id'],
                                        creator_address,
                                        cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                        nonce = payload_decoded['nonce'],
                                        is_pending = is_pending,
                                        as_set_op = True,
                                        #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                        #is_pending_timeout = False,
                                        #is_pending_replaces_nonce = False,
                                        )
                        #except KeyError:
                        #    pass
                    elif vote['direction'] == -2:
                        try:
                            self.sdb.remove('post_voters_' + str(2),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            pass
                    elif vote['direction'] == 2:
                        try:
                            self.sdb.remove('post_voters_' + str(-2),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            pass
                    elif vote['direction'] == -3:
                        try:
                            self.sdb.remove('post_voters_' + str(3),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            pass
                    elif vote['direction'] == 3:
                        try:
                            self.sdb.remove('post_voters_' + str(-3),
                                            vote['item_id'],
                                            creator_address,
                                            cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                            nonce = payload_decoded['nonce'],
                                            is_pending = is_pending,
                                            as_set_op = True,
                                            #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                            #is_pending_timeout = False,
                                            #is_pending_replaces_nonce = False,
                                            )
                        except KeyError:
                            pass
                    else:
                        assert False, vote['direction']


                    ####
                    
                    if vote['direction'] in [1, -1]:
                        
                        self.sdb.store('unblinded_votes',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )
                        
                    elif vote['direction'] == 0:

                        self.sdb.store('unblinded_votes',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )


                    elif vote['direction'] == 2:
                                                
                        self.sdb.store('unblinded_flags',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )
                        
                    elif vote['direction'] == -2:
                        
                        self.sdb.store('unblinded_flags',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )
                        
                    elif vote['direction'] == 3:
                        self.sdb.store('unblinded_approvals',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )
                        
                    elif vote['direction'] == -3:                        
                        self.sdb.store('unblinded_approvals',
                                       creator_address + '|' + vote['item_id'],
                                       vote['direction'],
                                       cur_hash = msg['blockHash'], #blind_credit_block_hash,
                                       nonce = payload_decoded['nonce'],
                                       is_pending = is_pending,
                                       #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                       #is_pending_timeout = False,
                                       #is_pending_replaces_nonce = False,
                                       )
                        
                    else:
                        assert False, repr(vote['direction'])
                        
            else:
                assert False, ('UNKNOWN_ITEM_TYPE', payload_decoded['item_type'])
                    
        elif payload_decoded['command'] == 'tok_to_lock':
            pass
        
        elif payload_decoded['command'] == 'lock_to_tok':
            pass
        
        elif payload_decoded['command'] == 'account_settings':
            pass
        
        block_number = False
        
        ## Compute block rewards, for actions older than MAX_UNBLIND_DELAY, to allow time for unblinding:
        
        if not is_pending:
            
            ##
            #### START REWARDS CALCULATION:
            ##
            
            block_number = msg['blockNumber']
            
            #assert doing_block_num <= block_number,('TOO SOON, fix MAX_UNBLIND_DELAY', doing_block_num, block_number)
            
            #print 'GREATER?', (msg['blockNumber'], self.latest_block_number, doing_block_num)
            #raw_input()
            
            if (msg['blockNumber'] > self.latest_block_number) and (doing_block_num > 0):
                
                #### GOT NEW BLOCK:
                
                self.latest_block_number = max(block_number, self.latest_block_number)
                
                ## Mint TOK rewards for the old block, upon each block update:

                """
                1) divide total lock among all previous voters + posters.
                2) some votes have less lock if voter voted multiple times this round.
                """
                
                ## Divide up each voter's lock power, between all votes he made this round:
                
                voter_lock_cache = {} ## {voter_id:voter_lock}
                voter_counts = {}     ## {voter_id:set(item_id,...)}
                total_lock = 0
                item_ids = set()
                
                for voter_id_item_id, direction in self.sdb.iterate_items('unblinded_votes',
                                                                          at_hash = msg['blockHash'],
                                                                          block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                                                          allow_pending = False,
                                                                          ):
                    voter_id, item_id = voter_id_item_id.split('|')
                    
                    if voter_id not in voter_counts:
                        voter_lock = self.sdb.lookup('min_lock_per_user',
                                                     voter_id,
                                                     default = 1.0, #(voter_id in self.genesis_users and 1.0 or 0.0),
                                                     block_offset = -self.rw['MAX_UNBLIND_DELAY'], 
                                                     at_hash = msg['blockHash'],
                                                     allow_pending = True,
                                                     )#[0]
                        voter_lock_cache[voter_id] = voter_lock
                        total_lock += voter_lock
                    
                    if voter_id not in voter_counts:
                        voter_counts[voter_id] = set()
                    voter_counts[voter_id].add(item_id)
                    
                    item_ids.add(item_id)
                
                print 'voter_counts:', voter_counts
                print 'voter_lock_cache:', voter_lock_cache
                print 'total_lock:', total_lock
                print 'PRESS ENTER...'
                #raw_input()
                    
                total_lock_per_item = Counter()
                lock_per_user = {}
                
                for (voter_id, item_id), direction in self.sdb.iterate_items('unblinded_votes',
                                                                             at_hash = msg['blockHash'],
                                                                             block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                                                             allow_pending = False,
                                                                             ):
                    ## Spread among all posts he voted on:
                    voter_lock = voter_lock_cache[voter_id] / float(len(voter_counts[voter_id]))
                    lock_per_user[voter_id] = voter_lock
                    total_lock_per_item[item_id] += voter_lock
                    
                
                ## Get list of all old voters, for each post:
                
                old_voters = {}
                
                for item_id in item_ids:
                    old_voters[item_id] = []
                    
                    old_voters[item_id] = self.sdb.lookup('post_voters_1',  ## Upvoters only, for v1.
                                                          item_id,
                                                          default = {},
                                                          block_offset = -self.rw['MAX_UNBLIND_DELAY'], 
                                                          at_hash = msg['blockHash'],
                                                          allow_pending = True,
                                                          ).keys()#[0].keys()
                    
                    ## Treat poster as just another voter:

                    post = False
                    post = self.sdb.lookup('posts',
                                           item_id,
                                           default = False,
                                           at_hash = msg['blockHash'],
                                           allow_pending = True,
                                           )#[0]
                    if post is False:
                        ## TODO -
                        ## We got a vote for a post that's not yet fully confirmed...
                        ## Later reward the submitter... 
                        pass
                    else:
                        item_poster_id = post['status']['creator_address']
                        old_voters[item_id].append(item_poster_id)
                
                #### Compute curation rewards:
                
                all_lock = float(sum(total_lock_per_item.values()))

                if all_lock:

                    #### Have some rewards to record:

                    new_rewards_curator = Counter()
                    new_rewards_sponsor = Counter()

                    for item_id, x_old_voters in old_voters.iteritems():

                        if all_lock and len(old_voters[item_id]):
                            xrw = (total_lock_per_item[item_id] / all_lock) / len(old_voters[item_id])
                        else:
                            xrw = 0

                        new_rewards_curator[voter_id] += xrw

                        ## Sponsor rewards for curation:

                        post = self.sdb.lookup('posts',
                                               item_id,
                                               at_hash = msg['blockHash'],
                                               allow_pending = True,
                                               )#[0]
                        if 'sponsor' in post:
                            new_rewards_curator[post['sponsor']] += xrw


                    ## Re-weight rewards to proper totals:

                    aa = float(sum(new_rewards_curator.values()))
                    if aa:
                        conv = self.rw['REWARDS_CURATION'] / aa
                        new_rewards_curator = [(x,(y * conv)) for x,y in new_rewards_curator.iteritems()]
                    else:
                        new_rewards_curator = []

                    bb = float(sum(new_rewards_sponsor.values()))
                    if bb:
                        conv = self.rw['REWARDS_SPONSOR'] / bb
                        new_rewards_sponsor = [(x,(y * conv)) for x,y in new_rewards_sponsor.iteritems()]
                    else:
                        new_rewards_sponsor = []

                    ## Mark as earned:

                    for user_id, reward in (new_rewards_curator + new_rewards_sponsor):

                        with self.sdb.the_lock:
                            self.sdb.store('earned_rewards_lock',
                                           user_id,
                                           reward + self.sdb.lookup('earned_rewards_lock',
                                                                    user_id,
                                                                    default = 0,
                                                                    cur_hash = msg['blockHash'],
                                                                    is_pending = True,
                                                                    #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                                                    #is_pending_timeout = False,
                                                                    #is_pending_replaces_nonce = False,
                                                                    ),#[0],
                                           cur_hash = msg['blockHash'],
                                           is_pending = True,
                                           #is_pending_dependent_on_hash = payload_decoded['cur_hash'],
                                           #is_pending_timeout = False,
                                           #is_pending_replaces_nonce = False,
                                           )

                
                assert not is_pending

                ##
                #### Occasionally distribute rewards:
                ##
                
                if (self.mode == 'rewards') and (block_number % self.rw['REWARDS_FREQUENCY']) == (self.rw['REWARDS_FREQUENCY'] - 1):
                    
                    ## Compute net owed:
                    
                    old_rewards_block_num = doing_block_num - (self.rw['REWARDS_FREQUENCY'] * 2)
                    
                    net_earned = 0.0
                    
                    for user_id, earned_lock in self.sdb.iterate_items('earned_rewards_lock',
                                                                       at_hash = msg['blockHash'],
                                                                       block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                                                       allow_pending = False,
                                                                       ):
                        
                        paid_lock = self.sdb.lookup('paid_rewards_lock',
                                                    user_id,
                                                    default = 0.0,
                                                    at_hash = msg['blockHash'],
                                                    block_offset = -self.rw['MAX_UNBLIND_DELAY'],
                                                    allow_pending = False,
                                                    )#[0]
                        
                        net_earned += float(max(0.0, earned_lock - paid_lock))
                    
                    ## Distribute rewards:
                    
                    rrr = []
                    tot_lock_paying_now = 0.0
                    for reward, user_id in sorted(new_rewards_curator + new_rewards_sponsor, reverse = True):
                        
                        if tot_lock_paying_now / net_earned >= self.rw['REWARDS_CUTOFF']:
                            break
                        
                        if reward < self.rw['MIN_REWARD_LOCK']:
                            break
                            
                        tot_lock_paying_now += reward

                        rrr.append([reward, user_id])
                        
                    for reward_tok, user_id in rrr:
                        
                        reward_tok = 0.9 * reward_lock
                        tot_tok_paying_now = 0.9 * tot_lock_paying_now
                        
                        tx = self.sdb.send_transaction('mintTokens(address, uint, uint, uint, uint, uint, uint)',
                                                      [reward_tok,
                                                       reward_lock,
                                                       user_id,
                                                       tot_tok_paying_now,
                                                       tot_lock_paying_now,
                                                       block_number,
                                                       self.rw['REWARDS_FREQUENCY'],
                                                       ],
                                                      gas_limit = self.rw['MAX_GAS_REWARDS'],
                                                      )
                    
                    
                ## Cleanup:
                #self.sdb.prune_historical(max_blocks = 50)
                    

            ### END REWARDS
            
            #for xnum in xrange(last_block_rewarded,
            #                   latest_block_ready,
            #                   ):
            #    pass

            if not self.offline_testing_mode:
                self.prev_block_number = msg['blockNumber']
        
        if False and (not is_pending):
            print
            print '====STATE===='
            print 'is_pending:', is_pending
            print 'block_number:', block_number
            print 'command:', payload_decoded['command']
            print 'payload_decoded:', payload_decoded
            #print 'doing_block_num:',doing_block_num
            #print "the_db['votes']", the_db['votes']
            #print "the_db['posts']", the_db['posts']
            #print "the_db['scores']", the_db['scores']
            #print 'self.blind_lookup', self.blind_lookup

            
            print 'feed_history:'
            for c, xx in enumerate(self.feed_history):
                print '%04d' % c, xx

            raw_input()
        
        return {'item_ids':item_ids}
        
    def get_current_tok_per_lock(self,
                                 genesis_tm,
                                 current_tm,
                                 start_amount = 1.0,
                                 ):
        """
        Returns current TOK/LOCK exchange rate, based on seconds since contract genesis and annual lock interest rate.
        """
        
        rr = start_amount * ((1.0 + self.rw['REWARDS_LOCK_INTEREST_RATE']) ** ((current_tm - genesis_tm) / 31557600.0))
        
        return rr
            
        
    def deploy_contract(self,):
        """
        Create new instance of dApp on blockchain.
        """

        assert not self.offline_testing_mode
        
        self.sdb.deploy()
    
        
    def submit_blind_action(self,
                            blind_data,
                            ):
        """
        Submit blinded vote(s) to blockchain.
        
        `blind_data` is signed message containing blinded vote(s), of the form:
        
        {   
            "payload": "{\"command\":\"vote_blind\",\"blind_hash\":\"03689918bda30d10475d2749841a22b30ad8d8d163ff2459aa64ed3ba31eea7c\",\"num_items\":1,\"nonce\":1485769087047}",
            "sig": {
                "sig_s": "4f529f3c8fabd7ecf881953ee01cfec5a67f6b718364a1dc82c1ec06a2c65f14",
                "sig_r": "dc49a14c82f7d05719fa893efbef28b337b913f2be0b1675f3f3722276338730",
                "sig_v": 28
            },
            "pub": "11f1b3f728713521067451ae71e795d05da0298ac923666fb60f6d0f152725b0535d2bb8c5ae5fefea8a6db5de2ac800b658f53f3afa0113f6b2e34d25e0f300"
        }
        """
        
        print ('START_SUBMIT_BLIND_ACTION')
        
        tracking_id = self.DBL['RUN_ID'] + '|' + str(self.DBL['TRACKING_NUM'].increment())
        
        ## Sanity checks:
        
        #self.cache_blind(msg_data['pub'], blind_data, 'DIRECT')

        #assert blind_data['sig']
        #assert blind_data['pub']
        #json.loads(blind_data['payload'])
        
        self.process_event(blind_data,
                           is_pending = True,
                           do_verify = False,
                           )
        
        if not self.offline_testing_mode:
            
            dd = dumps_compact(blind_data)
            
            tx = self.sdb.send_transaction('addLog(bytes)',
                                           [dd],
                                           #send_from = user_id,
                                           gas_limit = self.rw['MAX_GAS_DEFAULT'],
                                           callback = False,
                                          )
        
        print ('DONE_SUBMIT_BLIND_ACTION')
        
        rr = {'success':True,
              'tracking_id':tracking_id,
              'command':'blind_action',
              }
        
        return rr 

    
    def submit_unblind_action(self,
                              msg_data,
                              ):
        """
        Submit unblinded votes to the blockchain.
        
        `msg_data` is signed message revealing previously blinded vote(s), of the form:
        
        {   
            "payload": "{\"command\":\"vote_unblind\",\"blind_hash\":\"03689918bda30d10475d2749841a22b30ad8d8d163ff2459aa64ed3ba31eea7c\",\"blind_reveal\":\"{\\\"votes\\\":[{\\\"item_id\\\":\\\"99\\\",\\\"direction\\\":1}],\\\"rand\\\":\\\"CnKDXhTSU2bdqX4Y\\\"}\",\"nonce\":1485769087216}",
            "sig": {
                "sig_s": "56a5f496962e9a6dedd8fa0d4132c3ffb627cf0c8239c625f857a22d5ee5e080",
                "sig_r": "a846493114e98c0e8aa6f398d33bcbca6e1c277ac9297604ddecb397dc7ed3d8",
                "sig_v": 28
            },
            "pub": "11f1b3f728713521067451ae71e795d05da0298ac923666fb60f6d0f152725b0535d2bb8c5ae5fefea8a6db5de2ac800b658f53f3afa0113f6b2e34d25e0f300"
        }
        """
        
        print ('START_UNBLIND_ACTION', msg_data)
        
        tracking_id = self.DBL['RUN_ID'] + '|' + str(self.DBL['TRACKING_NUM'].increment())
        
        #payload_decoded = json.loads(msg_data['payload'])
        
        #payload_inner = json.loads(payload['blind_reveal'])
        
        #print ('GOT_INNER', payload_inner)
        
        #item_ids = self.cache_unblind(msg_data['pub'], payload_decoded, 'DIRECT')
        
        item_ids = self.process_event(msg_data,
                                      is_pending = True,
                                      do_verify = False,
                                     )['item_ids']
        
        #print ('CACHED_VOTES', dict(self.DBL['all_dbs']['DIRECT']['votes']))
        
        if not self.offline_testing_mode:
            ## Send to blockchain:
            
            rr = dumps_compact(msg_data)
        
            tx = self.sdb.send_transaction('addLog(bytes)',
                                           [rr],
                                           #send_from = user_id,
                                           gas_limit = self.rw['MAX_GAS_DEFAULT'],
                                          )
            #tracking_id = tx
            
        print ('DONE_UNBLIND_ACTION')

        rr = {'success':True,
              'tracking_id':tracking_id,
              "command":"unblind_action",
              'item_ids':item_ids,
              }
        
        return rr
        
    def lockup_tok(self):
        tx = self.sdb.send_transaction('lockupTok(bytes)',
                                       [rr],
                                       gas_limit = self.rw['MAX_GAS_DEFAULT'],
                                       )
    
    def get_balances(self,
                     user_id,
                     ):
        xx = self.sdb.read_transaction('balanceOf(address)',
                                       [rr],
                                       gas_limit = self.rw['MAX_GAS_DEFAULT'],
                                       )
        rr = loads_compact(xx['data'])
        return rr

    def withdraw_lock(self,):
        tx = self.sdb.send_transaction('withdrawTok(bytes)',
                                       [rr],
                                       gas_limit = self.rw['MAX_GAS_DEFAULT'],
                                       )

    def get_vote_history(self,
                         post_id,
                         ):
        ## TODO
        return []
        rr = {}
        for table_name in ['post_voters_1',
                           'post_voters_-1',
                           ]:
            for fork_name in self.cw.confirm_states:
                for block_num, user_id_is_up in self.sdb.tables[table_name].forks[fork_name].hh.get(post_id,{}).items():
                    if block_num not in rr:
                        rr[block_num] = {}
                    for aa,bb in [(x,y and table_name or ('rem_' + table_name)) for x,y in user_id_is_up.items()]:
                        if bb.startswith('rem_'):
                            ## Only overwrite removes:
                            #if aa not in rr[block_num]:
                            #    rr[block_num][aa] = bb
                            pass ## For now, no removes.
                        else:
                            rr[block_num][aa] = bb
        rr = sorted(rr.items(), reverse = True)
        return rr
        
    def get_sorted_posts(self,
                         offset = 0,
                         increment = 50,
                         sort_by = False,
                         filter_users = False,
                         filter_ids = False,
                         web_node_flag_accounts = [],
                         ):
        """
        Get sorted items.
        """
        print ('GET_ITEMS', offset, increment, sort_by, 'filter_users', filter_users, 'filter_ids', filter_ids)

        if (not sort_by) or (sort_by == 'trending'):
            sort_by = 'score'

        if sort_by == 'new':
            sort_by = 'created_time'
            
        if sort_by == 'best':
            sort_by = 'score'
            
        assert sort_by in ['score', 'created_time'], sort_by
        
        ## Filter:
        
        if filter_users:
            rr = []
            #for post in self.posts_by_post_id.itervalues():
            for post_id, post in self.sdb.iterate_items('posts',
                                                        at_hash = 'latest',
                                                        ):
                if (post['status']['creator_address'] in filter_users) or (post['status']['creator_address'][:20] in filter_users):
                    rr.append(post)
                
        elif filter_ids:
            rr = []
            for xx in filter_ids:
                #rr = self.posts_by_post_id.get(xx, False)
                post = self.sdb.lookup('posts',
                                       xx,
                                       at_hash = 'latest',
                                       default = False
                                       )#[0]
                if post:
                    rr.append(post)
        
        else:
            #rr = self.posts_by_post_id.values()
            rr = []
            for post_id, post in self.sdb.iterate_items('posts',
                                                        at_hash = 'latest',
                                                        ):
                rr.append(post)
        
        ## Use highest score from any consensus state:
        
        #the_db = self.DBL['all_dbs'].get(via, [])
        for post in rr:
            #post['status']['score'] = max(the_db['scores'].get(post['post_id'], 0) + 1, post['status'].get('score', 1))
            #post['status']['score'] = len(self.tdb.lookup('post_voters_' + str(1),
            #                                              T_ANY_FORK,
            #                                              post['post_id'],
            #                                              default = set(),
            #                                              as_set_op = True,
            #                                              )[0])
            post['status']['score']  = self.sdb.lookup('scores',
                                                       post['post_id'],
                                                       at_hash = 'latest',
                                                       default = 0,
                                                      )#[0]
            print ('SCORE', post['status']['score'])
        
        ## Sort:
        
        rr = list(sorted([(x['status'][sort_by],x) for x in rr], reverse=True))
        rr = rr[offset:offset + increment]
        rr = [y for x,y in rr]
        
        ## Done:
        
        rrr = {'success':True, 'items':rr, 'sort':sort_by}
        
        print ('GOT', len(rrr))
        
        return rrr

    def get_user_leaderboard(self,
                             offset = 0,
                             increment = 50,
                             ):
        """
        Note: Leaderboard only updated when rewards are re-computed.
        """
        
        #the_db = self.DBL['all_dbs']['BLOCKCHAIN_CONFIRMED']
        
        rr = [(x['score'], x) for x in self.all_users.values()]
        rr = [y for x,y in rr]
        rr = rr[offset:offset + increment]
        
        rrr = {'success':True, 'users':rr}
        
        return rrr

