#!/usr/bin/env python

##
#### Settings:
##

TEST_MODE = False

REWARDS_ACCOUNT = '0x4effded5ac372ec3318142de763d553ca444c1c6'
#REWARDS_ACCOUNT = False

## See cccoin/docs/nginx_config for nginx setup, or set to False to disable.:
IMAGE_PROXY_PATH = '/images/'
#IMAGE_PROXY_PATH = False

DATA_DIR = 'build_contracts/'

DEPLOY_WITH_TRUFFLE = True
CONTRACT_ADDRESS_TRUFFLE_FN = '../build/contracts/CCCoinToken.json'
CONTRACT_ADDRESS_FN = DATA_DIR + 'cccoin_contract_address.txt'

MAIN_CONTRACT_FN = '../contracts/CCCoinToken.sol'

from node_contract import DEFAULT_RPC_HOST, DEFAULT_RPC_PORT

## Rewards parameters:

CORE_SETTINGS = {'REWARDS_CURATION':90.0,     ## Voting rewards
                 'REWARDS_WITNESS':10.0,      ## Witness rewards
                 'REWARDS_SPONSOR':10.0,      ## Web nodes that cover basic GAS / TOK for users on their node.
                 'REWARDS_POSTER_MULT':1,     ## Reward / penalize the poster as if he were this many voters.
                 'REWARDS_CUTOFF':0.95,       ## Percent of total owed rewards to send in each round. Avoids dust.
                 'MIN_REWARD_LOCK':1,         ## Minimum number of LOCK that will be paid as rewards.
                 'REWARDS_FREQUENCY':140,     ## 140 blocks = 7 hours
                 'REWARDS_LOCK_INTEREST_RATE':1.0,   ## Annual interest rate paid to LOCK holders.
                 'MAX_UNBLIND_DELAY':20,      ## Max number of blocks allowed between submitting a blind vote & unblinding.
                 'MAX_GAS_DEFAULT':10000,     ## Default max gas fee per contract call.
                 'MAX_GAS_REWARDS':10000,     ## Max gas for rewards function.
                 'NEW_USER_LOCK_DONATION':1,  ## Free LOCK given to new users that signup through this node.
                 }

## Number of blocks to wait before advancing to each new state:

DEFAULT_CONFIRM_STATES = {'BLOCKCHAIN_PENDING':0,
                          'BLOCKCHAIN_CONFIRMED':15,
                          }
##
#### Print Settings:
##

ss = {x:y for x,y in dict(locals()).iteritems() if not x.startswith('__')}

import json
print 'SETTINGS:'
print json.dumps(ss, indent=4)


##
#### Module Imports:
##

from node_core import (CCCoinCore,
                       solidity_string_encode,
                       solidity_string_decode,
                       dumps_compact,
                       loads_compact,
                       client_post,
                       client_vote,
                       client_create_blind,
                       )
from node_temporal import test_temporal_table
# from node_trend import test_trend_detection
from node_contract import ContractWrapper, test_contract_wrapper
from node_generic import setup_main
from node_web import inner_start_web, sig_helper, vote_helper

##
#### Other Imports:
##

import web3
import bitcoin as btc

import json
from os import mkdir, listdir, makedirs, walk, rename, unlink
from os.path import exists,join,split,realpath,splitext,dirname

from random import choice, randint

##
#### Setup Environment:
##

if not exists(DATA_DIR):
    mkdir(DATA_DIR)

if True:
    with open(MAIN_CONTRACT_FN) as f:
        main_contract_code = f.read()
        
else:
    
    main_contract_code = \
    """
    pragma solidity ^0.4.6;

    contract CCCoin payable {
        event TheLog(bytes);
        function addLog(bytes val) { 
            TheLog(val);
        }
    }
    """#.replace('payable','') ## for old versions of solidity


##
#### Contract Management:
##

def check_anything_deployed(address):
    from ethjsonrpc import EthJsonRpc
    c = EthJsonRpc(DEFAULT_RPC_HOST, DEFAULT_RPC_PORT)
    if c.eth_getCode(address) == '0x0':
        print ('NOTHING DEPLOYED AT SPECIFIED ADDRESS:', address)
        return False
    return True

def get_deployed_address():
    """
    Get contract address, check that anything is actually deployed to that address.
    """
    
    print ('Reading contract address from file...', CONTRACT_ADDRESS_FN)
    if DEPLOY_WITH_TRUFFLE:
        if exists(CONTRACT_ADDRESS_TRUFFLE_FN):
            with open(CONTRACT_ADDRESS_TRUFFLE_FN) as f:
                h = json.loads(f.read())
            if 'address' in h:
                if check_anything_deployed(h['address']):
                    return h['address']
            else:
                print 'FOUND_TRUFFLE_BUT_NO_ADDRESS_KEY', CONTRACT_ADDRESS_TRUFFLE_FN
    
    ## Fallback to this, even if DEPLOY_WITH_TRUFFLE was set:
    if exists(CONTRACT_ADDRESS_FN):
        with open(CONTRACT_ADDRESS_FN) as f:
            d = f.read()
        print ('GOT', d)
        if check_anything_deployed(d):
            return d
    return False


from time import time

def setup_cccoin_contract(set_name = 'CCCoin',
                          set_symbol = 'CCC',
                          set_max_creation_rate_per_second = 1,
                          set_minter_address = REWARDS_ACCOUNT,
                          set_cccoin_address = REWARDS_ACCOUNT,
                          set_start_time = int(time()),
                          deploy_from = REWARDS_ACCOUNT,
                          ):

    print ('READY_TO_DEPLOY', locals())
    
    with open(MAIN_CONTRACT_FN) as f:
        code = f.read()

    ## Need to do in 2 steps, so we can pass `cw.c.coinbase` to the constructor:
    
    cw = ContractWrapper(the_code = code,
                         settings_confirm_states = {'BLOCKCHAIN_CONFIRMED':1},
                         start_at_current_block = True, ## dont get logs from old tests
                         auto_deploy = False,
                         )

    if set_minter_address is False:
        set_minter_address = cw.c.eth_coinbase()
    
    if set_cccoin_address is False:
        set_cccoin_address = cw.c.eth_coinbase()
    
    ## For the sig - NO SPACES AFTER COMMAS ALLOWED! USE uint256 instead of uint!:
    
    cw.deploy(the_sig = 'CCCoinToken(string,string,uint256,address,address,uint256)', 
              the_args = [set_name,
                          set_symbol,
                          set_max_creation_rate_per_second,
                          set_minter_address,
                          set_cccoin_address,
                          set_start_time,
                          ],
              deploy_from = deploy_from,
              block = True,
              )

    return cw


def deploy_contract(via_cli = False,
                    ):
    """
    Deploy new instance of this dApp to the blockchain.
    """
    
    #assert not DEPLOY_WITH_TRUFFLE, 'Must deploy with truffle instead, because DEPLOY_WITH_TRUFFLE is True.'
    
    fn = CONTRACT_ADDRESS_FN
    
    assert not exists(fn), ('File with contract address already exists. Delete this file to ignore:', fn)
    
    if not exists(DATA_DIR):
        mkdir(DATA_DIR)

    cw = setup_cccoin_contract()
    
    assert (cw.contract_address, cw.contract_address)
    
    with open(fn, 'w') as f:
        f.write(cw.contract_address)
    
    print ('NEW_CONTRACT_DEPLOYED', cw.contract_address, '->', fn)
    print ('PRESS ENTER...')
    raw_input()
    
    
    return cw.contract_address
    
##
#### Cross-Component Testing:
##  
    
def test_rewards(via_cli = False):
    """
    Variety of tests for the rewards function.
    """
    
    code = \
    """
    pragma solidity ^0.4.6;

    contract CCCoinToken {
        event TheLog(bytes);
        function addLog(bytes val) payable { 
            TheLog(val);
        }
    }
    """
    
    ## Deploy again and ignore any existing state:
    
    rw = CORE_SETTINGS.copy()
    
    rw.update({'REWARDS_FREQUENCY':1, ## Compute after every block.
               'REWARDS_CURATION':1.0,##
               'REWARDS_WITNESS':1.0, ##
               'REWARDS_SPONSOR':1.0, ##
               'MAX_UNBLIND_DELAY':0, ## Wait zero extra blocks for unblindings.
               })
    
    unk = set(rw).difference(CORE_SETTINGS)
    assert not unk, ('UNKNOWN SETTINGS:', unk)
    
    cw = ContractWrapper(the_code = code,
                         start_at_current_block = True,
                         settings_confirm_states = {'BLOCKCHAIN_CONFIRMED':0, ## Confirm instantly
                                                    },
                         )        

    cca = CCCoinCore(contract_wrapper = cw,
                     settings_rewards = rw,
                     genesis_users = ['u1','u2','u3'], ## Give these users free genesis LOCK, to bootstrap rewards.
                     )
    
    cca.test_feed_round([{'user_id':'u3','action':'post','use_id':'p1','image_title':'a'},
                         {'user_id':'u3','action':'post','use_id':'p2','image_title':'b'},
                         {'user_id':'u1','action':'vote','item_id':'p1','direction':1},
                         ])

    cca.test_feed_round([{'user_id':'u2','action':'vote','item_id':'p2','direction':1},
                         ])
    
    ## u1 should have a vote reward, u3 should have a post reward:



def test_3(via_cli = False):
    """
    Test 3.
    """
    offline_testing_mode = False

    code = \
    """
    pragma solidity ^0.4.6;

    contract CCCoinToken {
        event TheLog(bytes);
        function addLog(bytes val) payable { 
            TheLog(val);
        }
    }
    """
    
    the_pw = 'some big long brainwallet password'
    priv = btc.sha256(the_pw)
    pub = btc.privtopub(priv)

    cw = ContractWrapper(the_code = code,
                         settings_confirm_states = DEFAULT_CONFIRM_STATES,
                         )

    cccoin = CCCoinCore(contract_wrapper = cw,
                        settings_rewards = CORE_SETTINGS,
                        )

    if not offline_testing_mode:
        cccoin.deploy_contract()
    
    for x in xrange(3):

        blind_post, unblind_post = client_post('http://' + str(x),
                                               'The Title ' + str(x),
                                               priv,
                                               pub,
                                               )
        
        cccoin.submit_blind_action(blind_post)
        yy = cccoin.submit_unblind_action(unblind_post)

        item_id = yy['item_ids'][0]
        
        for y in xrange(x):
            blind_vote, unblind_vote = client_vote(item_id,
                                                   choice([-1, 0, 1,]),
                                                   priv,
                                                   pub,
                                                   )

            cccoin.submit_blind_action(blind_vote)
            cccoin.submit_unblind_action(unblind_vote)

    cccoin.cw.loop_once()
    cccoin.cw.loop_once()

    print '====LIST:'
    
    for c,xx in enumerate(cccoin.get_sorted_posts()['items']):
        print '==%03d:' % (c + 1)
        print json.dumps(xx, indent=4)
        

        
def test_2(via_cli = False):
    """
    Test 2.
    """
    
    cccoin = CCCoinCore(offline_testing_mode = True,
                        settings_rewards = CORE_SETTINGS,
                        )

    for x in xrange(3):
    
        blind_post = {"sig": {"sig_s": "31d1de9b700f0c5e211692a50d5b5ef4939bfa07464d9b5d62a61be7f69d47f2", 
                              "sig_r": "42d1f4e78f37b77141dd9284c6d05cde323c12e6d6020a38f951e780d5dcade8", 
                              "sig_v": 27
                              }, 
                      "payload": "{\"command\":\"blind\",\"item_type\":\"posts\",\"blind_hash\":\"5162231ccf65cee46791ffbeb18c732a41605abd73b0440bf110a9ba558d2323\",\"num_items\":1,\"nonce\":1486056332736}", 
                      "pub": "f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1"
                      }

        cccoin.submit_blind_action(blind_post)

        unblind_post = {"payload": "{\"command\":\"unblind\",\"item_type\":\"posts\",\"blind_hash\":\"5162231ccf65cee46791ffbeb18c732a41605abd73b0440bf110a9ba558d2323\",\"blind_reveal\":\"{\\\"rand\\\": \\\"cbHYj7psrXGYNEfA\\\", \\\"posts\\\": [{\\\"image_title\\\": \\\"Sky Diving%d\\\", \\\"image_url\\\": \\\"http://cdn.mediachainlabs.com/hh_1024x1024/943/943a9bdc010a0e8eb823e4e0bcac3ee1.jpg\\\"}]}\",\"nonce\":1486056333038}" % x, 
                        "sig": {"sig_s": "31d1de9b700f0c5e211692a50d5b5ef4939bfa07464d9b5d62a61be7f69d47f2", 
                                "sig_r": "42d1f4e78f37b77141dd9284c6d05cde323c12e6d6020a38f951e780d5dcade8", 
                                "sig_v": 27
                                }, 
                        "pub": "f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1"
                        }

        cccoin.submit_unblind_action(unblind_post)

    for x in xrange(3):
        blind_vote = {u'payload': u'{"command":"blind","item_type":"votes","blind_hash":"3a3282d9fcf4953837ae8de46a90b7998e15b5d6d7b0944d0879bde1983f5a91","num_items":1,"nonce":1486058848406}',
                      u'pub': u'f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1',
                      u'sig': {u'sig_r': u'53c51f498efdfff2c588b81f4cb82e3b2beb5f2469ea78f47e657d2275dc92b3',
                               u'sig_s': u'3aebfbd9b5cb1b6a68100dbe32d747f94ccf47855a960cd7dfa2f23194ee8301',
                               u'sig_v': 27},
                      }

        cccoin.submit_blind_action(blind_vote)

        unblind_vote = {"payload": "{\"command\":\"unblind\",\"item_type\":\"votes\",\"blind_hash\":\"3a3282d9fcf4953837ae8de46a90b7998e15b5d6d7b0944d0879bde1983f5a91\",\"blind_reveal\":\"{\\\"votes\\\":[{\\\"item_id\\\":\\\"f3f77c486896e44134a3\\\",\\\"direction\\\":1}],\\\"rand\\\":\\\"AY7c7uSUpLwLAF6Q\\\"}\",\"nonce\":1486058848700}", 
                        "pub": "f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1", 
                        "sig": {
                            "sig_s": "2177c47105ded1f7d70238abc63482c81039afa2e01e5d054095f982f2bc8ecf", 
                            "sig_r": "96287bd76e87fce1ef2780a943bf5811c47e82973cc802b476092d66f03a3b1a", 
                            "sig_v": 28
                        }, 
                        }
    
        cccoin.submit_unblind_action(unblind_vote)
        
    rr = cccoin.get_sorted_posts()
    
    print '========POSTS:'
    print rr
    

def test_1(via_cli = False):
    """
    Test CCCoin logging and rewards functions.
    """

    code = \
    """
    pragma solidity ^0.4.6;

    contract CCCoinToken {
        event TheLog(bytes);
        function addLog(bytes val) payable { 
            TheLog(val);
        }
    }
    """
    
    cw = ContractWrapper(code,
                         settings_confirm_states = DEFAULT_CONFIRM_STATES,
                         )
    
    cont_addr = cw.deploy()
    

    events = [{'payload_decoded': {u'num_items': 1, u'item_type': u'votes', u'blind_hash': u'59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471', u'command': u'blind', u'nonce': 1485934064014}, u'sig': {u'sig_s': u'492f15906be6bb924e7d9b9d954bc989a14c85f5c3282bb4bd23dbf2ad37c206', u'sig_r': u'abc17a3e61ed708a34a2af8bfad3270863f4ee02dd0e009e80119262087015d4', u'sig_v': 28}, u'payload': u'{"command":"blind","item_type":"votes","blind_hash":"59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471","num_items":1,"nonce":1485934064014}', u'pub': u'f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1'},
              {'payload_decoded': {u'nonce': 1485934064181, u'item_type': u'votes', u'blind_hash': u'59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471', u'blind_reveal': u'{"votes":[{"item_id":"1","direction":0}],"rand":"tLKFUfvh0McIDUhr"}', u'command': u'unblind'}, u'sig': {u'sig_s': u'7d0e0d70f1d440e86487881893e27f12192dd23549daa4dc89bb4530aee35c3b', u'sig_r': u'9f074305e710c458ee556f7c6ba236cc57869ad9348c75ce1a47094b9dbaa6dc', u'sig_v': 28}, u'payload': u'{"command":"unblind","item_type":"votes","blind_hash":"59f4132fb7d6e430c591cd14a9d1423126dca1ec3f75a3ea1ebed4d2d4454471","blind_reveal":"{\\"votes\\":[{\\"item_id\\":\\"1\\",\\"direction\\":0}],\\"rand\\":\\"tLKFUfvh0McIDUhr\\"}","nonce":1485934064181}', u'pub': u'f2e642e8a5ead4fc8bb3b8776b949e52b23317f1e6a05e99619330cca0fc6f87de28131e696ba7f9d9876d99c952e3ccceda6d3324cdfaf5452cf8ea01372dc1'},
              ]
    
    #events = ['test' + str(x) for x in xrange(3)]
    
    events = [dumps_compact(x) for x in events[-1:]]
    
    for xx in events:
        cw.send_transaction('addLog(bytes)',
                            [xx],
                            block = True,
                            gas_limit = 1000000,
                            gas_price = 100,
                            value = web3.utils.currency.to_wei(1,'ether'),
                            )
        if False:
            print ('SIZE', len(xx))
            tx = cw.c.call_with_transaction(cw.c.eth_coinbase(),
                                            cw.contract_address,
                                            'addLog(bytes)',
                                            [xx],
                                            gas = 1000000,
                                            gas_price = 100,
                                            value = web3.utils.currency.to_wei(1,'ether'),
                                            )
            receipt = cw.c.eth_getTransactionReceipt(tx) ## blocks to ensure transaction is mined
        
    def cb(msg, receipt, confirm_level):
        msg['data'] = solidity_string_decode(msg['data'])
        print ('GOT_LOG:')
        print json.dumps(msg, indent=4)
    
    #cw.events_callback = cb
    
    cc2 = CCCoinCore(cw,
                     settings_rewards = CORE_SETTINGS,
                     #offline_testing_mode = True,
                     ) 
    
    cw.events_callback = cc2.process_event
    
    logs = cw.poll_incoming()

    if False:
        print ('XXXXXXXXX')
        params = {"fromBlock": "0x01",
                  "address": cw.contract_address,
        }
        filter = str(cw.c.eth_newFilter(params))

        for xlog in cw.c.eth_getFilterLogs(filter):
            print json.dumps(xlog, indent=4)

def start_web(via_cli = False):
    """
    Web mode: Web server = Yes, Write rewards = No, Audit rewards = No.

    This mode runs a web server that users can access. Currently, writing of posts, votes and signups to the blockchain
    from this mode is allowed. Writing of rewards is disabled from this mode, so that you can run many instances of the web server
    without conflict.
    """
    print ('SETUP_CCCOIN...')
    
    the_address = get_deployed_address()

    if the_address:
        print ('USING_ALREADY_DEPLOYED', the_address)

    else:
        the_address = deploy_contract()
        print ('USING_NEWLY_DEPLOYED', the_address)

    assert the_address
        
    cw = ContractWrapper(the_address = the_address,
                         
                         settings_confirm_states = DEFAULT_CONFIRM_STATES,
                         )

    ## Must be created pre-forking, for the shared in-memory DBs:
    cccoin = CCCoinCore(contract_wrapper = cw,
                        settings_rewards = CORE_SETTINGS,
                        mode = 'web',
                        ) 
    
    cw.start_contract_thread()
    
    inner_start_web(cccoin,
                    image_proxy_path = IMAGE_PROXY_PATH,
                    )
    
    
def start_rewards():
    """
    Rewards mode: Web server = No, Write rewards = Yes, Audit rewards = No.
    
    Only run 1 instance of this witness, per community (contract instantiation.)
    
    This mode collects up events and distributes rewards on the blockchain. Currently, you must be the be owner of 
    the ethereum contract (you called `deploy_contract`) in order to distribute rewards.
    """

    the_address = get_deployed_address()
    
    cw = ContractWrapper(the_address = the_address,
                         settings_confirm_states = DEFAULT_CONFIRM_STATES,
                         )        
    
    xx = CCCoinCore(cw,
                    mode = 'rewards',
                    settings_rewards = CORE_SETTINGS,
                    )
    
    while True:
        xx.loop_once()
        sleep(0.5)

def start_audit():
    """
    Audit mode: Web server = No, Write rewards = No, Audit rewards = Yes.
    """
    cw = ContractWrapper(the_address = the_address,
                         settings_confirm_states = DEFAULT_CONFIRM_STATES,
                         )
    
    xx = CCCoinCore(mode = 'audit',
                    settings_rewards = CORE_SETTINGS,
                    )
    
    while True:
        xx.loop_once()
        sleep(0.5)

        
functions=['deploy_contract',
           'start_rewards',
           'start_audit',
           'start_web',
           'sig_helper',
           'vote_helper',
           'test_1',
           'test_2',
           'test_3',
           'test_rewards',
           ]

def main():    
    setup_main(functions,
               globals(),
               'node_main.py',
               )

if __name__ == '__main__':
    main()

