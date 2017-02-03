#!/usr/bin/env python

"""
"""


DATA_DIR = 'cccoin_conf/'
CONTRACT_ADDRESS_FN = DATA_DIR + 'cccoin_contract_address.txt'


import bitcoin as btc

from ethjsonrpc.utils import hex_to_dec, clean_hex, validate_block
from ethjsonrpc import EthJsonRpc

import ethereum.utils

import binascii

import json

from os import mkdir, listdir, makedirs, walk, rename, unlink
from os.path import exists,join,split,realpath,splitext,dirname

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from random import randint, choice
from os import urandom

from collections import Counter

######## Ethereum parts:


main_contract_code = \
"""
pragma solidity ^0.4.6;

contract CCCoin payable {
    event TheLog(bytes);
    function addLog(bytes val) { 
        TheLog(val);
    }
}
"""#.replace('payable','')

"""
Contract below implements StandardToken (https://github.com/ethereum/EIPs/issues/20) interface, in addition to:
 - Log event = vote, submit items, request tok -> lock.
 - Create user account.
 - Get user balances (tok / lock).
 - Withdraw tok.
 - Change user account owner address.
 - Change contract owner address.
 - Minting / rewards distribution (runnable only by MC, may be called multiple times per rewards cycle due to gas limits)
"""

xmain_contract_code = \
"""
pragma solidity ^0.4.0;

contract owned { 
    address owner;

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }
    function owned() { 
        owner = msg.sender; 
    }
}

contract mortal is owned {
    function kill() {
        if (msg.sender == owner) selfdestruct(owner);
    }
}

contract TokFactory is owned, mortal{ 

     event TheLog(bytes); 

     function addLog(bytes val) payable {
         TheLog(val);
     }

    mapping(address => address[]) public created;
    mapping(address => bool) public isToken; //verify without having to do a bytecode check.
    bytes public tokByteCode;
    address public verifiedToken;
    event tokenCreated(uint256 amount, address tokenAddress, address owner);
    Tok tok;

    function () { 
      throw; 
    }

    modifier noEther { 
      if (msg.value > 0) { throw; }
      _; 
    }

    modifier needTok { 
      if (address(tok) == 0x0) { throw; }
      _;
    }

    function TokFactory() {
      //upon creation of the factory, deploy a Token (parameters are meaningless) and store the bytecode provably.
      owner = msg.sender;
    }

    function getOwner() constant returns (address) { 
      return owner; 
    }

    function getTokenAddress() constant returns (address) { 
      // if (verifiedToken == 0x0) { throw; }
      return verifiedToken;
    } 

    //verifies if a contract that has been deployed is a validToken.
    //NOTE: This is a very expensive function, and should only be used in an eth_call. ~800k gas
    function verifyToken(address _tokenContract) returns (bool) {
      bytes memory fetchedTokenByteCode = codeAt(_tokenContract);

      if (fetchedTokenByteCode.length != tokByteCode.length) {
        return false; //clear mismatch
      }
      //starting iterating through it if lengths match
      for (uint i = 0; i < fetchedTokenByteCode.length; i ++) {
        if (fetchedTokenByteCode[i] != tokByteCode[i]) {
          return false;
        }
      }

      return true;
    }

    //for now, keeping this internal. Ideally there should also be a live version of this that any contract can use, lib-style.
    //retrieves the bytecode at a specific address.
    function codeAt(address _addr) internal returns (bytes o_code) {
      assembly {
          // retrieve the size of the code, this needs assembly
          let size := extcodesize(_addr)
          // allocate output byte array - this could also be done without assembly
          // by using o_code = new bytes(size)
          o_code := mload(0x40)
          // new "memory end" including padding
          mstore(0x40, add(o_code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
          // store length in memory
          mstore(o_code, size)
          // actually retrieve the code, this needs assembly
          extcodecopy(_addr, add(o_code, 0x20), 0, size)
      }
    }

    function createTok(uint256 _initialAmount, string _name, uint8 _decimals, string _symbol) onlyOwner  returns (address) {
        tok = new Tok(_initialAmount, _name, _decimals, _symbol);
        created[msg.sender].push(address(tok));
        isToken[address(tok)] = true;
        // tok.transfer(owner, _initialAmount); //the creator will own the created tokens. You must transfer them.
        verifiedToken = address(tok); 
        tokByteCode = codeAt(verifiedToken);
        tokenCreated(_initialAmount, verifiedToken, msg.sender);
        return address(tok);
    }
    function rewardToken(address _buyer, uint256 _amount)  onlyOwner returns (bool) {
      return tok.transfer(_buyer, _amount); 
  }
}

contract StandardToken is owned, mortal{

    event Transfer(address sender, address to, uint256 amount);
    event Approval(address sender, address spender, uint256 value);

    /*
     *  Data structures
     */
    struct User {
      bool initialized; 
      address userAddress; 
      bytes32 userName;
      uint256 registerDate;
      uint8 blockVoteCount;    // number of votes this block
      uint256 currentBlock; 
      uint8 totalVotes; 
      mapping (uint8 => Post) votedContent;  // mapping of each vote to post 
    }

    struct Lock {
      uint256 amount; 
      uint256 unlockDate;
    }

    struct Post {
      bool initialized; 
      address creator; 
      bytes32 title;
      bytes32 content; 
      uint256 creationDate; 
      uint8 voteCount;     // total + or - 
      address[] voters;
      mapping (address => uint8) voteResult;     // -1 = downvote , 0 = no vote,  1 = upvote 
    }


    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;
    mapping (address => Lock[]) public lockedTokens;
    mapping (address => Post[]) public posts;
    uint8 public numUsers;
    mapping (address => User) public users;
    address[] userAddress; 

    
    /*
     *  Read and write storage functions
     */
    /// @dev Transfers sender's tokens to a given address. Returns success.
    /// @param _to Address of token receiver.
    /// @param _value Number of tokens to transfer.
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Allows allowed third party to transfer tokens from one address to another. Returns success.
    /// @param _from Address from where tokens are withdrawn.
    /// @param _to Address to where tokens are sent.
    /// @param _value Number of tokens to transfer.
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    /// @dev Sets approved amount of tokens for spender. Returns success.
    /// @param _spender Address of allowed account.
    /// @param _value Number of approved tokens.
    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /*
     * Read storage functions
     */
    /// @dev Returns number of allowed tokens for given address.
    /// @param _owner Address of token owner.
    /// @param _spender Address of token spender.
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

}

contract Tok is StandardToken{ 

    address tokFactory; 

    string name; 
    uint8 decimals;
    string symbol; 

    modifier noEther { 
      if (msg.value > 0) { throw; }
      _; 
    }

    modifier controlled { 
        if (msg.sender != tokFactory) throw; 
        _;
    }
    
    function () {
        //if ether is sent to this address, send it back.
        throw;
    }
    
    function Tok(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
        ) noEther{
        tokFactory = msg.sender;
        balances[msg.sender] = _initialAmount;               // Give the TokFactory all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function getUserAddress(address _user) noEther returns (address) { 
      return users[_user].userAddress; 
    }
    function getUserName(address _user) noEther returns (bytes32) { 
      return users[_user].userName; 
    }

    function register(bytes32 _username) noEther returns (bool success) { 
      User newUser = users[msg.sender];
      newUser.userName = _username;
      newUser.userAddress = msg.sender;
      newUser.registerDate = block.timestamp;
      return true; 

    }

    function mintToken(address _target, uint256 _mintedAmount) controlled {
        balances[_target] += _mintedAmount;
        totalSupply += _mintedAmount;
        Transfer(owner, _target, _mintedAmount);
    }

    function  post(bytes32 _title, bytes32 _content) noEther{
      Post[] posts = posts[msg.sender];
      posts.push(Post({creator: msg.sender, title: _title, content: _content, creationDate: block.timestamp, voteCount: 0}));
    }

    function vote(uint8 _postID, address _creator) noEther {
           User voter = users[msg.sender];
           Post postVotedOn = posts[_creator][_postID];
           if (voter.currentBlock == block.number) {
             // uint256 requiredLock =  (1 * numVotes) ** 3) + 100);  
             // uint256 lockBalance = lockBalance(msg.sender);
             // if (lockBalance < requiredLock) { throw;     }  
           }
           else { 
            voter.blockVoteCount = 0; 
            voter.currentBlock = block.number;
            uint256 totalLock = lockBalance(msg.sender);
            if (totalLock > 100) { 

            } 
           }
    }

    function lockBalance(address lockAccount)  constant returns (uint256) { 
      Lock[] lockedList = lockedTokens[lockAccount];
      uint256 total = 0;  
      for (uint8 i = 0; i < lockedList.length; i++) { 
        total += lockedList[i].amount; 
        }
      return total;
    }
    function calculateLockPayout(uint256 _amount) internal constant controlled { 
      for (uint8 i = 0; i < numUsers; i++) { 
         address temp = userAddress[i]; 
         User user = users[temp]; 
         uint256 userLockBalance = lockBalance(temp);

      }
    }
}
"""



class ContractWrapper:
    
    def __init__(self,
                 the_code,
                 events_callback = False,
                 rpc_host = '127.0.0.1',
                 rpc_port = 9999, ## 8545,
                 confirm_states = {'PENDING':0,
                                   'BLOCKCHAIN_CONFIRMED':15,
                                   'STALE':100,
                                   },
                 final_confirm_state = 'BLOCKCHAIN_CONFIRMED',
                 contract_address = False,
                 ):
        """
        Simple contract wrapper, assists with deploying contract, sending transactions, and tracking event logs.
        
        Args:
          - `events_callback` will be called upon each state transition, according to `confirm_states`, 
             until `final_confirm_state`.
          - `contract_address` contract address, from previous `deploy()` call.
        """

        self.the_code = the_code
        
        self.loop_block_num = -1
        
        self.confirm_states = confirm_states
        self.events_callback = events_callback
        
        self.c = EthJsonRpc(rpc_host, rpc_port)

        self.pending_transactions = {}  ## {tx:callback}
        self.pending_logs = {}
        self.latest_block_num = -1

        self.latest_block_num_done = 0

        if contract_address is False:
            if exists(CONTRACT_ADDRESS_FN):
                print ('Reading contract address from file...', CONTRACT_ADDRESS_FN)
                with open(CONTRACT_ADDRESS_FN) as f:
                    d = f.read()
                print ('GOT', d)
                self.contract_address = d
            else:
                self.deploy()
        else:
            self.contract_address = contract_address

        assert self.contract_address
                    
    def deploy(self):
        print ('DEPLOYING_CONTRACT...')        
        # get contract address
        xx = self.c.eth_compileSolidity(self.the_code)
        #print ('GOT',xx)
        compiled = xx['code']
        contract_tx = self.c.create_contract(self.c.eth_coinbase(), compiled, gas=3000000)
        self.contract_address = str(self.c.get_contract_address(contract_tx))
        print ('DEPLOYED', self.contract_address)
        return self.contract_address

    def loop_once(self):
        
        if self.c.eth_syncing():
            print ('BLOCKCHAIN_STILL_SYNCING')
            return
        
        if self.events_callback is not False:
            self.poll_incoming()
        
        self.poll_outgoing()
        

    def poll_incoming(self):
        """
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_newfilter
        """
        
        self.latest_block_num = self.c.eth_blockNumber()

        for do_state in ['BLOCKCHAIN_CONFIRMED',
                         #'PENDING',
                         ]:
            
            self.latest_block_num_confirmed = max(0, self.latest_block_num - self.confirm_states[do_state])
            
            from_block = max(1,self.latest_block_num_done)
            
            to_block = self.latest_block_num_confirmed
            
            got_block = 0
            
            params = {'fromBlock': '0x01',#ethereum.utils.int_to_hex(from_block),
                      'toBlock': ethereum.utils.int_to_hex(to_block),
                      'address': self.contract_address,
                      }
            
            print ('eth_newFilter', 'do_state:', do_state, 'latest_block_num:', self.latest_block_num, 'params:', params)
            
            self.filter = str(self.c.eth_newFilter(params))
            
            print ('eth_getFilterChanges', self.filter)
            
            msgs = self.c.eth_getFilterLogs(self.filter)
            
            print ('POLL_INCOMING_GOT', len(msgs))
            
            for msg in msgs:
                
                got_block = ethereum.utils.parse_int_or_hex(msg['blockNumber'])
                
                self.events_callback(msg = msg, receipt = False, received_via = do_state)

                self.latest_block_num_done = max(0, max(self.latest_block_num_done, got_block - 1))
        
            
    def send_transaction(self,
                         foo,
                         args,
                         callback = False,
                         send_from = False,
                         block = False,
                         gas_limit = False,
                         gas_price = 100,
                         value = 100000000000,
                         ):
        """
        1) Attempt to send transaction.
        2) Get first confirmation via transaction receipt.
        3) Re-check receipt again after N blocks pass.
        
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sendtransaction
        """
        print ('SEND_TRANSACTION:', foo, args)

        if send_from is False:
            send_from = self.c.eth_coinbase()
        
        send_to = self.contract_address 

        print ('====TRANSACTION')
        print ('send_from', send_from)
        print ('send_to', send_to)
        print ('foo', foo)
        print ('args', args)
        #print ('gas', gas_limit)

        gas_limit = 1000000
        gas_price = 100
        value = web3.utils.currency.to_wei(1,'ether')
                            
        tx = self.c.call_with_transaction(send_from,
                                          send_to,
                                          foo,
                                          args,
                                          gas = gas_limit,
                                          gas_price = gas_price,
                                          value = value,
                                          )
        
        if block:
            receipt = self.c.eth_getTransactionReceipt(tx) ## blocks to ensure transaction is mined
            #print ('GOT_RECEIPT', receipt)
            #if receipt['blockNumber']:
            #    self.latest_block_num = max(ethereum.utils.parse_int_or_hex(receipt['blockNumber']), self.latest_block_num)
        else:
            self.pending_transactions[tx] = (callback, self.latest_block_num)

        self.latest_block_num = self.c.eth_blockNumber()
        
        return tx

    def poll_outgoing(self):
        """
        Confirm outgoing transactions.
        """
        for tx, (callback, attempt_block_num) in self.pending_transactions.items():

            ## Compare against the block_number where it attempted to be included:
            
            if (attempt_block_num <= self.latest_block_num - self.confirm_states['BLOCKCHAIN_CONFIRMED']):
                continue
            
            receipt = self.c.eth_getTransactionReceipt(tx)
            
            if receipt['blockNumber']:
                actual_block_number = ethereum.utils.parse_int_or_hex(receipt['blockNumber'])
            else:
                ## TODO: wasn't confirmed after a long time.
                actual_block_number = False
            
            ## Now compare against the block_number where it was actually included:
            
            if (actual_block_number is not False) and (actual_block_number >= self.latest_block_num - self.confirm_states['BLOCKCHAIN_CONFIRMED']):
                if callback is not False:
                    callback(receipt)
                del self.pending_transactions[tx]
    
    def read_transaction(self, foo, value):
        rr = self.c.call(self.c.eth_coinbase(), self.contract_address, foo, value)
        return rr

    
    def sign(self, user_address, value):
        rr = self.c.eth_sign(self.c.eth_coinbase(), self.contract_address, user_address, value)
        return rr
        


def deploy_contract(via_cli = False):
    """
    Deploy new instance of this dApp to the blockchain.
    """
    
    fn = CONTRACT_ADDRESS_FN
    
    assert not exists(fn), ('File with contract address already exists:', fn)
    
    if not exists(DATA_DIR):
        mkdir(DATA_DIR)
    
    cont = ContractWrapper(main_contract_code)
    
    addr = cont.deploy()
    
    with open(fn) as f:
        f.write(addr)
    
    print ('DONE', addr, '->', fn)

############### Utils:
    
def dumps_compact(h):
    #print ('dumps_compact',h)
    return json.dumps(h, separators=(',', ':'), sort_keys=True)

def loads_compact(d):
    #print ('loads_compact',d)
    r = json.loads(d)#, separators=(',', ':'))
    return r


from Crypto.Hash import keccak

sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()

def web3_sha3(seed):
    return '0x' + (sha3_256(str(seed)).encode('hex'))

#assert web3_sha3('').encode('hex') == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
assert web3_sha3('') == '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

def consistent_hash(h):
    ## Not using `dumps_compact()`, in case we want to change that later.
    return web3_sha3(json.dumps(h, separators=(',', ':'), sort_keys=True))

import multiprocessing

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


############## Simple in-memory data structures, to start:

RUN_ID = get_random_bytes(32).encode('hex')

TRACKING_NUM = SharedCounter()

manager = multiprocessing.Manager()

LATEST_NONCE = manager.dict() ## {api_key:nonce}

CHALLENGES_DB = manager.dict() ## {'public_key':challenge}

SEEN_USERS_DB = manager.dict() ## {'public_key':1}

TEST_MODE = False

## Quick in-memory DB:

all_dbs = {}

for which in ['BLOCKCHAIN_CONFIRMED',
              'BLOCKCHAIN_PENDING',
              'DIRECT',
              ]:
    all_dbs[which] = {'votes':manager.dict(), ## {(pub_key, item_id):direction},
                      'flags':manager.dict(), ## {(pub_key, item_id):direction},
                      'posts':manager.dict(), ## {post_id:post}
                      'scores':manager.dict(), ## {item_id:score}
                      }

############### CCCoin Core API:


import struct
import binascii

def solidity_string_decode(ss):
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


import web3


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
    
        
class CCCoinAPI:
    def _validate_api_call(self):
        pass
    
    def __init__(self, mode = 'web', offline_mode = True, the_code = False):
        
        assert mode in ['web', 'witness', 'audit']
        
        self.mode = mode

        self.offline_mode = offline_mode
        
        if not offline_mode:
            self.cw = ContractWrapper(the_code,
                                      events_callback = self.process_event, #self.rewards_and_auditing_callback)
                                      )

        ## TOK rewards settings:
        
        self.REWARDS_CURATION = 90.0    ## Voting rewards
        self.REWARDS_POSTING = 10.0     ## Posting rewards
        self.REWARDS_WITNESS = 10.0     ## Witness rewards
        self.REWARDS_SPONSOR = 10.0     ## Web nodes that cover basic GAS / TOK for users on their node.
        
        self.REWARDS_FREQUENCY = 140    ## 140 blocks = 7 hours
        
        self.MAX_UNBLIND_DELAY = 20     ## Maximum number of blocks allowed between submitting a blind vote and unblinding.
        
        self.MAX_GAS_DEFAULT = 10000    ## Default max gas fee per contract call.
        self.MAX_GAS_REWARDS = 10000    ## Max gas for rewards function.
        
        self.NEW_USER_LOCK_DONATION = 1 ## Free LOCK given to new users that signup through this node.

        self.LOCK_INTEREST_RATE = 1.0    ## Annual inteest rate paid to LOCK holders
        
        ##
        
        self.all_users = {}
        
        ###
        
        self.latest_block_num = -1
        
        self.posts_by_post_id = {}        ## {post_id:post}
        self.post_ids_by_block_num = {}   ## {block_num:[post_id,...]}
        self.votes_lookup = {}            ## {(user_id, item_id): direction}
        
        self.blind_lookup = {}            ## {block_number:[block_hash, ...]}
        self.blind_lookup_rev = {}        ## {blind_hash:blind_dict}

        self.old_actions = {}             ## {block_num:[action,...]}
        self.old_lock_balances = {}       ## {block_num:}
        
        self.block_info = {}              ## {block_number:{info}}
        
        self.balances_tok = {}            ## {user_id:amount}
        self.balances_lock = {}           ## {user_id:amount}
        
        self.voting_bandwidth = {}        ## {user_id:amount}
        self.posting_bandwidth = {}       ## {user_id:amount}

        self.num_votes = Counter()        ## {(user_id,block_num):num}

        self.prev_block_number = -1

    
    def cache_unblind(self, creator_pub, payload_decoded, received_via):
        """
        Cache actions in local indexes.
        
        Accepts messages from any of:
        1) New from Web API
        2) New Blockchain
        3) Old from Blockchain that were previously seen via Web API.
        """
    
    def process_event(self,
                      msg,
                      received_via,
                      receipt = False,
                      do_verify = True,
                      ):
        """
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

        if received_via == 'DIRECT':

            payload_decoded = loads_compact(msg['payload'])
            msg_data = msg
            msg = {'data':msg}
            
        elif received_via in ['BLOCKCHAIN_CONFIRMED', 'BLOCKCHAIN_PENDING']:
            
            msg['data'] = solidity_string_decode(msg['data'])
            msg['blockNumber'] = ethereum.utils.parse_int_or_hex(msg['blockNumber'])
            msg["logIndex"] = ethereum.utils.parse_int_or_hex(msg['logIndex'])
            msg["transactionIndex"] = ethereum.utils.parse_int_or_hex(msg['transactionIndex'])
            msg_data = loads_compact(msg['data'])
            payload_decoded = loads_compact(msg_data['payload'])
            
        else:
            assert False, repr(received_via)
        
        print ('====PROCESS_EVENT:', received_via)
        print json.dumps(msg, indent=4)


        the_db = all_dbs[received_via]
                
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
        
        
        if payload_decoded['command'] == 'balance':
            
            ## Record balance updates:
            
            assert False, 'TODO - confirm that log was written by contract.'
            
            self.balances_tok[payload['addr']] += payload['amount']
            
        elif payload_decoded['command'] == 'blind':
            
            if received_via == 'BLOCKCHAIN_CONFIRMED':
                
                ## Just save earliest blinding blockNumber for later:
                ## TODO: save token balance at this time.
                
                if msg['blockNumber'] not in self.blind_lookup:
                    self.blind_lookup[msg['blockNumber']] = set()
                self.blind_lookup[msg['blockNumber']].add(payload_decoded['blind_hash'])
                
                if payload_decoded['blind_hash'] not in self.blind_lookup_rev:
                    self.blind_lookup_rev[payload_decoded['blind_hash']] = msg['blockNumber']
        
        elif payload_decoded['command'] == 'unblind':

            print ('====COMMAND_UNBLIND:', payload_decoded)
            
            creator_pub = msg_data['pub']
            
            #creator_address = btc.pubtoaddr(msg_data['pub'])

            creator_address = msg_data['pub'][:20]
            
            payload_inner = loads_compact(payload_decoded['blind_reveal'])


            ## Check that reveal matches supposed blind hash:

            hsh = btc.sha256(payload_decoded['blind_reveal'].encode('utf8'))

            hash_fail = False
            
            if payload_decoded['blind_hash'] != hsh:
                
                print ('HASH_MISMATCH', payload_decoded['blind_hash'], hsh)

                hash_fail = True

                payload_decoded['blind_hash'] = hsh
            
            if received_via == 'BLOCKCHAIN_CONFIRMED':

                if payload_decoded['blind_hash'] not in self.blind_lookup_rev:
                    
                    ## If blind was never seen, just credit to current block:
                    
                    self.blind_lookup_rev[payload_decoded['blind_hash']] = msg['blockNumber']
                    
                    if msg['blockNumber'] not in self.blind_lookup:
                        self.blind_lookup[msg['blockNumber']] = set()
                    
                    self.blind_lookup[msg['blockNumber']].add(payload_decoded['blind_hash'])

                
                    

                    
                    
            print ('PAYLOAD_INNER:', payload_inner)
            
            if payload_decoded['item_type'] == 'posts':
                
                print ('====COMMAND_UNBLIND_POSTS:', payload_inner)
                
                #### FROM PENDING:
                
                #assert False, 'WIP'
                
                ## Cache post:
                
                for post in payload_inner['posts']:
                    
                    ## Update local caches:
                    
                    post_id = create_long_id(creator_pub, dumps_compact(post))
                    
                    item_ids.append(post_id)
                    
                    if post_id not in self.posts_by_post_id:                    

                        post['post_id'] = post_id
                        post['status'] = {'confirmed':False,
                                          'created_time':int(time()),
                                          'created_block_num':False, ## Filled in when confirmed via blockchain
                                          #'score':1,
                                          #'score_weighted':1,
                                          'creator_addr':creator_address,
                                          }
                        
                        self.posts_by_post_id[post_id] = post
                        
                        if received_via == 'BLOCKCHAIN_CONFIRMED':
                            
                            if msg['blockNumber'] not in self.post_ids_by_block_num:
                                self.post_ids_by_block_num[msg['blockNumber']] = []
                            self.post_ids_by_block_num[msg['blockNumber']].append(post['post_id'])

                            ## TODO - best way to delete posts?:
                            
                            if post.get('deleted') and (post_id in self.posts_by_post_id):
                                self.posts_by_post_id[post_id]['status']['deleted'] = True
            
            elif payload_decoded['item_type'] == 'votes':
                
                for vote in payload_inner['votes']:

                    #print ('!!!INCREMENT', vote['item_id'], the_db['scores'].get(vote['item_id']))
                    
                    the_db['scores'][vote['item_id']] = the_db['scores'].get(vote['item_id'], 0) + vote['direction'] ## TODO - Not thread safe.
                    
                    if vote['direction'] in [1, -1]:
                        the_db['votes'][(creator_pub, vote['item_id'])] = vote['direction']
                    
                    elif vote['direction'] == 0:
                        try: del the_db['votes'][(creator_pub, vote['item_id'])]
                        except: pass
                        
                    elif vote['direction'] == 2:
                        the_db['flags'][(creator_pub, vote['item_id'])] = vote['direction']
                        
                    elif vote['direction'] == -2:
                        try: del the_db['flags'][(creator_pub, vote['item_id'])]
                        except: pass
                    
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
        

        ## Block rewards, for sufficiently old actions:
        
        if (received_via == 'BLOCKCHAIN_CONFIRMED') and False: ## Received via blockchain.
            if (msg['blockNumber'] > self.prev_block_number) and (msg['blockNumber'] % 700 == 699):
                pass

            ### START REWARDS
            block_number = ethereum.utils.parse_int_or_hex(msg['blockNumber'])
            
            ## REWARDS:
            
            if (msg['blockNumber'] > self.latest_block_number):
                
                ## GOT NEW BLOCK:

                self.latest_block_number = max(block_number, self.latest_block_number)
                
                ## Mint TOK rewards for the old block, upon each block update:
                
                doing_block_id = block_number - (self.MAX_UNBLIND_DELAY + 1)
                
                total_lock_this_round = self.total_lock_at_block.get(doing_block_id, 0.0)
                
                for sig, (voter_id, item_id, voter_lock) in self.unblinded_votes_at_block.get(doing_block_id, {}).iteritems():

                    item_poster_id = self.poster_ids[item_id]
                    
                    if item_id not in self.new_voters_for_item:
                        self.new_voters_for_item[item_id] = set()
                    self.new_voters_for_item[item_id].add(voter_id)
                    
                    reward_per_voter = self.REWARDS_CURATION * (voter_lock / total_lock_this_item) * (total_lock_this_item / total_lock_this_round) / len(self.old_voters_for_item[item_id])
                    
                    reward_poster = self.REWARDS_POSTING * (total_lock_this_item / total_lock_this_round)
                    
                    for old_voter_id in self.old_voters_for_item[item_id]:

                        ## Curator rewards:
                        self.new_rewards[old_voter_id] = self.new_rewards.get(old_voter_id, 0.0) + reward_per_voter

                        ## Sponsor rewards for curation:
                        if old_voter_id in self.sponsors:
                            self.new_rewards[self.sponsors[old_voter_id]] = self.new_rewards.get(self.sponsors[old_voter_id], 0.0) +  (self.REWARDS_SPONSOR / self.REWARDS_CURATION)
                        
                    self.new_rewards[item_poster_id] = self.new_rewards.get(item_poster_id, 0.0) + reward_poster
                
                ## Occasionally distribute rewards:

                if (block_number % self.REWARDS_FREQUENCY) == 0:

                    assert confirm_level == 'CONFIRMED', confirm_level
                    
                    if self.mode == 'audit':

                        ## TODO - Wait a little longer, then check that previous batch paid out correctly.
                        
                        pass
                    
                    elif self.mode == 'witness':
                        
                        rr = dumps_compact({'t':'mint', 'rewards':self.new_rewards})

                        tx = self.cw.send_transaction('addLog(bytes)',
                                                      [rr],
                                                      gas_limit = self.MAX_GAS_DEFAULT,
                                                      )

                        xx = self.new_rewards.items()

                        tx = self.cw.send_transaction('mintTok(bytes)',
                                                      [[x for x,y in xx],
                                                       [y for x,y in xx],
                                                      ],
                                                      gas_limit = self.MAX_GAS_REWARDS,
                                                      )
                        self.new_rewards.clear()
                
                ## Cleanup:
                
                if doing_block_id in self.unblinded_votes_at_block:
                    del self.unblinded_votes_at_block[doing_block_id]

                for item_id,voters in self.new_voters_for_item.iteritems():
                    
                    if item_id not in self.old_voters_for_item:
                        self.old_voters_for_item[item_id] = set()
                    
                    self.old_voters_for_item[item_id].update(voters)
                    
                self.new_voters_for_item.clear()

            ### END REWARDS
            
            #for xnum in xrange(last_block_rewarded,
            #                   latest_block_ready,
            #                   ):
            #    pass

            if not self.offline_mode:
                self.prev_block_number = msg['blockNumber']

        return {'item_ids':item_ids}
        
    def get_current_tok_per_lock(self,
                                 genesis_tm,
                                 current_tm,
                                 start_amount = 1.0,
                                 ):
        """
        Returns current TOK/LOCK exchange rate, based on seconds since contract genesis and annual lock interest rate.
        """
        
        rr = start_amount * ((1.0 + self.LOCK_INTEREST_RATE) ** ((current_tm - genesis_tm) / 31557600.0))
        
        return rr
            
        
    def deploy_contract(self,):
        """
        Create new instance of dApp on blockchain.
        """

        assert not self.offline_mode
        
        self.cw.deploy()
    
        
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
        
        tracking_id = RUN_ID + '|' + str(TRACKING_NUM.increment())
        
        ## Sanity checks:
        
        #self.cache_blind(msg_data['pub'], blind_data, 'DIRECT')

        #assert blind_data['sig']
        #assert blind_data['pub']
        #json.loads(blind_data['payload'])
        
        self.process_event(blind_data,
                           received_via = 'DIRECT',
                           do_verify = False,
                           )
        
        if not self.offline_mode:
            
            dd = dumps_compact(blind_data)
            
            tx = self.cw.send_transaction('addLog(bytes)',
                                          [dd],
                                          #send_from = user_id,
                                          gas_limit = self.MAX_GAS_DEFAULT,
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
        
        print ('START_UNBLIND_ACTION')
        
        tracking_id = RUN_ID + '|' + str(TRACKING_NUM.increment())
        
        #payload_decoded = json.loads(msg_data['payload'])
        
        #payload_inner = json.loads(payload['blind_reveal'])
        
        #print ('GOT_INNER', payload_inner)
        
        #item_ids = self.cache_unblind(msg_data['pub'], payload_decoded, 'DIRECT')
        
        item_ids = self.process_event(msg_data,
                                      received_via = 'DIRECT',
                                      do_verify = False,
                                     )['item_ids']
        
        #print ('CACHED_VOTES', dict(all_dbs['DIRECT']['votes']))
        
        if not self.offline_mode:
            ## Send to blockchain:
            
            rr = dumps_compact(msg_data)
        
            tx = self.cw.send_transaction('addLog(bytes)',
                                          [rr],
                                          #send_from = user_id,
                                          gas_limit = self.MAX_GAS_DEFAULT,
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
        tx = self.cw.send_transaction('lockupTok(bytes)',
                                      [rr],
                                      gas_limit = self.MAX_GAS_DEFAULT,
                                      )

    def get_balances(self,
                     user_id,
                     ):
        xx = self.cw.read_transaction('balanceOf(address)',
                                      [rr],
                                      gas_limit = self.MAX_GAS_DEFAULT,
                                      )
        rr = loads_compact(xx['data'])
        return rr

    def withdraw_lock(self,):
        tx = self.cw.send_transaction('withdrawTok(bytes)',
                                      [rr],
                                      gas_limit = self.MAX_GAS_DEFAULT,
                                      )
        
    def get_sorted_posts(self,
                         offset = 0,
                         increment = 50,
                         sort_by = False,
                         filter_users = False,
                         filter_ids = False,
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
            for xx in self.posts_by_post_id.itervalues():
                if xx['status']['creator_addr'] in filter_users:
                    rr.append(xx)
                    
        elif filter_ids:
            rr = []
            for xx in filter_ids:
                rr.append(self.posts_by_post_id.get(xx))
        
        else:
            rr = self.posts_by_post_id.values()
        
        ## Use highest score from any consensus state:
        
        for via in ['BLOCKCHAIN_CONFIRMED', 'DIRECT']:
            the_db = all_dbs[via]
            for post in rr:
                post['status']['score'] = max(the_db['scores'].get(post['post_id'], 0) + 1, post['status'].get('score', 1))

        ## Sort:
        
        rr = list(sorted([(x['status'][sort_by],x) for x in rr], reverse=True))
        rr = rr[offset:offset + increment]
        rr = [y for x,y in rr]
        
        rrr = {'success':True, 'items':rr, 'sort':sort_by}

        print 'GOT', rrr
        
        return rrr

    def get_user_leaderboard(self,
                             offset = 0,
                             increment = 50,
                             ):
        """
        Note: Leaderboard only updated when rewards are re-computed.
        """
        
        the_db = all_dbs['BLOCKCHAIN_CONFIRMED']
        
        rr = [(x['score'], x) for x in self.all_users.values()]
        rr = [y for x,y in rr]
        rr = rr[offset:offset + increment]
        
        rrr = {'success':True, 'users':rr}
        
        return rrr

        
        

def trend_detection(input_gen,
                    window_size = 7,
                    prev_window_multiple = 1,
                    empty_val_2 = 1,
                    input_is_absolutes = False, ## otherwise, must convert to differences
                    do_ttl = False,
                    ttl_halflife_steps = 1,
                    ):
    """
    Basic in-memory KL-divergence based trend detection, with some helpers.
    """
    
    from math import log
    from sys import maxint
    
    tot_window_size = window_size + window_size * prev_window_multiple
    
    all_ids = set()
    windows = {}        ## {'product_id':[1,2,3,4]}

    the_prev = {}       ## {item_id:123}
    the_prev_step = {}  ## {item_id:step}
    
    max_score = {}      ## {item_id:score}
    max_score_time = {} ## {item_id:step_num}
    
    first_seen = {}     ## {item_id:step_num}
    
    output = []
    
    for c,hh in enumerate(input_gen):

        output_lst = []
        
        #step_num = hh['step']
        
        ## For seen items:
        for item_id,value in hh['values'].iteritems():
            
            if item_id not in first_seen:
                first_seen[item_id] = c
                        
            all_ids.add(item_id)

            if item_id not in windows:
                windows[item_id] = [0] * tot_window_size

            if item_id not in the_prev:
                the_prev[item_id] = value
                the_prev_step[item_id] = c - 1
                
            if input_is_absolutes:
                
                nn = (value - the_prev[item_id]) / float(c - the_prev_step[item_id])
                
                windows[item_id].append(nn)
                                
            else:
                windows[item_id].append(value)
            
            windows[item_id] = windows[item_id][-tot_window_size:]
            
            the_prev[item_id] = value
            the_prev_step[item_id] = c

        # Fill in for unseen items:
        for item_id in all_ids.difference(hh['values'].keys()):
            windows[item_id].append(0)
            
            windows[item_id] = windows[item_id][-tot_window_size:]

        if c < tot_window_size:
            continue

        
        ## Calculate on windows:
        for item_id,window in windows.iteritems():

            window = [max(empty_val_2,x) for x in window]
            
            cur_win = window[-window_size:]
            prev_win = window[:-window_size]
            
            cur = sum(cur_win) / float(window_size)
            prev = sum(prev_win) / float(window_size * prev_window_multiple)  #todo - seen for first time?
            
            if len([1 for x in prev_win if x > empty_val_2]) < window_size:
                #ignore if too many missing
                score = 0
            else:
                score = prev * log( cur / prev )
            
            prev_score = max_score.get(item_id, -maxint)
            
            if score > prev_score:
                max_score_time[item_id] = c
                
            max_score[item_id] = max(prev_score, score)

            #Sd(h, t) = SM(h) * (0.5)^((t - tmax)/half-life)
            if do_ttl:
                score = max_score[item_id] * (0.5 ** ((c - max_score_time[item_id])/float(ttl_halflife_steps)))

            output_lst.append((score,item_id,window))
            
        output_lst.sort(reverse=True)
        output.append(output_lst)

    return output

def test_trend_detection():
    trend_detection(input_gen = [{'values':{'a':5,'b':2,}},
                                 {'values':{'a':7,'b':2,}},
                                 {'values':{'a':9,'b':2,}},
                                 {'values':{'a':11,'b':4,}},
                                 {'values':{'a':13,'b':5,}},
                                 {'values':{'a':16,'b':6,'c':1,}},
                                 {'values':{'a':17,'b':7,'c':1,'d':1}},
                                 ],
                    window_size = 2,
                    prev_window_multiple = 1,
                    input_is_absolutes = True,
                    do_ttl = True,
                    )


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
                ):
    return client_create_blind({'posts':[{'image_url':image_url,
	                                  'image_title':image_title,
                                          }],
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
    

def test_3(via_cli = False):
    """
    Test 3.
    """
    offline_mode = False

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
    
    cccoin = CCCoinAPI(offline_mode = offline_mode,
                       the_code = code,
                       )

    if not offline_mode:
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
    
    cccoin = CCCoinAPI(offline_mode = True)

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
    
    cw = ContractWrapper(code)
    
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
                            gas = 1000000,
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
    
    #cc2 = CCCoin2()
    
    cc2 = CCCoinAPI(offline_mode = True)
    
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

    
##
#### Generic helper functions for web server:
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

    
def raw_input_enter():
    print 'PRESS ENTER...'
    raw_input()


def ellipsis_cut(s,
                 n=60,
                 ):
    s=unicode(s)
    if len(s)>n+1:
        return s[:n].rstrip()+u"..."
    else:
        return s


def shell_source(fn_glob,
                 allow_unset = False,
                 ):
    """
    Source bash variables from file. Input filename can use globbing patterns.
    
    Returns changed vars.
    """
    import os
    from os.path import expanduser
    from glob import glob
    from subprocess import check_output
    from pipes import quote
    
    orig = set(os.environ.items())
    
    for fn in glob(fn_glob):
        
        fn = expanduser(fn)
        
        print ('SOURCING',fn)
        
        rr = check_output("source %s; env -0" % quote(fn),
                          shell = True,
                          executable = "/bin/bash",
                          )
        
        env = dict(line.split('=',1) for line in rr.split('\0'))
        
        changed = [x for x in env.items() if x not in orig]
        
        print ('CHANGED',fn,changed)

        if allow_unset:
            os.environ.clear()
        
        os.environ.update(env)
        print env
    
    all_changed = [x for x in os.environ.items() if x not in orig]
    return all_changed
    

def terminal_size():
    """
    Get terminal size.
    """
    h, w, hp, wp = struct.unpack('HHHH',fcntl.ioctl(0,
                                                    termios.TIOCGWINSZ,
                                                    struct.pack('HHHH', 0, 0, 0, 0),
                                                    ))
    return w, h

def space_pad(s,
              n=20,
              center=False,
              ch = '.'
              ):
    if center:
        return space_pad_center(s,n,ch)    
    s = unicode(s)
    #assert len(s) <= n,(n,s)
    return s + (ch * max(0,n-len(s)))

def usage(functions,
          glb,
          entry_point_name = False,
          ):
    """
    Print usage of all passed functions.
    """
    try:
        tw,th = terminal_size()
    except:
        tw,th = 80,40
                   
    print
    
    print 'USAGE:',(entry_point_name or ('python ' + sys.argv[0])) ,'<function_name>'
        
    print
    print 'Available Functions:'
    
    for f in functions:
        ff = glb[f]
        
        dd = (ff.__doc__ or '').strip() or 'NO_DOCSTRING'
        if '\n' in dd:
            dd = dd[:dd.index('\n')].strip()

        ee = space_pad(f,ch='.',n=40)
        print ee,
        print ellipsis_cut(dd, max(0,tw - len(ee) - 5))
    
    sys.exit(1)

    
def set_console_title(title):
    """
    Set console title.
    """
    try:
        title = title.replace("'",' ').replace('"',' ').replace('\\',' ')
        cmd = "printf '\033k%s\033\\'" % title
        system(cmd)
    except:
        pass

import sys
from os import system

def setup_main(functions,
               glb,
               entry_point_name = False,
               ):
    """
    Helper for invoking functions from command-line.
    """
        
    if len(sys.argv) < 2:
        usage(functions,
              glb,
              entry_point_name = entry_point_name,
              )
        return

    f=sys.argv[1]
    
    if f not in functions:
        print 'FUNCTION NOT FOUND:',f
        usage(functions,
              glb,
              entry_point_name = entry_point_name,
              )
        return

    title = (entry_point_name or sys.argv[0]) + ' '+ f
    
    set_console_title(title)
    
    print 'STARTING ',f + '()'

    ff=glb[f]

    ff(via_cli = True) ## New: make it easier for the functions to have dual CLI / API use.


##
### Web frontend:
##


import json
import ujson
import tornado.ioloop
import tornado.web
from time import time
from tornadoes import ESConnection

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

############## Authentication:

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
    

def get_session(self,
                extend = True,
                ):

    ## Track some basic metrics:
    
    referer=self.request.headers.get('Referer','')
    orig_referer=self.get_secure_cookie('orig_referer')
    
    if not orig_referer:
        self.set_secure_cookie('orig_referer',
                               str(referer),
                               )
    
        orig_page=self.get_secure_cookie('orig_page')
        if not orig_page:
            self.set_secure_cookie('orig_page',
                                   str(self.request.uri),
                                   )
        
        orig_time=self.get_secure_cookie('orig_time')
        if not orig_time:
            self.set_secure_cookie('orig_time',
                                   str(time()),
                                   )
        
    ## Check auth:
    
    r = self.get_secure_cookie('auth')#,False
    
    print ('get_session() AUTH',repr(r))
    
    if not r:
        self.set_secure_cookie('auth','false')
        return False
    
    session = loads(r)
    
    if not session:
        self.set_secure_cookie('auth','false')
        return False
    
    return session


def validate_api_call(post_data,
                      user_key,
                      secret_key,
                      sig,
                      ):
    """
    Shared-secret. HMAC authenticated calls, with nonce.
    """

    sig_expected = hmac.new(str(secret_key), str(post_data), hashlib.sha512).hexdigest()
    
    if sig != sig_expected:
        print ('BAD SIGNATURE', 'user_key:', user_key)
        return (False, 'BAD_SIGNATURE')
    
    rq = json.loads(post_data)
    
    if (user_key in LATEST_NONCE) and (rq['nonce'] <= LATEST_NONCE[user_key]):
        print ('OUTDATED NONCE')
        return (False, 'OUTDATED NONCE')

    LATEST_NONCE[user_key] = rq['nonce']
    
    return (True, '')


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
                
                if (hh['pub'] in LATEST_NONCE) and ('nonce' in hh['payload_decoded'])and (hh['payload_decoded']['nonce'] <= LATEST_NONCE[hh['pub']]):
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


############## Web core:


class Application(tornado.web.Application):
    def __init__(self,
                 ):
        
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
                    ]
        
        settings = {'template_path':join(dirname(__file__), 'templates_cccoin'),
                    'static_path':join(dirname(__file__), 'static_cccoin'),
                    'xsrf_cookies':False,
                    'cookie_secret':'1234',
                    }
        
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    
    def __init__(self, application, request, **kwargs):
        RequestHandler.__init__(self, application, request, **kwargs)
        
        self._current_user_read = False
        self._current_user_write = False
        
        self.loader = tornado.template.Loader('templates_cccoin/')

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
        if not hasattr(self.application,'cccoin'):
            self.application.cccoin = CCCoinAPI(mode = 'web', the_code = main_contract_code)
        return self.application.cccoin
        
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
        kwargs['all_dbs'] = all_dbs
        kwargs['time'] = time
        
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
        
        
        the_items = self.cccoin.get_sorted_posts(filter_users = filter_users,
                                                 filter_ids = filter_ids,
                                                 sort_by = sort_by,
                                                 offset = offset,
                                                 increment = 1000,
                                                 )
        
        num_items = len(the_items['items'])
        
        print ('the_items', the_items)
        
        self.render_template('offchain_frontend.html',locals())
        



class handle_login_1(BaseHandler):
    #@check_auth(auth = False)
    @tornado.gen.coroutine
    def post(self):

        hh = json.loads(self.request.body)

        the_pub = hh['the_pub']
        
        challenge = CHALLENGES_DB.get(the_pub, False)
        
        if challenge is False:
            challenge = binascii.hexlify(urandom(16))
            CHALLENGES_DB[the_pub] = challenge

        self.write_json({'challenge':challenge})


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
        
        challenge = CHALLENGES_DB.get(the_pub, False)
        
        if challenge is False:
            print ('LOGIN_2: ERROR UNKNOWN CHALLENGE', challenge)
            self.write_json({'success':False,
                             'error':'UNKNOWN_OR_EXPIRED_CHALLENGE',
                             })
            return
        
        print 'GOT=============='
        print json.dumps(hh, indent=4)
        print '================='
        
        is_success = btc.ecdsa_raw_verify(btc.sha256(challenge.encode('utf8')),
                                          (hh['sig']['sig_v'],
                                           btc.decode(hh['sig']['sig_r'],16),
                                           btc.decode(hh['sig']['sig_s'],16)),
                                          the_pub,
                                          )
        
        print ('LOGIN_2_RESULT is_success:', is_success)
        
        self.set_secure_cookie('auth', json.dumps({'created':int(time()),
                                                   'pub':the_pub,
                                                   }))

        is_new = SEEN_USERS_DB.get(the_pub, False)
        SEEN_USERS_DB[the_pub] = True
        
        self.write_json({'success':is_success,
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
        

def web(port = 50000,
        via_cli = False,
        ):
    """
    Web mode: Web server = Yes, Write rewards = No, Audit rewards = No.

    This mode runs a web server that users can access. Currently, writing of posts, votes and signups to the blockchain
    from this mode is allowed. Writing of rewards is disabled from this mode, so that you can run many instances of the web server
    without conflict.
    """
    
    print ('BINDING',port)
    
    try:
        tornado.options.parse_command_line()
        http_server = HTTPServer(Application(),
                                 xheaders=True,
                                 )
        http_server.bind(port)
        http_server.start(1) # Forks multiple sub-processes
        tornado.ioloop.IOLoop.instance().set_blocking_log_threshold(0.5)
        IOLoop.instance().start()
        
    except KeyboardInterrupt:
        print 'Exit'
    
    print ('WEB_STARTED')


def witness():
    """
    Witness mode: Web server = No, Write rewards = Yes, Audit rewards = No.
    
    Only run 1 instance of this witness, per community (contract instantiation.)
    
    This mode collects up events and distributes rewards on the blockchain. Currently, you must be the be owner of 
    the ethereum contract (you called `deploy_contract`) in order to distribute rewards.
    """
    
    xx = CCCoinAPI(mode = 'witness')
    
    while True:
        xx.loop_once()
        sleep(0.5)

def audit():
    """
    Audit mode: Web server = No, Write rewards = No, Audit rewards = Yes.
    """
    xx = CCCoinAPI(mode = 'audit')
    
    while True:
        xx.loop_once()
        sleep(0.5)

        
functions=['deploy_contract',
           'witness',
           'audit',
           'web',
           'sig_helper',
           'vote_helper',
           'test_1',
           'test_2',
           'test_3',
           ]

def main():    
    setup_main(functions,
               globals(),
               'offchain.py',
               )

if __name__ == '__main__':
    main()

