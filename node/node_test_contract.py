#!/usr/bin/env python

"""
"""

from node_contract import ContractWrapper, test_contract_wrapper

import bitcoin as btc

from time import time, sleep

##
#### Utils:
##

def get_lang_version():
    minimal_code = \
    """
    pragma solidity ^0.4.6;
    contract CCCoin {
        event MainLog(bytes);
        function addLog(bytes val) { 
            MainLog(val);
        }
    }
    """
    from ethjsonrpc import EthJsonRpc
    c = EthJsonRpc('127.0.0.1', 9999)
    c.eth_compileSolidity(minimal_code)['info']['compilerVersion']


def test_getters():
    minimal_code = \
    """
    pragma solidity ^0.4.6;
    contract Test {
      uint256 public the_var = 5;
    }
    """
    from ethjsonrpc import EthJsonRpc
    c = EthJsonRpc('127.0.0.1', 9999)
    xx = c.eth_compileSolidity(minimal_code)
    compiled = xx['code']
    contract_tx = c.create_contract(c.eth_coinbase(),
                                         compiled,
                                         gas=3000000,
                                         )
    contract_address = str(c.get_contract_address(contract_tx))
    
    rr = c.call(address = contract_address,
                sig = 'the_var()',
                args = [],
                result_types = ['uint256'],
                )
    
    assert rr[0] == 5, rr
    print ('PASSED')
    

def setup_contract(set_name = 'CCCoin',
                   set_symbol = 'CCC',
                   set_max_creation_rate_per_second = 1,
                   set_minter_address = False,
                   set_cccoin_address = False,
                   set_start_time = int(time()),
                   ):
    
    with open('../Contracts/CCCoinToken.sol') as f:
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

    print [set_name,
           set_symbol,
           set_max_creation_rate_per_second,
           set_minter_address,
           set_cccoin_address,
           set_start_time,
           ]

    ## For the sig - NO SPACES AFTER COMMAS ALLOWED! USE uint256 instead of uint!:
    
    cw.deploy(the_sig = 'CCCoinToken(string,string,uint256,address,address,uint256)', 
              the_args = [set_name,
                          set_symbol,
                          set_max_creation_rate_per_second,
                          set_minter_address,
                          set_cccoin_address,
                          set_start_time,
                          ],
              )

    return cw

##
#### Test `max_rate_not_reached`:
##

code_limit = \
"""
pragma solidity ^0.4.4;

contract CCCoinToken {
    
    //**** Constant token-specific fields:
    
    uint public constant MAX_CREATION_RATE_PER_SECOND = 1; 

    event MintEvent(uint reward_tok,
		    uint reward_lock,
		    address recipient,
		    //uint block_num,
		    //uint rewards_freq,
		    //uint tot_tok,
		    //uint tot_lock,
		    //uint current_tok,
		    //uint current_lock,
		    uint minted_tok,
		    uint minted_lock
		   );
    mapping (address => uint) total_minted_tok;
    mapping (address => uint) total_minted_lock;
    mapping (address => uint) balances_lock;    
    uint public totalSupplyLock;

    modifier only_minter {
        assert(msg.sender == minter_address);
        _;
    }
    
    modifier max_rate_not_reached(uint x) {
        assert((totalSupply / (now - x)) < MAX_CREATION_RATE_PER_SECOND);
        _;
    }

    function mintTokens(uint reward_tok, uint reward_lock, address recipient) //uint block_num, uint rewards_freq, uint tot_tok, uint tot_lock
    external
    only_minter
    max_rate_not_reached(start_time)
    {
        balances[recipient] = safeAdd(balances[recipient], reward_tok);
        totalSupply = safeAdd(totalSupply, reward_tok);
        balances_lock[recipient] = safeAdd(balances_lock[recipient], reward_lock);
        totalSupplyLock = safeAdd(totalSupply, reward_lock);
	MintEvent(reward_tok,
		  reward_lock,
		  recipient,
		  //block_num,
		  //rewards_freq,
		  //tot_tok, tot_lock,
		  //balances[recipient],
		  //balances_lock[recipient]
		  total_minted_tok[recipient],
		  total_minted_lock[recipient]
		 );
    }

}
"""

def sleep_loud(tm):
    print ('SLEEPING...', tm)
    sleep(tm)
    print ('DONE_SLEEP')


from Crypto.Hash import keccak
sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()

def test_contract_1_inner(cw, delay):
    
    priv = btc.sha256('the test password')
    pub = btc.privtopub(priv)
    addr = '0x' + sha3_256(pub)[-20:].encode('hex')
    
    for c in xrange(10):
        
        sleep_loud(delay)
        
        reward_tok = c + 1
        reward_lock = c + 1
        recipient = addr

        args = [reward_tok,
                reward_lock,
                recipient,
                ]
        
        print ('mintTokens()', args)
        
        tx = cw.send_transaction('mintTokens(uint256,uint256,address)',
                                 args,
                                 gas_limit = 100000,
                                 )
        
    cw.loop_once()

from ethjsonrpc.exceptions import BadResponseError

def test_contract_1():
    """
    Test that `max_rate_not_reached` protects against excessively fast minting.
    """
    
    print ('test_contract_1()')
    
    cw = setup_contract(set_max_creation_rate_per_second = 1)
    
    ## Mint slowly (half the maximum speed), check that only first minting goes through:
    test_contract_1_inner(cw, delay = 2)

    print ('GET_RESULT')

    caught = False
    try:
        rr = cw.c.call(address = cw.contract_address,
                       sig = 'totalSupply()',
                       args = [],
                       result_types = ['uint256'],  ## uint and int are aliases for uint256 and int256, respectively
                       )
    except BadResponseError as e:
        print 'CAUGHT_ASSERTION'
        caught = True
        
    assert not caught, ('FAILED - `max_rate_not_reached` should not have triggered assertion.',)

    print ('RESULT_1:', rr[0])
    
    ## Mint way too fast, check that only first minting goes through:
    test_contract_1_inner(cw, delay = 2)

    print ('GET_RESULT')

    caught = False

    try:
        rr = cw.c.call(address = cw.contract_address,
                       sig = 'totalSupply()',
                       args = [],
                       result_types = ['uint256'],  ## uint and int are aliases for uint256 and int256, respectively
                       )
    except BadResponseError as e:
        print 'CAUGHT_ASSERTION'
        caught = True
    
    assert caught, ('FAILED - `max_rate_not_reached` assertion failure not caught.',)

    print ('RESULT_2:', rr[0])
    
    print ('PASSED')



if __name__ == '__main__':
    test_contract_1()
