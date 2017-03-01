import pytest
from time import time, sleep
import bitcoin as btc

## pytest fixture configuration (see conftest.py)
force_redeploy_contract = True
contract_wrapper_args = dict(settings_confirm_states = {'BLOCKCHAIN_CONFIRMED':1},
                             start_at_current_block = True, ## dont get logs from old tests
                             auto_deploy = False, # dont' auto-deploy, so we can get the coinbase address
                             )

@pytest.fixture(params=['CCCoin'])
def contract_name(request):
    return request.param

@pytest.fixture(params=['CCC'])
def contract_symbol(request):
    return request.param

@pytest.fixture(params=[2]) # setting to 1 causes a solidity assertion due to integer division
def max_creation_rate(request):
    return request.param

@pytest.fixture
def deployed_contract(request, cccoin_contract, contract_name, contract_symbol, max_creation_rate):
    minter_address = request.config.getoption('--minter-address') or cccoin_contract.c.eth_coinbase()
    cccoin_address = request.config.getoption('--cccoin-address') or cccoin_contract.c.eth_coinbase()
    start_time = int(time())

    args = [contract_name, contract_symbol, max_creation_rate, minter_address, cccoin_address, start_time]
    print('deploying with args: ', args)

    cccoin_contract.deploy(
        the_sig='CCCoinToken(string,string,uint256,address,address,uint256)',
        the_args=args
    )
    return cccoin_contract


def test_get_lang_version(eth_json_rpc):
    minimal_code = \
        """
        pragma solidity ^0.4.6;
        contract CCCoin {
            event MainLog(bytes);
            function addLog(bytes val) payable {
                MainLog(val);
            }
        }
        """
    try:
        eth_json_rpc.eth_compileSolidity(minimal_code)['info']['compilerVersion']
    except KeyError as e:
        assert False, 'Compiler did not return info.compilerVersion field'


def test_getters(eth_json_rpc):
    minimal_code = \
        """
        pragma solidity ^0.4.6;
        contract Test {
          uint256 public the_var = 5;
        }
        """
    c = eth_json_rpc
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


def sleep_loud(tm):
    print ('SLEEPING...', tm)
    sleep(tm)
    print ('DONE_SLEEP')


from Crypto.Hash import keccak
sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()

def contract_1_test_inner(cw, delay):

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

def test_contract_1(deployed_contract, max_creation_rate):
    """
    Test that `max_rate_not_reached` protects against excessively fast minting.
    """

    print ('test_contract_1()')

    cw = deployed_contract

    print ('GET_RESULT')

    caught = False
    try:
        ## Mint slowly (half the maximum speed), check that only first minting goes through:
        contract_1_test_inner(cw, delay = max_creation_rate * 2)

        print ('GET_RESULT')
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

    caught = False
    try:
        ## Mint way too fast, check that only first minting goes through:
        contract_1_test_inner(cw, delay = max_creation_rate * 0.1)
    except BadResponseError as e:
        print 'CAUGHT_ASSERTION'
        caught = True

    assert caught, ('FAILED - `max_rate_not_reached` assertion failure not caught.',)

    print ('GET_RESULT')
    rr = cw.c.call(address = cw.contract_address,
                   sig = 'totalSupply()',
                   args = [],
                   result_types = ['uint256'],  ## uint and int are aliases for uint256 and int256, respectively
                   )
    print ('RESULT_2:', rr[0])

    print ('PASSED')