import pytest
from subprocess import Popen, PIPE
from signal import SIGTERM

from node_core import CCCoinCore
from node_contract import ContractWrapper
from node_main import CORE_SETTINGS, DEFAULT_CONFIRM_STATES
from utils import find_open_port
from os import path
from ethjsonrpc import EthJsonRpc

CONTRACT_CODE_PATH = path.normpath(path.join(path.dirname(__file__), '..', 'contracts', 'CCCoinToken.sol'))

def pytest_addoption(parser):
    parser.addoption("--rpc-port", action="store", default=None,
                     help="rpc-port: if given, use ethereum rpc on this port instead of spawning a testrpc instance")
    parser.addoption('--rpc-host', action='store', default='localhost',
                     help='rpc-host: set to target an external ethereum rpc on a different host')
    parser.addoption('--contract-path', action='store', default=CONTRACT_CODE_PATH,
                     help='path to solidity contract to deploy')
    parser.addoption('--contract-address', action='store', default=None,
                     help='If given, should be the address of a deployed contract (reachable with external --rpc-port option).')
    parser.addoption('--minter-address', action='store', default=None,
                     help='Used in contract test to set the address of the "minting" account.  Defaults to coinbase address.')
    parser.addoption('--cccoin-address', action='store', default=None,
                     help='Used in contract test to set the address of the CCCoin contract owner. Defaults to coinbase address.')

@pytest.fixture(scope="module")
def eth_json_rpc(eth_rpc_host, eth_rpc_port):
    """
    An instance of EthJsonRpc that uses the host and port specified with
    the `--rpc-host` and `--rpc-port` flags (or an ephemeral testrpc instance if
    `--rpc-port` is not given)
    """
    return EthJsonRpc(eth_rpc_host, eth_rpc_port)

@pytest.fixture(scope="module")
def eth_rpc_host(request):
    """
    RPC hostname or IP. defaults to `localhost`, but can be overridden with
    `--rpc-host` cli flag
    """
    return request.config.getoption('--rpc-host')

@pytest.fixture(scope="module")
def eth_rpc_port(request):
    """
    If cli flag `--rpc-port` is given, returns that port.

    Otherwise, spawns a new testrpc instance on a random port and returns it.
    The testrpc instance will be killed after the test that depends on this
    fixture completes
    """
    external_rpc_port = request.config.getoption('--rpc-port')
    if external_rpc_port is not None:
        yield int(external_rpc_port)
    else:
        open_port = find_open_port()
        testrpc_process = Popen(["testrpc", "-p", str(open_port)], stdout=PIPE)
        while not testrpc_process.stdout.readline().lower().startswith('listening'):
            pass

        yield open_port
        print('shutting down testrpc')
        testrpc_process.send_signal(SIGTERM)
        testrpc_process.wait()

@pytest.fixture(scope="module")
def cccoin_contract(request, eth_rpc_host, eth_rpc_port):
    """
    Fixture that creates a ContractWrapper based on command line flags and
    test-module attributes.

    cli flags:
     - `--rpc-host`: defaults to localhost
     - `--rpc-port`: port for external RPC (geth, testrpc, etc).
        if rpc-port flag is not given, we'll launch a new testrpc instance
        on a random port for each test module!
     - `--contract-path`: file path to solidity contract
     - `--contract-address`: eth address of deployed contract.
         use with rpc-port if you've already deployed to geth

    test module variables:
    - `contract_args`: keyword args for `ContractWrapper` constructor.
                        set this in your test module
    """

    wrapper_kwargs = {'settings_confirm_states': DEFAULT_CONFIRM_STATES,
                      'rpc_host': eth_rpc_host,
                      'rpc_port': eth_rpc_port}

    contract_addr = request.config.getoption('--contract-address')
    if contract_addr is not None:
        wrapper_kwargs['the_address'] = contract_addr
    else:
        code_path = request.config.getoption('--contract-path')
        with open(code_path, 'r') as f:
            code = f.read()
        wrapper_kwargs['the_code'] = code

    wrapper_kwargs.update(getattr(request.module, 'contract_args', {}))
    contract = ContractWrapper(**wrapper_kwargs)
    return contract

@pytest.fixture(scope="module")
def cccoin_core(request, cccoin_contract):
    """
    Fixture that creates a CCCoinCore instance based on the
    default settings in node_main, optionally overridden by
    special test-module scoped variables:
      - cccoin_core_args: keyword args to pass to CCCoinCore constructor
      - cccoin_rewards_settings: overrides the contents of the default `settings_rewards` dict.
         will be merged into default CORE_SETTINGS.

    see cccoin_contract fixture for contract parameters
    :param request:
    :param cccoin_contract:
    :return:
    """
    core_kwargs = {'settings_rewards': CORE_SETTINGS.copy(),
                   'contract_wrapper': cccoin_contract}

    core_kwargs['settings_rewards'].update(getattr(request.module, 'cccoin_rewards_settings', {}))
    core_kwargs.update(getattr(request.module, 'cccoin_core_args', {}))
    return CCCoinCore(**core_kwargs)

