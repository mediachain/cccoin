import pytest
from subprocess import Popen, PIPE
from signal import SIGTERM

from node_core import CCCoinCore
from node_contract import ContractWrapper
from node_main import CORE_SETTINGS, DEFAULT_CONFIRM_STATES
from utils import find_open_port
from os import path

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

@pytest.fixture(scope="module")
def eth_rpc_port(request):
    """
    Spawns a new testrpc instance on a random port.
    If you define a variable `external_rpc_port` in your
    test module, skips spawning testrpc and uses the external port
    :return: the port the testrpc listens on
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
def cccoin_contract(request, eth_rpc_port):
    eth_rpc_host = getattr(request.module, 'external_rpc_host', 'localhost')

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
    core_kwargs = {'settings_rewards': CORE_SETTINGS.copy(),
                   'contract_wrapper': cccoin_contract}

    core_kwargs['settings_rewards'].update(getattr(request.module, 'cccoin_rewards_settings', {}))
    core_kwargs.update(getattr(request.module, 'cccoin_core_args', {}))
    return CCCoinCore(**core_kwargs)

