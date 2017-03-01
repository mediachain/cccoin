import pytest
from subprocess import Popen
from signal import SIGTERM
from node_mc import MediachainQueue, MediachainClient
from node_core import client_post
import bitcoin as btc
from time import sleep
import shutil
from utils import find_open_port
from tornado.ioloop import IOLoop

# test that CCCoinCore writes to mediachain successfully
# Must have `mcnode` on your $PATH for this to work

# pytest fixture configuration (see conftest.py)

contract_args = {'start_at_current_block': True, 'settings_confirm_states': {'BLOCKCHAIN_CONFIRMED':1}}
cccoin_core_args = {'write_to_mc': True}

@pytest.fixture
def mc_node_url(tmpdir):
    """
    create an ephemeral mcnode that we can write to from CCCoin
    :param tmpdir: pytest tmpdir fixture (for storing node data)
    :param find_open_port: pytest fixture function we can call to find an open tcp port
    :return:
    """
    p2p_port = str(find_open_port())
    control_port = str(find_open_port())
    data_dir = str(tmpdir)
    mcnode_process = Popen(["mcnode", "-d", data_dir, "-l", p2p_port, "-c", control_port])
    mc_url = 'http://localhost:' + control_port
    sleep(0.2)
    yield mc_url

    # cleanup
    mcnode_process.send_signal(SIGTERM)
    mcnode_process.wait()
    shutil.rmtree(data_dir)

def test_cccoin_mc_write(mc_node_url, cccoin_core):
    cccoin_core.mcq = MediachainQueue(mc_api_url=mc_node_url, default_namespace='cccoin')
    the_pw = 'some big long brainwallet password'
    priv = btc.sha256(the_pw)
    pub = btc.privtopub(priv)
    blind_post, unblind_post = client_post('http://foo',
                                       'The Title ',
                                       priv,
                                       pub,
                                       )

    cccoin_core.submit_blind_action(blind_post)
    cccoin_core.submit_unblind_action(unblind_post)
    cccoin_core.cw.loop_once()
    start_block = cccoin_core.cw.latest_block_num

    while cccoin_core.cw.latest_block_num < start_block + 3: # not sure why / if this is the magic number, but it WFM...
        cccoin_core.cw.loop_once()
        sleep(0.1)

    cccoin_core.mcq.wait_for_completion()

    client = MediachainClient(mc_api_url=mc_node_url)
    results = IOLoop.current().run_sync(lambda: client.query('SELECT * FROM cccoin'))

    assert(len(results) > 0)
