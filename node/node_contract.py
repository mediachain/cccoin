#!/usr/bin/env python

import web3
import ethereum.utils ## Slow...

from ethjsonrpc.utils import hex_to_dec, clean_hex, validate_block
from ethjsonrpc import EthJsonRpc
from time import sleep

DEFAULT_RPC_HOST = '127.0.0.1'
DEFAULT_RPC_PORT = 9999

def fixed_int_to_hex(vv):
    rr = ethereum.utils.int_to_hex(vv)
    if rr == '0x':
        rr = '0x0'
    return rr

from threading import current_thread,Thread
from Queue import Queue
from time import sleep, time

class ContractWrapper:
    
    def __init__(self,
                 the_code = False,
                 the_sig = None,
                 the_args = None,
                 the_address = False,
                 events_callback = False,
                 deploy_callback = False,
                 blocking_sleep_time = 0.1,
                 rpc_host = DEFAULT_RPC_HOST,
                 rpc_port = DEFAULT_RPC_PORT,
                 settings_confirm_states = {},
                 contract_address = False,
                 start_at_current_block = False,
                 auto_deploy = True,
                 contract_thread_sleep_time = 1.0,
                 ):
        """
        Simple contract wrapper, assists with deploying contract, sending transactions, and tracking event logs.
        
        Args:
        - the_code: solidity code for contract that should be deployed, prior to any operations.
        - the_address: address of already-deployed main contract.
        - contract_address: contract address, from previous `deploy()` call.
        - the_sig: optional constructor signature.
        - the_args: optional constructor args.
        - events_callback: callback for event messages e.g. `TheLog()`, `MintEvent()`, `LockupTokEvent()`, `TransferTokEvent()`.
        - deploy_callback: callback for contract deploys.
        - blocking_sleep_time: time to sleep when blocking and polling for a transaction receipt.
        """

        self.blocking_sleep_time = blocking_sleep_time

        self.c = EthJsonRpc(rpc_host, rpc_port)

        self.contract_thread_sleep_time = contract_thread_sleep_time

        self.start_at_current_block = start_at_current_block

        self.current_block_at_init = self.c.eth_blockNumber()
        
        if self.start_at_current_block:
            self.latest_done_block = self.current_block_at_init - 1
        else:
            self.latest_done_block = 0

        self.the_code = the_code
        self.the_sig = the_sig
        self.the_args = the_args

        self.contract_address = the_address
        
        assert self.the_code or self.contract_address
        
        self.loop_block_num = -1

        self.confirm_states = settings_confirm_states
        
        self.events_callback = events_callback

        self.pending_transactions = {}  ## {tx:callback}
        self.pending_logs = {}
        self.latest_block_num = -1

        self.latest_block_num_done = 0

        self.send_transaction_queue = Queue()

        self.is_deployed = False
        
        if auto_deploy:
            if the_address:
                assert self.check_anything_deployed(the_address), ('NOTHING DEPLOYED AT SPECIFIED ADDRESS:', the_address)
                self.is_deployed = True
            elif the_code:
                self.deploy()
        
    def check_anything_deployed(self, address):
        """ Basic sanity check, checks if ANY code is deployed at provided address. """
        if self.c.eth_getCode(address) == '0x0':
            return False
        return True
            
    def deploy(self,
               the_sig = False,
               the_args = False,
               block = False,
               deploy_from = False,
               callback = False,
               ):
        """ Deploy contract. Optional args_sig and args used to pass arguments to contract constructor."""

        if the_sig is not False:
            self.the_sig = the_sig
        
        if the_args is not False:
            self.the_args = the_args

        assert self.the_code

        if deploy_from is False:
            deploy_from = self.c.eth_coinbase()
        
        print ('DEPLOYING_CONTRACT...', 'deploy_from:', deploy_from, 'the_sig:', the_sig, 'the_args:', the_args)        
        # get contract address
        xx = self.c.eth_compileSolidity(self.the_code)
        #print ('GOT',xx)
        compiled = get_compiled_code(xx)

        contract_tx = self.c.create_contract(from_ = deploy_from,
                                             code = compiled,
                                             gas = 3000000,
                                             sig = self.the_sig,
                                             args = self.the_args,
                                             )

        if block:
            ## NOTE: @yusef feel free to switch back to this method if you want:
            #print('CONTRACT DEPLOYED, WAITING FOR CONFIRMATION')
            #wait_for_confirmation(self.c, contract_tx)
            
            print ('BLOCKING FOR RECEIPT..')
            while True:
                receipt = self.c.eth_getTransactionReceipt(contract_tx) ## blocks to ensure transaction is mined
                if receipt:
                    break
                sleep(self.blocking_sleep_time)
            print ('GOT RECEIPT')
        else:
            self.pending_transactions[contract_tx] = (callback, self.latest_block_num)
        
        self.contract_address = str(self.c.get_contract_address(contract_tx))
        self.is_deployed = True
        print ('DEPLOYED', self.contract_address)
        return self.contract_address

    def loop_once(self):
        assert self.is_deployed, 'Must deploy contract first.'

        had_any_events = False
        
        if self.c.eth_syncing():
            print ('BLOCKCHAIN_STILL_SYNCING')
            return False
        
        if self.events_callback is not False:
            had_any_events = self.poll_incoming()
        
        had_any_events = self.poll_outgoing() or had_any_events

        num_fails = 0
        
        while self.send_transaction_queue.qsize():
            print ('TRY_TO_SEND')
            tries, args, kw = self.send_transaction_queue.get()
            try:
                self._send_transaction(*args, **kw)
            except Exception as e:
                print ('FAILED_TO_SEND', e, tries, args, kw)
                sleep(1) ## TODO
                self.send_transaction_queue.put((tries + 1, args, kw))
                break
                
        return had_any_events
        

    def poll_incoming(self):
        """
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_newfilter
        
        1) Create new event filter for each event type we're watching.
        2) 
        """
        
        assert self.is_deployed, 'Must deploy contract first.'

        self.latest_block_num = self.c.eth_blockNumber()
                
        for do_state, state_num_blocks in self.confirm_states.items():
            
            from_block = self.latest_done_block + 1 - state_num_blocks
            to_block = max(self.latest_done_block, self.latest_block_num) + 1
            
            if from_block < 0:
                continue
            if from_block < 1:
                from_block = 1
            
            got_block = 0
            
            params = {'from_block': fixed_int_to_hex(from_block),
                      'to_block': 'latest',#fixed_int_to_hex(to_block),
                      'address': self.contract_address,
                      }
            
            print ('eth_newFilter', 'do_state:', do_state, 'latest_block_num:', self.latest_block_num, 'params:', params)
            
            self.the_filter = str(self.c.eth_newFilter(**params))
            
            print ('eth_getFilterChanges', self.the_filter)
            
            msgs = self.c.eth_getFilterLogs(self.the_filter)
            
            if msgs:
                had_any_events = True
            else:
                had_any_events = False
                
            print ('POLL_INCOMING_GOT', len(msgs))
            
            for msg in msgs:
                
                self.latest_done_block = max(self.latest_done_block,
                                             ethereum.utils.parse_int_or_hex(msg['blockNumber']),
                                             )
                
                self.events_callback(msg = msg, receipt = False, received_via = do_state)

                self.latest_block_num_done = max(0, max(self.latest_block_num_done, got_block - 1))

            return had_any_events

    def _start_contract_thread(self,):
        while True:
            try:
                had_any_events = self.loop_once()
            except Exception as e:
                print ('LOOP_ONCE_EXCEPTION', e)
                continue
            
            if not had_any_events:
                print ('NO_NEW_EVENTS')
                sleep(self.contract_thread_sleep_time)
    
    def start_contract_thread(self,):
        """
        Start ContractWrapper loop_once() in background thread, which (in that thread!) calls back to self.process_event()
        """
        self.t = Thread(target = self._start_contract_thread)
        self.t.daemon = True
        self.t.start()
    
    def send_transaction(self, *args, **kw):
        assert len(args) <= 2
        if kw.get('block'):
            self.send_transaction(*args, **kw)
        else:
            self.send_transaction_queue.put((0, args, kw))
        
    def _send_transaction(self,
                         args_sig,
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

        assert self.is_deployed, 'Must deploy contract first.'

        print ('SEND_TRANSACTION:', args_sig, args)

        if send_from is False:
            send_from = self.c.eth_coinbase()
        
        send_to = self.contract_address 

        print ('====TRANSACTION')
        print ('send_from', send_from)
        print ('send_to', send_to)
        print ('args_sig', args_sig)
        print ('args', args)
        #print ('gas', gas_limit)

        
        gas_limit = 1000000
        gas_price = self.c.DEFAULT_GAS_PRICE
        value = web3.utils.currency.to_wei(1,'ether')

        data = self.c._encode_function(args_sig, args)
        data_hex = '0x' + data.encode('hex')
        
        tx = self.c.eth_sendTransaction(from_address = send_from,
                                        to_address = send_to,
                                        data = data_hex,
                                        gas = gas_limit,
                                        gas_price = gas_price,
                                        value = value,
                                        )
        
        if block:
            print ('BLOCKING FOR RECEIPT..')
            while True:
                receipt = self.c.eth_getTransactionReceipt(tx) ## blocks to ensure transaction is mined
                if receipt:
                    break
                sleep(self.blocking_sleep_time)
            print ('GOT RECEIPT')
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

        assert self.is_deployed, 'Must deploy contract first.'

        had_any_events = False
        if self.pending_transactions:
            had_any_events = True
        
        for tx, (callback, attempt_block_num) in self.pending_transactions.items():
            
            ## Compare against the block_number where it attempted to be included:
            
            if (attempt_block_num <= self.latest_block_num - self.confirm_states['BLOCKCHAIN_CONFIRMED']):
                continue
            
            receipt = self.c.eth_getTransactionReceipt(tx)
            
            if receipt is not None and 'blockNumber' in receipt:
                actual_block_number = ethereum.utils.parse_int_or_hex(receipt['blockNumber'])
            else:
                ## TODO: wasn't confirmed after a long time.
                actual_block_number = False
            
            ## Now compare against the block_number where it was actually included:
            
            if (actual_block_number is not False) and (actual_block_number >= self.latest_block_num - self.confirm_states['BLOCKCHAIN_CONFIRMED']):
                if callback is not False:
                    callback(receipt)
                del self.pending_transactions[tx]

        return had_any_events
    
    def read_transaction(self, args_sig, value):
        rr = self.c.call(self.c.eth_coinbase(), self.contract_address, args_sig, value)
        return rr

    
    def sign(self, user_address, value):
        rr = self.c.eth_sign(self.c.eth_coinbase(), self.contract_address, user_address, value)
        return rr
        

def get_compiled_code(rpc_compiler_output):
    compiled = None
    try:
        compiled = rpc_compiler_output['code']
    except KeyError:
        # geth seems to like putting the compiler output into an inner dict keyed by input filename,
        # e.g {'CCCoinToken.sol': {'code': '...', 'etc': '...'}
        for k, v in rpc_compiler_output.iteritems():
            if isinstance(v, dict) and 'code' in v:
                compiled = v['code']
                break
    if compiled is None:
        raise Exception('Unable to retrieve compiled code from eth_compileSolidity RPC call')
    return compiled

def wait_for_confirmation(eth_json_rpc, tx_hash, sleep_time=0.1):
    while eth_json_rpc.eth_getTransactionReceipt(tx_hash) is None:
        sleep(sleep_time)

def test_contract_wrapper():
    pass

