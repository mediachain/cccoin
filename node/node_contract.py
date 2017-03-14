#!/usr/bin/env python

## !!! REPLACED BY node_blockchain.py & node_state.py

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
import json

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
                 reorg_callback = False,
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

        self.block_details = {}
        
        self.reorg_callback = reorg_callback
        self.confirmation_tracker = {} ## {'block_hash':{'prev_block_hash':xx, 'block_num':yy}}
        
        self.done_block_nums = {} ## {confirm_state:set()}
        self.done_transactions = {} ## {confirm_state:set()}
        self.prev_block_num = {} ## {confirm_state:set()}
        
        self.blocking_sleep_time = blocking_sleep_time
        
        self.c = EthJsonRpc(rpc_host, rpc_port)

        self.contract_thread_sleep_time = contract_thread_sleep_time

        self.start_at_current_block = start_at_current_block

        self.current_block_at_init = self.c.eth_blockNumber()
        
        if self.start_at_current_block:
            self.last_incoming_block = max(0, self.current_block_at_init - 1)
        else:
            self.last_incoming_block = 0

        self.starting_block_num = self.last_incoming_block

        self.msgs = {} ## {block_num:[msg, msg, msg]}

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

    
    def check_for_reorg(self,
                        block_num,
                        ):
        """ Check for reorg since last check, and reorgs during our reorg rewinding... """
        print ('START check_for_reorg', block_num)

        return 
        block_num = ethereum.utils.parse_int_or_hex(block_num)
        
        while True:
            
            cur_num = block_num
            had_reorg = False
            
            while True:
                if cur_num == self.starting_block_num:
                    break

                assert cur_num >= self.starting_block_num, (cur_num, self.starting_block_num)

                ## Get info for prev and current:
                
                for x_block_num in [block_num, block_num - 1]:
                    if x_block_num not in self.block_details:
                        rh = self.c.eth_getBlockByNumber(x_block_num)
                        
                        ## Strip down to just a couple fields:
                        block_h = {'timestamp':ethereum.utils.parse_int_or_hex(rh['timestamp']),
                                   'hash':rh['hash'],
                                   'parentHash':rh['parentHash'],
                                   'blockNumber':x_block_num,
                                   }
                        self.block_details[x_block_num] = block_h

                ## Check for reorg:
                
                block_h = self.block_details[block_num]

                if block_h['parentHash'] != self.block_details[block_h['blockNumber'] - 1]['hash']:
                    print ('!!! REORG', block_num, '->', cur_num)
                    cur_num -= 1
                    self.latest_done_block = cur_num
                    had_reorg = True
                    continue
                break
            
            ## Rewind state if had_reorg:
            
            if had_reorg and (self.reorg_callback is not False):
                self.reorg_callback(cur_num)
                self.last_incoming_block = cur_num - 1
            
            ## If had_reorg, loop again - to detect another reorg that occured while we tracked down the reorg...
            
            if not had_reorg:
                break
            
        return had_reorg

    
    def poll_incoming(self, chunk_size = 50):
        """
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_newfilter

        - track buffer of events from old blocks
        - track pointer to last processed block
        """
        
        assert self.is_deployed, 'Must deploy contract first.'
        
        #self.latest_block_num = self.c.eth_blockNumber()
        
        from_block = self.last_incoming_block + 1
        
        params = {'from_block': fixed_int_to_hex(from_block),
                  'to_block':  'latest', #fixed_int_to_hex(from_block + chunk_size),
                  'address': self.contract_address,
                  }

        print ('eth_newFilter', 'from_block:', from_block, 'params:', params)
        
        self.the_filter = str(self.c.eth_newFilter(**params))

        num_blocks = len(self.msgs)

        xx_msgs = self.c.eth_getFilterLogs(self.the_filter)
        
        for msg in xx_msgs:
            msg['blockNumber'] = ethereum.utils.parse_int_or_hex(msg['blockNumber'])
            if msg['blockNumber'] not in self.msgs:
                self.msgs[msg['blockNumber']] = []
            self.msgs[msg['blockNumber']].append(msg)

        if num_blocks == len(self.msgs):
            ## Nothing new
            assert not len(xx_msgs), len(xx_msgs)
            return False
        
        for do_state, state_num_blocks in self.confirm_states.items():

            longest_confirm_state = max(self.confirm_states.values())
            newest_block_num = max(max(self.msgs), self.last_incoming_block)
            
            ## Oldest to newest:
            
            for nn in xrange(max(1, self.last_incoming_block - state_num_blocks),
                             newest_block_num + 1,
                             ):
                
                if self.check_for_reorg(nn):
                    ## Just wait for next call to poll_incoming() before resuming.
                    return False

                if nn in self.msgs:
                    for msg in self.msgs[nn]:
                        print ('EMIT', do_state, nn, msg['data'])
                        self.events_callback(msg = msg, receipt = False, received_via = do_state)
            
            ## Clear out old buffer:
            
            for nn in self.msgs.keys():
                if nn < newest_block_num - longest_confirm_state - 1:
                    del self.msgs[nn]
        
        self.last_incoming_block = newest_block_num

        return True
    
        if False:
            ## START CHECKS

            if do_state not in self.done_transactions:
                self.done_transactions[do_state] = set()
                self.done_block_nums[do_state] = set()

            msg_block_num = ethereum.utils.parse_int_or_hex(msg['blockNumber'])

            if cm == 0:
                assert msg_block_num not in self.done_block_nums[do_state], ('Seen block twice?',
                                                                             msg_block_num,
                                                                             )
                self.done_block_nums[do_state].add(msg_block_num)

            if do_state in self.prev_block_num:
                assert msg_block_num >= self.prev_block_num[do_state], ('REORG?',
                                                                        msg_block_num,
                                                                        self.prev_block_num[do_state],
                                                                        )
            self.prev_block_num[do_state] = msg_block_num

            assert msg['transactionHash'] not in self.done_transactions[do_state], ('Seen transaction twice?',
                                                                                    msg_block_num,
                                                                                    msg['transactionHash'],
                                                                                    )
            self.done_transactions[do_state].add(msg['transactionHash'])

            ## END CHECKS

        return had_any_events

    def _start_contract_thread(self,
                               terminate_on_exception = False,
                               ):
        while True:
            try:
                had_any_events = self.loop_once()
            except Exception as e:
                print ('-----LOOP_ONCE_EXCEPTION', e)
                #exit(-1)
                raise
                
                if terminate_on_exception:
                    raise
                continue
            
            if not had_any_events:
                print ('NO_NEW_EVENTS')
            
            sleep(self.contract_thread_sleep_time)
    
    def start_contract_thread(self,
                              start_in_foreground = False,
                              terminate_on_exception = False,
                              ):
        """
        Start ContractWrapper loop_once() in background thread, which (in that thread!) calls back to self.process_event()
        """
        if start_in_foreground:
            self._start_contract_thread(terminate_on_exception = terminate_on_exception)
        else:
            self.t = Thread(target = self._start_contract_thread,
                            args = (terminate_on_exception,),
                            )
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

