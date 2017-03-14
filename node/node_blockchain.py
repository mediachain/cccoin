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
import json


class EthereumBlockchain:
    def __init__(self,
                 the_code = False,
                 the_sig = None,
                 the_args = None,
                 the_address = False,
                 rpc_host = DEFAULT_RPC_HOST,
                 rpc_port = DEFAULT_RPC_PORT,
                 background_thread_sleep_time = 1.0,
                 ):
        
        self.con = EthJsonRpc(rpc_host, rpc_port)
        
        self.the_code = the_code
        self.the_sig = the_sig
        self.the_args = the_args
        
        self.contract_address = the_address
        
        assert self.the_code or self.contract_address
        
        self.loop_once_started = False
        
        self.sig_to_topic_id_cache = {}
        
        self.send_transaction_queue = Queue()
        
        self.is_deployed = False
        
        self.background_thread_sleep_time = background_thread_sleep_time
        
    def event_sig_to_topic_id(self, sig):
        """ Compute ethereum topic_ids from function signatures. """
        if sig in self.sig_to_topic_id_cache:
            return self.sig_to_topic_id_cache[sig]
        name = sig[:sig.find('(')]
        types = [x.strip().split()[0] for x in sig[sig.find('(')+1:sig.find(')')].split(',')]
        topic_id = ethereum.utils.int_to_hex(ethereum.abi.event_id(name,types))
        self.sig_to_topic_id_cache[sig] = topic_id
        return topic_id
    
    def _estimate_event_log_outputs(self,
                                    args_sig,
                                    args,
                                    *_1, **_2):
        """
        Called by send_transaction().
        
        Instantly estimate what event log(s) will be output from a contract call transaction, so that the app can instantly compute derived
        state for pending transactions, which will later be confirmed when the corresponding events are read in from confirmed blocks on the blockchain.
        
        In theory, this could involve replicating the full EVM logic here.  Typically though, we'll just implement those contract
        calls that have trivial logic & don't depend on blockchain state, e.g. `addLog(bytes)`, and ignore the rest.
        """
        
        pending_logs = []
        
        topic_id = self.event_sig_to_topic_id(args_sig)
        
        if args_sig == 'TheLog(bytes)':
            
            assert len(args) == 1
            
            log = {"type": "mined", 
                   "data": args[0], ## TODO: need to solidity-encode this string, or not?
                   "topics": [topic_id], 
                   #"blockHash": "0xebe2f5a6c9959f83afc97a54d115b64b3f8ce62bbccb83f22c030a47edf0c301", 
                   #"transactionHash": "0x3a6d530e14e683e767d12956cb54c62f7e8aff189a6106c3222b294310cd1270", 
                   #"blockNumber": "0x68", 
                   #"address": "0x88f93641a96cb032fd90120520b883a657a6f229", 
                   #"logIndex": "0x00", 
                   #"transactionIndex": "0x00"
                   }
            
            pending_logs.append(log)
        
        return pending_logs
        
    def get_block_by_hash_callback(self, block_hash):
        """
        Get block by blockHash.
        
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getblockbyhash
        """
        rh = self.con.eth_getBlockByHash(block_hash)
        
        for k in ['number', 'timestamp']:
            rh[k] = ethereum.utils.parse_int_or_hex(rh[k])
        
        return rh
        
    
    def get_logs_by_block_num_callback(self, block_num):
        """
        Get event logs for a particular block num. It's OK if the block_num has an unexpected hash, 
        that'll be taken care of by caller.
        
        https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getlogs
        """
        
        the_filter = self.con.eth_newFilter(from_block =  fixed_int_to_hex(block_num),
                                            to_block = fixed_int_to_hex(block_num),
                                            address = self.contract_address,
                                            )
        
        rr =  self.con.eth_getLogs(str(the_filter))
        
        for msg in rr:
            msg['data'] = solidity_string_decode(msg['data'])
            msg['blockNumber'] = ethereum.utils.parse_int_or_hex(msg['blockNumber'])
            msg["logIndex"] = ethereum.utils.parse_int_or_hex(msg['logIndex'])
            msg["transactionIndex"] = ethereum.utils.parse_int_or_hex(msg['transactionIndex'])
            msg_data = loads_compact(msg['data'])
            payload_decoded = loads_compact(msg_data['payload'])
            
        return rr

    def get_latest_block_number(self):
        bn = self.con.eth_blockNumber()
        return bn
    
    def get_latest_block_callback(self):
        """
        Returns the single latest block. Missing intermediate blocks will be automatically looked up by caller.
        """
        bn = self.get_latest_block_number()
        block = self.con.eth_getBlockByNumber(bn)
        return block

                
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
            self.contract_sig = the_sig
        
        if the_args is not False:
            self.contract_args = the_args

        assert self.the_code

        if deploy_from is False:
            deploy_from = self.c.eth_coinbase()
        
        print ('DEPLOYING_CONTRACT...', 'deploy_from:', deploy_from, 'the_sig:', the_sig, 'the_args:', the_args)        
        # get contract address
        xx = self.con.eth_compileSolidity(self.the_code)
        #print ('GOT',xx)
        
        compiled = None
        
        try:
            compiled = xx['code']
        except KeyError:
            # geth seems to like putting the compiler output into an inner dict keyed by input filename,
            # e.g {'CCCoinToken.sol': {'code': '...', 'etc': '...'}
            for k, v in xx.iteritems():
                if isinstance(v, dict) and 'code' in v:
                    compiled = v['code']
                    break
        
        assert compiled
        
        contract_tx = self.con.create_contract(from_ = deploy_from,
                                               code = compiled,
                                               gas = 3000000,
                                               sig = self.contract_sig,
                                               args = self.contract_args,
                                               )

        if block:
            ## NOTE: @yusef feel free to switch back to this method if you want:
            #print('CONTRACT DEPLOYED, WAITING FOR CONFIRMATION')
            #wait_for_confirmation(self.c, contract_tx)
            
            print ('BLOCKING FOR RECEIPT..')
            while True:
                receipt = self.con.eth_getTransactionReceipt(contract_tx) ## blocks to ensure transaction is mined
                if receipt:
                    break
                sleep(self.blocking_sleep_time)
            print ('GOT RECEIPT')
        else:
            self.pending_transactions[contract_tx] = (callback, self.latest_block_num)
        
        self.contract_address = str(self.con.get_contract_address(contract_tx))
        self.is_deployed = True
        print ('DEPLOYED', self.contract_address)
        return self.contract_address

    
    def do_send_transaction(self,
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
            send_from = self.con.eth_coinbase()
        
        send_to = self.contract_address 

        print ('====TRANSACTION')
        print ('send_from', send_from)
        print ('send_to', send_to)
        print ('args_sig', args_sig)
        print ('args', args)
        #print ('gas', gas_limit)

        
        gas_limit = 1000000
        gas_price = self.con.DEFAULT_GAS_PRICE
        value = web3.utils.currency.to_wei(1,'ether')

        data = self.con._encode_function(args_sig, args)
        data_hex = '0x' + data.encode('hex')
        
        tx = self.con.eth_sendTransaction(from_address = send_from,
                                          to_address = send_to,
                                          data = data_hex,
                                          gas = gas_limit,
                                          gas_price = gas_price,
                                          value = value,
                                          )
        
        if block:
            print ('BLOCKING FOR RECEIPT..')
            while True:
                receipt = self.con.eth_getTransactionReceipt(tx) ## blocks to ensure transaction is mined
                if receipt:
                    break
                sleep(self.blocking_sleep_time)
            print ('GOT RECEIPT')
            #print ('GOT_RECEIPT', receipt)
            #if receipt['blockNumber']:
            #    self.latest_block_num = max(ethereum.utils.parse_int_or_hex(receipt['blockNumber']), self.latest_block_num)
        else:
            self.pending_transactions[tx] = (callback, self.latest_block_num)

        self.latest_block_num = self.con.eth_blockNumber()
        
        return {'tx':tx, 'pending_logs':pending_logs}

    def poll_outgoing_receipts(self):
        """
        Check for transaction receipts on transactions sent from this node.
        TODO - why not replace this with just watching for incoming transactions???
        """
        
        assert self.is_deployed, 'Must deploy contract first.'

        had_any_events = False
        if self.pending_transactions:
            had_any_events = True
        
        for tx, (callback, attempt_block_num) in self.pending_transactions.items():
            
            receipt = self.con.eth_getTransactionReceipt(tx)
            
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
    
    
    def _start_background_thread(self,
                                 terminate_on_exception = False,
                                 ):
        last_event = False
        
        while True:
            try:
                had_any_events = self.loop_writes_once()
            except Exception as e:
                print ('-----LOOP_ONCE_EXCEPTION', e)
                #exit(-1)
                raise
                
                if terminate_on_exception:
                    raise
                continue

            if had_any_events:
                last_event = time()
            else:
                print ('NO_NEW_EVENTS', last_event and (time() - last_event))
            
            sleep(self.background_thread_sleep_time)
    
    def start_background_thread(self,
                                start_in_foreground = False,
                                terminate_on_exception = False,
                                ):
        """
        Start ContractWrapper loop_once() in background thread, which (in that thread!) calls back to self.process_event()
        """
        if start_in_foreground:
            self._start_background_thread(terminate_on_exception = terminate_on_exception)
        else:
            self.t = Thread(target = self._start_background_thread,
                            args = (terminate_on_exception,),
                            )
            self.t.daemon = True
            self.t.start()
    
    def send_transaction(self, *args, **kw):
        """
        1) If possible create simulated outputs of transactions, to use as pending state.
        2) Queue the transaction for blockchain commit.
        
        Used for e.g.:
        - addLog(bytes)
        - mintTokens(address, uint, uint, uint, uint, uint, uint)
        - withdrawTok(bytes)
        - lockupTok(bytes)
        """
        
        assert len(args) <= 2
        assert self.loop_once_started, 'loop_once() not started?'
        
        ## Potentially slow blocking call to commit it to the blockchain:

        if kw.get('block'):
            ## Send transaction in blocking mode, and grab actual event logs that are committed:
            
            rh = self.do_send_transaction(*args, **kw)
            
            pending_logs = rh['pending_logs']
            
        else:
            ## Run callbacks, return simulated event logs where possible:
            
            self.send_transaction_queue.put((0, args, kw))
            
            pending_logs = self._estimate_event_log_outputs(*args, **kw)

        
        ## Run logic_callback() against pending transactions:
            
        for log in pending_logs:
            self.logic_callback(log,
                                is_pending = (kw.get('block') and True),
                                is_noop = log.get('is_noop', False)
                                )
        
        return pending_logs
            

    def loop_writes_once(self):
        ## Check for available write receipts:
        #self.poll_outgoing_receipts()

        self.loop_once_started = True
        
        ## Do write transactions transactions:
        
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

    
