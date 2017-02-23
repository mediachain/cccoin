#!/usr/bin/env python

import web3
import ethereum.utils ## Slow...

from ethjsonrpc.utils import hex_to_dec, clean_hex, validate_block
from ethjsonrpc import EthJsonRpc

DEFAULT_RPC_HOST = '127.0.0.1'
DEFAULT_RPC_PORT = 9999

class ContractWrapper:
    
    def __init__(self,
                 the_code = False,
                 the_address = False,
                 events_callback = False,
                 rpc_host = DEFAULT_RPC_HOST,
                 rpc_port = DEFAULT_RPC_PORT,
                 settings_confirm_states = {},
                 final_confirm_state = 'BLOCKCHAIN_CONFIRMED',
                 contract_address = False,
                 start_at_current_block = False,
                 ):
        """
        Simple contract wrapper, assists with deploying contract, sending transactions, and tracking event logs.
        
        Args:
        - the_code - solidity code for contract that should be deployed, prior to any operations.
        - the_address - address of already-deployed main contract.
        - `events_callback` will be called upon each state transition, according to `confirm_states`, 
          until `final_confirm_state`.
        - `contract_address` contract address, from previous `deploy()` call.
        """

        self.start_at_current_block = start_at_current_block
        
        self.the_code = the_code
        self.contract_address = the_address

        assert self.the_code or self.contract_address
        
        self.loop_block_num = -1

        self.confirm_states = settings_confirm_states
        
        self.events_callback = events_callback

        self.c = EthJsonRpc(rpc_host, rpc_port)

        self.pending_transactions = {}  ## {tx:callback}
        self.pending_logs = {}
        self.latest_block_num = -1

        self.latest_block_num_done = 0

        if the_code:
            self.deploy()
        
                    
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

        if self.start_at_current_block:
            start_block = self.c.eth_blockNumber()
        else:
            start_block = 0
        
        self.latest_block_num = self.c.eth_blockNumber()

        for do_state in ['BLOCKCHAIN_CONFIRMED',
                         #'PENDING',
                         ]:
            
            self.latest_block_num_confirmed = max(0, self.latest_block_num - self.confirm_states[do_state])
            
            from_block = max(1,self.latest_block_num_done)
            
            to_block = self.latest_block_num_confirmed
            
            got_block = 0
            
            params = {'fromBlock': ethereum.utils.int_to_hex(start_block),#ethereum.utils.int_to_hex(from_block),#'0x01'
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
        


def test_contract_wrapper():
    pass
