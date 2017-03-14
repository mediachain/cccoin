#!/usr/bin/env python

"""
Sophisticated state tracking and fusion using blockchain consensus, nonces, and timeouts to dictate eventual consistency.

Motivation:
Blockchain consensus is better viewed as a tree, not a linear line, and managing derived state, especially when that derived
state should be fed back into the blockchain in a feedback loop, is highly non-trivial if you don't view it as a tree.

Usage:
(1) Pass a class that implements the basic blockchain callbacks. See EthereumBlockchain and MockBlockchain.
(2) Pass an application callback class (see MockApp and CCCoinCore) which implements a `logic_callback()` function that:
    + Receives event log messages, along with their block hash and confirmation status (e.g. is_pending == True).
    + Does store(), lookup(), iterate_items() calls back to the state manager, to compute its derived view of the blockchain state
      at each block in the transaction tree.
    + Does send_transaction() calls to modify the blockchain state.

Roles:
- Maintains a rigorously defined view of derived state, based on the confirmation or rejection of input values coming 
  from confirmed blockchain transactions, the blockchain pending mempool, and the local pending mempool.
- Manages all access to smart-contract calls, see node_blockchain.py for specific implementations.

Features:
- tables for key-value storage.
- nonce-based prioritization of actions.
- fusing pending-write & confirmed-read views of state.

Confirmation level types:
- confirmed:  transactions that have been put into blocks on the blockchain. I.e. 1+ confirmation transactions.
- pending:    pending, unordered transactions that are not yet in a blockchain block, either come from the blockchain 
              mempool or a local write. I.e. 0 confirmation transactions.
"""


from copy import deepcopy
from Queue import Queue

from threading import current_thread,Thread
from Queue import Queue
from time import sleep, time
import json


class StateManager:    
    def __init__(self,
                 blockchain_callbacks,
                 starting_block_hash = False,
                 starting_block_num = 1,
             ):
        
        assert starting_block_num >= 1, '1 is smallest possible value for starting_block_num in ethereum'
        
        self.bcc = blockchain_callbacks
        self.starting_block_hash = starting_block_hash
        self.starting_block_num = starting_block_num

        #import leveldb
        #self.the_db = leveldb.LevelDB(db_name)
        
        self.hh = {}
        self.hh_pending = {}
        
        self.parent_lookup = {} ## {blockHash:blockParentHash}
        self.block_hash_to_block_num = {}
        self.latest_hash = False
        
        self.is_setup_tables = False
        self.is_setup_logic_callback = False
        
        self.send_transaction_queue = Queue()
        
        ## Just for timing info etc:
        self.block_details = {} ## {hash:{'timestamp':1234}}
            
    def setup_tables(self,
                     table_names,
                     ):
        self.is_setup_tables = True
        self.table_names = table_names
        for table in self.table_names:
            self.hh[table] = {}
            self.hh_pending[table] = {}
        
    def setup_logic_callback(self, logic_callback):
        self.is_setup_logic_callback = True
        self.logic_callback = logic_callback
        
    def loop_once(self,
                 break_when_caught_up = False,
                 ):
        assert self.is_setup_tables, 'Must call setup_tables().'
        assert self.is_setup_logic_callback, 'Must call setup_logic_callback().'
        
        ## Read side:
        
        self._check_block_loaded(self.bcc.get_latest_block_callback()['hash'])
        
        ## Write side:
        
        self.bcc.loop_writes_once()
    
    def _check_block_loaded(self, the_hash):
        """
        State management and missing block backfill.
        """
        
        while True:
            ## Get list of any unseen blocks:
            
            buf = []

            cur_hash = the_hash
            
            first_time = True
            
            while True:
                
                block = self.bcc.get_block_by_hash_callback(cur_hash)
                
                if (self.latest_hash is False) or (block['totalDifficulty'] > self.latest_hash[0]):
                    self.latest_hash = [block['totalDifficulty'], block['hash'], block['number']]
                    
                self.block_hash_to_block_num[block['hash']] = block['number']
                
                assert block['number'] >= 1, ('Expecting block numbers to be >= 1', block['number'])
                
                self.parent_lookup[block['hash']] = block['parentHash']
                
                if block['number'] == self.starting_block_num:
                    break
                
                if block['hash'] == self.starting_block_hash:
                    break

                #if first_time:
                #    print '???', self.hh[self.table_names[0]]
                #    raw_input()

                if first_time and (block['hash'] not in self.hh[self.table_names[0]]):
                    buf.append((block['number'],
                                block['hash'],
                                ))

                if block['parentHash'] not in self.hh[self.table_names[0]]:
                    buf.append((block['number'] - 1,
                                block['parentHash'],
                                ))
                else:
                    break
                
                ### Just for convenience:
                if block['hash'] not in self.block_details:
                    self.block_details[block['hash']] = {'timestamp':block['timestamp'],
                                                         'number':block['number'],
                                                         'hash':block['hash'],
                                                         'parentHash':block['parentHash'],
                                                         }
                
                print ('backtrack_unseen_block:', block['parentHash'], '->', cur_hash)
                
                cur_hash = block['parentHash']
                first_time = False

            if buf:
                print ('DOING BLOCKS:', list(reversed(buf)))
                #raw_input()

            last_block_num = False
            if self.latest_hash:
                last_block_num = self.latest_hash[2]
            
            ## Compute new state, from oldest to newest:
            
            any_wrong = False
            
            for block_num, expected_hash in reversed(buf):
                
                logs = self.bcc.get_logs_by_block_num_callback(block_num)

                if not logs:
                    ## Add noop, just so prior state gets copied:
                    logs = [{'blockHash':expected_hash, 'blockNumber':block_num, 'is_noop':True}]
                
                for log in logs:
                    if log["blockHash"] != expected_hash: ## genesis block or expected hash
                        #assert False, (log["blockHash"], expected_hash, block_num)
                        any_wrong = True
                        break
                    
                    if log["blockHash"] not in self.hh[self.table_names[0]]:
                        ## Copy state from preceding block:
                        
                        print ('backfill_unseen_block', log["blockNumber"], 'of', last_block_num, log["blockHash"])
                        
                        for table in self.table_names:
                            if (block_num == self.starting_block_num) or (log["blockHash"] == self.starting_block_hash):
                                old_state = {}
                            else:
                                old_state = deepcopy(self.hh[table][self.parent_lookup[log['blockHash']]]['s'])
                            
                            self.hh[table][log["blockHash"]] = {'h':log['blockHash'],                      ## block hash
                                                                'p':self.parent_lookup[log['blockHash']],  ## parent block hash
                                                                's':old_state,                             ## state
                                                                }
                    
                    ## Continue computing logic forward from this old state / old block:
                    
                    self.logic_callback(log,
                                        is_pending = False,
                                        is_noop = log.get('is_noop', False)
                                        )
                
                if any_wrong:
                    break
            
            if not any_wrong:
                break
    
    def store(self,
              table,                                ## Table name
              key,                                  ## Key
              value,                                ## Value
              cur_hash = False,                     ## Transaction is bound to this hash in the transaction tree.
              as_set_op = False,                    ## Do store as a set add (or remove if following flag is set) operation.
              set_remove = False,                   ## Do store as a set remove operation.
              nonce = False,                        ## Monotonically increasing nonce from the end user, determines priority.
              at_block_num = False,                 ## Store at block_num, on same chain as cur_hash. Must be < cur_hash's block_num!
              is_pending = False,                   ## Update came from pending transaction.
              is_pending_dependent_on_hash = False, ## Ignore update if this block_hash isn't in recent committed history.
              is_pending_timeout = False,           ## Ignore update if after this time limit.
              is_pending_replaces_nonce = False,    ## Either accept this update, or other update with given nonce, not both.
              ):
        """
        Low-level key-value storage. Called from `logic_callback()`. We also attach a bunch of block-tracking info
        to allow the manager to determine where this state lies on the transaction tree.
        
        General idea:
        - Compute the tree of most likely future outcomes.
        - Select a single most likely outcome chain based on all provided constraints.
        
        - maintain both sides in 1 tree:
          (read_val, read_nonce, is_pending, pending_val, pending_nonce, pending_hash, pending_timeout, pending_replaces_nonce)
        
        Only show pending side if:
        - nonce >= than read_side nonce
        - latest read_side block_num < is_pending_timeout
        - if is_pending_dependent_on_cur_hash and latest read_side has cur_hash is in its ancestors.
        
        Contract protections:
        - nonce: contract only accepts transactions with increasing (sender, nonce) and abs(nonce - time()) < 90.
        - is_pending_replaces_nonce: contract must either accept this newer (sender, nonce) transaction, or the older, but not both.
        - is_pending_dependent_on_cur_hash: contract must ensure that cur_hash is within the last 256 ancestors of current fork.
        - is_pending_timeout: contract refuses write if more than N blocks have passed since cur_hash's block num.
        
        get_failed() - to get list of stale direct for retrying (only for is_pending_bind_to_hash = False)
        
        monotonic nonces: performance.now, 
        https://developers.google.com/web/updates/2012/08/When-milliseconds-are-not-enough-performance-now
        
        """
        assert cur_hash or is_pending
        if set_remove:
            assert as_set_op

        if not is_pending:
            self._check_block_loaded(cur_hash)
        
        if is_pending:
            the_state = self.hh_pending[table]
        else:
            the_state = self.hh[table][cur_hash]['s']
        
        if nonce is not False:
            if key in the_state:
                if as_set_op:
                    old_val, old_nonce = the_state[key][value]
                else:
                    old_val, old_nonce = the_state[key]
                if old_nonce >= nonce:
                    print ('IGNORE_OLD_NONCE')
                    return False
        
        if as_set_op:
            if key not in self.hh[table][cur_hash]['s']:
                the_state[key] = {}
            if set_remove:
                the_state[value] = (False, nonce)
            else:
                the_state[key][value] = (True, nonce)
            return
        
        the_state[key] = (value, nonce)
        
        return True

    
    def lookup(self,
               table,                ## Table name.
               key,                  ## Key.
               at_hash = 'latest',   ## Consider state as of end of the block with this block hash.
               block_offset = 0,     ## Consider state as of the end of the given block offset, relative to at_hash.
               default = KeyError,   ## Default value if missing.
               allow_pending = True, ## Consider pending transactions, depending on nonces & timeouts set at store().
               ):
        """
        Low-level lookup of value in the key_value storage, as of `at_hash`.
        """
        print ('lookup', key, at_hash, block_offset, default)
        
        assert block_offset <= 0
        
        if at_hash == 'latest':
            if self.latest_hash is False:
                if default is KeyError:
                    raise KeyError
                return default
            at_hash = self.latest_hash[1]
        
        self._check_block_loaded(at_hash)
        
        use_hash = at_hash
        for x in xrange(abs(block_offset)):
            xx = self.parent_lookup[use_hash]
            if self.block_hash_to_block_num[use_hash] == self.starting_block_num:
                print 'GENESIS_BREAK'
                break
            if use_hash == self.starting_block_hash:
                print 'GENESIS_BREAK'
                break
            use_hash = xx
        
        rr = self.hh[table][use_hash]['s'].get(key, KeyError)
        
        if allow_pending:
            rr2 = self.hh_pending[table].get(key, KeyError)
        else:
            rr2 = KeyError
        
        if (rr is KeyError) and (rr2 is KeyError):
            ## lookup(s) failed:
            if default is not KeyError:
                return default
            raise KeyError
        
        elif (rr is not KeyError) and (rr2 is not KeyError):
            ## prioritize by nonces:    
            if rr2[1] > rr[1]:
                return rr2[0]
            else:
                return rr[0]
        
        elif (rr is not KeyError):
            ## confirmed:
            return rr[0]
        
        elif (rr2 is not KeyError):
            ## pending:
            return rr2[0]
        
        else:
            assert False, 'cannot get here'

    def iterate_items(self,
                      table,                ## Table name.
                      at_hash = 'latest',   ## Consider state as of end of the block with this block hash.
                      block_offset = 0,     ## Consider state as of the end of the given block offset, relative to at_hash.
                      allow_pending = True, ## Consider pending transactions, depending on nonces & timeouts set at store().
                      ):
        """
        Iterate items in a table.
        """
        print ('iterate_items', table, at_hash, block_offset, allow_pending)

        if at_hash == 'latest':
            if self.latest_hash is False:
                return []
            at_hash = self.latest_hash[1]

        k1 = self.hh[table][at_hash]['s'].keys()
        k2 = self.hh_pending[table].keys()

        rr = []
        for kk in set(k1).union(k2):
            vv = self.lookup(table,
                             kk,
                             at_hash = at_hash,
                             block_offset = block_offset,
                             allow_pending = allow_pending,
                             )
            rr.append((kk, vv))
        
        return rr
            
    

                        
def test_state():
    ## genesis parentHash = '0x0000000000000000000000000000000000000000000000000000000000000000'
    
    blocks = [{'number':1,
               'hash':'h1',
               'timestamp': 0,
               'parentHash':'h0',
               'totalDifficulty':0,
               'event_log': [1, 2],
               },
              {'number':2,
               'hash':'h2',
               'timestamp': 0,
               'parentHash':'h1',
               'totalDifficulty':1,
               'event_log': [3, 4],
               },
              {'number':3,
               'hash':'h3',
               'timestamp': 0,
               'parentHash':'h2',
               'totalDifficulty':2,
               'event_log': [5, 6],
               },
              ## Gets orphaned:
              {'number':4,
               'hash':'h4',
               'timestamp': 0,
               'parentHash':'h3',
               'totalDifficulty':3,
               'event_log': [7, 8],
               },
              ## Reorg:
              {'number':4,
               'hash':'h5',
               'timestamp': 0,
               'parentHash':'h3',
               'totalDifficulty':5,
               'event_log': [9, 10],
              },
              {'number':5,
               'hash':'h6',
               'timestamp': 0,
               'parentHash':'h5',
               'totalDifficulty':6,
               'event_log': [11, 12],
               },
              ]
    
    
    class MockApp:
        def __init__(self, sdb):
            self.sdb = sdb
            self.calls = []
            
        def logic_callback(self, log, *args, **kw):
            print ('logic_callback', log)
            
            self.calls.append(log)
            
            cur_hash = log['blockHash']
            
            action = log['data'] ## parse action(s) from data
            
            prev = sdb.lookup('table1',
                              'k',
                              at_hash = cur_hash,
                              default = 0,
                              )

            sdb.store('table1',
                      'k',
                      action + prev,
                      cur_hash = cur_hash,
                      )
    
    class MockBlockchain:
        def __init__(self,):
            self.yielded = []
            self.block_lookup = {x['number']:x for x in blocks if x['hash'] != 'h4'} ## TODO
            self.blocks_h = {x['hash']:x for x in blocks}

        def get_block_by_hash_callback(self, block_hash):
            print ('get_block_by_hash_callback', block_hash,)
            return self.blocks_h[block_hash]

        def get_logs_by_block_num_callback(self, block_num):
            print ('get_logs_by_block_num_callback', block_num)
            the_block = self.block_lookup[block_num]
            for cc, val in enumerate(the_block['event_log']):
                self.yielded.append(val)
                yield {'blockHash':the_block['hash'],
                       'blockNumber':block_num,
                       'data':val,
                       'logIndex':cc,
                       }

        def get_latest_block_callback(self):
            print ('get_latest_block_callback')
            return blocks[-1]

    
    ## Instantiate:
    
    bcc = MockBlockchain()
    
    sdb = StateManager(bcc)
    
    app = MockApp(sdb)
    
    sdb.setup_tables(table_names = ['table1'])

    sdb.setup_logic_callback(logic_callback = app.logic_callback)
    
    ## Simulate blockchain with past reorg:
    
    sdb.loop_once(break_when_caught_up = True)
    cur = sdb.lookup('table1',
                     'k',
                     )
    expected = sum([1, 2, 3, 4, 5, 6, 9, 10, 11, 12])
    print ('RESULT', 'got:', cur, 'expected:', expected)
    assert cur == expected

    ## Simulate future reorg:
    
    bcc.block_lookup[4] = bcc.blocks_h['h4']
    
    for block in [{'number':5,
                   'hash':'h7',
                   'timestamp': 0,
                   'parentHash':'h4',
                   'totalDifficulty':7,
                   'event_log': [13, 20],
                   },
                  ]:
        bcc.block_lookup[block['number']] = block
        blocks.append(block)
        bcc.blocks_h[block['hash']] = block
    
    sdb.loop_once(break_when_caught_up = True)
    cur = sdb.lookup('table1',
                     'k',
                     )
    expected = sum([1, 2, 3, 4, 5, 6, 7, 8, 13, 20])
    print ('RESULT', 'got:', cur, 'expected:', expected)
    assert cur == expected

    print ('ITER', sdb.iterate_items('table1'))
    
    if False:
        for x in bcc.yielded:
            print 'yielded', x

        for x in app.calls:
            print ('calls', x)

        for x in sorted(sdb.hh):
            print x, sdb.hh[x]


if __name__ == '__main__':
    test_state()
