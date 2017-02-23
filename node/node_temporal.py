#!/usr/bin/env python

"""
TODO - Also create version with SQL backend.
"""

from sys import maxint

class TemporalTable:
    """
    Temporal in-memory database. Update and lookup historical values of a key.    
    """
    
    def __init__(self,):
        self.hh = {}             ## {key:{block_num:value}}
        self.current_latest = {} ## {key:block_num}
        self.all_block_nums = set()
        self.largest_pruned = -maxint
        
    def store(self, key, value, start_block, as_set_op = False):
        """ """
        if key not in self.hh:
            self.hh[key] = {}
            
        if as_set_op:
            if start_block not in self.hh[key]:
                self.hh[key][start_block] = set()
            self.hh[key][start_block].add(value) ## Must have already setup in previous call.
        else:
            self.hh[key][start_block] = value
            
        self.current_latest[key] = max(start_block, self.current_latest.get(key, -maxint))

        self.all_block_nums.add(start_block)
        
    def remove(self, key, value, start_block, as_set_op = False):
        if as_set_op:
            self.hh[key][start_block].discard(value) ## Must have already setup in previous call.
        else:
            del self.hh[key][start_block]
    
    def lookup(self, key, start_block = -maxint, end_block = 'latest', default = KeyError):
        """ Return only latest, between start_block and end_block. """

        if (start_block > -maxint) and (start_block <= self.largest_pruned):
            assert False, ('PREVIOUSLY_PRUNED_REQUESTED_BLOCK', start_block, self.largest_pruned)
        
        if (key not in self.hh) or (not self.hh[key]):
            if default is KeyError:
                raise KeyError
            return default

        ## Latest:
        
        if end_block == 'latest':
            end_block = self.current_latest[key]
        
        ## Exactly end_block:

        if start_block == end_block:
            if end_block in self.hh[key]:
                return self.hh[key][end_block]
        
        ## Closest <= block_num:
        
        for xx in sorted(self.hh.get(key,{}).keys(), reverse = True):
            if xx > end_block:
                continue
            if xx < start_block:
                continue
            return self.hh[key][xx]
        else:
            if default is KeyError:
                raise KeyError
            return default

    def iterate_block_items(self, start_block = -maxint, end_block = 'latest'):
        """ Iterate latest version of all known keys, between start_block and end_block. """
        
        for kk in self.current_latest:
            try:
                rr = self.lookup(kk, start_block, end_block)
            except:
                ## not yet present in db
                continue
            yield (kk, rr)
    
    def prune_historical(self, end_block):
        """ Prune ONLY OUTDATED records prior to and including `end_block`, e.g. to clear outdated historical state. """
        for key in self.hh.keys():
            for bn in sorted(self.hh.get(key,{}).keys()):
                if bn > end_block:
                    break
                del self.hh[key][bn]
        self.largest_pruned = max(end_block, self.largest_pruned)
        
    def wipe_newer(self, start_block):
        """ Wipe blocks newer than and and including `start_block` e.g. for blockchain reorganization. """
        for key in self.hh.keys():
            for bn in sorted(self.hh.get(key,{}).keys(), reverse = True):
                if bn < start_block:
                    break
                del self.hh[key][bn]

            
def test_temporal_table():
    print ('test_temporal_table()')
    xx = TemporalTable()
    xx.store('a', 'b', start_block = 1)
    assert xx.lookup('a') == 'b'
    xx.store('a', 'c', start_block = 3)
    assert xx.lookup('a') == 'c'
    xx.store('a', 'd', start_block = 2)
    assert xx.lookup('a') == 'c'
    assert xx.lookup('a', end_block = 2) == 'd'
    xx.store('e','h',1)
    xx.store('e','f',2)
    xx.store('e','g',3)
    assert tuple(xx.iterate_block_items()) == (('a', 'c'), ('e', 'g'))
    assert tuple(xx.iterate_block_items(end_block = 1)) == (('a', 'b'), ('e', 'h'))
    print ('PASSED')

if __name__ == '__main__':
    test_temporal_table()
