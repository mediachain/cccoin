#!/usr/bin/env python

"""
Temporal chain database, and chain fork consensus.

TODO - Also create version with SQL backend.
"""


from sys import maxint
import threading
import multiprocessing

##
## BUG1 means,
##
## When you have nested manager.dict()'s, instead of:
##  h['a']['b'] = 'c'
##
## You must instead do this:
##   y = h['a']
##   y['b'] = 'c'
##   h = y
##

class TemporalTable:
    """
    Temporal in-memory database. Update and lookup historical values of a key.    
    """
    
    def __init__(self,
                 process_safe = True,
                 ):
        self.process_safe = process_safe
        
        if self.process_safe:
            self.manager = multiprocessing.Manager()
            self.process_safe = True
            self.the_lock = self.manager.RLock()
            self.hh = self.manager.dict()
            self.current_latest = self.manager.dict()
            self.all_block_nums = self.manager.dict()
            self.largest_pruned = self.manager.Value('i', -maxint)
        else:
            self.process_safe = False
            self.the_lock = threading.RLock()
            self.hh = {}             ## {key:{block_num:value}}
            self.current_latest = {} ## {key:block_num}
            self.all_block_nums = {} ## set, but have to use dict
            self.largest_pruned = -maxint

    def _get_largest_pruned(self):
        if self.process_safe:
            return self.largest_pruned.value
        else:
            return self.largest_pruned
        
    def _set_largest_pruned(self, val):
        if self.process_safe:
            self.largest_pruned.value = val
        else:
            self.largest_pruned = val
        
    def store(self, key, value, start_block, as_set_op = False):
        """ """
        
        assert start_block != -maxint, 'ERROR: -MAXINT IS RESERVED'

        print ('STORE', key, value)
        
        with self.the_lock:
            if key not in self.hh:
                if self.process_safe:
                    self.hh[key] = self.manager.dict()
                    #self.hh[key][start_block] = value
                    ## BUG1:
                    tm = self.hh[key]
                    tm[start_block] = value
                    self.hh[key] = tm                    
                else:
                    self.hh[key] = {}

            if as_set_op:
                if start_block not in self.hh[key]:
                    if self.process_safe:
                        ## BUG1:
                        #self.hh[key][start_block] = self.manager.dict()
                        tm = self.hh[key]
                        tm[start_block] = self.manager.dict()
                        self.hh[key] = tm
                    else:
                        self.hh[key][start_block] = {}
                ## BUG1:
                #self.hh[key][start_block][value] = True ## Must have already setup in previous call.
                tm = self.hh[key]
                tm2 = tm[start_block]
                tm2[value] = True ## Must have already setup in previous call.
                tm[start_block] = tm2
                self.hh[key] = tm
            else:
                #self.hh[key][start_block] = value
                ## BUG1:
                tm = self.hh[key]
                tm[start_block] = value
                self.hh[key] = tm

            self.current_latest[key] = max(start_block, self.current_latest.get(key, -maxint))

            self.all_block_nums[start_block] = True
        
    def remove(self, key, value, start_block, as_set_op = False):
        with self.the_lock:
            if as_set_op:
                ## BUG1:
                #del self.hh[key][start_block][value] ## Must have already setup in previous call.
                tm = self.hh[key]
                tm2 = tm[start_block]
                del tm2[value]
                tm[start_block] = tm2
                self.hh[key] = tm
            else:
                ## BUG1:
                #del self.hh[key][start_block]
                tm = self.hh[key]
                del tm[start_block]
                self.hh[key] = tm
    
    def lookup(self, key, start_block = -maxint, end_block = 'latest', default = KeyError, with_block_num = True):
        """ Return only latest, between start_block and end_block. """

        assert with_block_num
        
        with self.the_lock:
            
            if (start_block > -maxint) and (start_block <= self._get_largest_pruned()):
                assert False, ('PREVIOUSLY_PRUNED_REQUESTED_BLOCK', start_block, self._get_largest_pruned())

            if (key not in self.hh) or (not self.hh[key]):
                if default is KeyError:
                    raise KeyError
                if with_block_num:
                    return default, False
                else:
                    return default

            ## Latest:

            if end_block == 'latest':
                end_block = self.current_latest[key]

            ## Exactly end_block:

            if start_block == end_block:
                if end_block in self.hh[key]:
                    if with_block_num:
                        return self.hh[key][end_block], start_block
                    else:
                        return self.hh[key][end_block]

            ## Closest <= block_num:

            for xx in sorted(self.hh.get(key,{}).keys(), reverse = True):
                if xx > end_block:
                    continue
                if xx < start_block:
                    continue
                if with_block_num:
                    return self.hh[key][xx], xx
                else:
                    return self.hh[key][xx]
            else:
                if default is KeyError:
                    raise KeyError
                if with_block_num:
                    return default, False
                else:
                    return default

            assert False,'should not reach'
            
    def iterate_block_items(self, start_block = -maxint, end_block = 'latest'):
        """ Iterate latest version of all known keys, between start_block and end_block. """
        with self.the_lock:
            for kk in self.current_latest.keys():
                try:
                    rr, bn = self.lookup(kk, start_block, end_block)
                except:
                    ## not yet present in db
                    continue
                yield (kk, rr)
                
    def prune_historical(self, end_block):
        """ Prune ONLY OUTDATED records prior to and including `end_block`, e.g. to clear outdated historical state. """
        with self.the_lock:
            for key in self.hh.keys():
                for bn in sorted(self.hh.get(key,{}).keys()):
                    if bn > end_block:
                        break
                    ## BUG1:
                    #del self.hh[key][bn]
                    tm = self.hh[key]
                    del tm[bn]
                    self.hh[key] = tm
                    
            self._set_largest_pruned(max(end_block, self.largest_pruned))
        
    def wipe_newer(self, start_block):
        """ Wipe blocks newer than and and including `start_block` e.g. for blockchain reorganization. """
        with self.the_lock:
            for key in self.hh.keys():
                for bn in sorted(self.hh.get(key,{}).keys(), reverse = True):
                    if bn < start_block:
                        break
                    ## BUG1:
                    #del self.hh[key][bn]
                    tm = self.hh[key]
                    del tm[bn]
                    self.hh[key] = tm



class TemporalForks:
    """
    A collection of `TemporalTable`s, one for each fork being tracked.

    Lookup latest state, resolved from multiple forks.

    Discard keys from direct that never got confirmed within max_confirm_time.
    """
    def __init__(self,
                 master_name,      ## 'name'
                 fork_names,       ## ['name']
                 max_non_master_age = False,
                 ):
        """
        - master_name: name of master fork
        - max_non_master_age: number of blocks before non-master blocks expire.
        """
        
        self.ANY_FORK = 'ANY_FORK'
        
        assert master_name in fork_names
        assert self.ANY_FORK not in fork_names
        
        manager = multiprocessing.Manager()

        self.forks = {} ## Doesn't ever change after this function, so regular dict.
        
        for fork in fork_names:
            self.forks[fork] = TemporalTable(process_safe = True)
        
        self.master_name = master_name
        self.max_non_master_age = max_non_master_age
        self.latest_master_block_num = manager.Value('i', -maxint)
        
        self.the_lock = manager.RLock()

        
    def update_latest_master_block_num(self, block_num):
        with self.the_lock:
            self.latest_master_block_num.value = max(block_num, self.latest_master_block_num.value)
        
    def store(self, fork_name, *args, **kw):
        """ store in specific fork """
        with self.the_lock:

            if True:
                 ## You should still do this manually too:
                if 'start_block' in kw:
                    sb = kw['start_block']
                else:
                    sb = args[2]
                self.update_latest_master_block_num(sb)
            
            if fork_name == self.ANY_FORK:
                assert False, 'really store in all forks?'
            else:
                assert fork_name in self.forks
                self.forks[fork_name].store(*args, **kw)
    
    def remove(self, fork_name, *args, **kw):
        """ remove just from specific fork """
        with self.the_lock:
            if fork_name == self.ANY_FORK:
                for fork_name, fork in self.forks.items():
                    fork.remove(*args, **kw)
            else:
                assert fork_name in self.forks
                self.forks[fork_name].remove(*args, **kw)
    
    def lookup(self, fork_name, key, start_block = -maxint, end_block = 'latest', default = KeyError):
        """ Lookup latest non-expired from any fork. """
        with self.the_lock:
            
            if fork_name != self.ANY_FORK:
                assert fork_name in self.forks
                return self.forks[fork_name].lookup(key = key,
                                                    start_block = start_block,
                                                    end_block = end_block,
                                                    default = default,
                                                    )
            
            assert self.latest_master_block_num.value != -maxint, 'Must call self.update_latest_master_block_num() first.'
            
            biggest_num = -maxint
            biggest_val = False

            start_block_non_master = start_block
            
            if self.max_non_master_age is not False:
                start_block_non_master = max(self.latest_master_block_num.value - self.max_non_master_age,
                                             start_block,
                                             )            
            
            for fork_name, fork in self.forks.items():

                if fork_name != self.master_name:
                    x_start_block = start_block_non_master
                else:
                    x_start_block = start_block
                
                try:
                    val, block_num = fork.lookup(key = key,
                                                 start_block = x_start_block,
                                                 end_block = end_block,
                                                 default = KeyError,
                                                 )
                    print 'FORK', fork_name, x_start_block, val, block_num
                except KeyError:
                    continue
                
                if block_num > biggest_num:
                    biggest_num = block_num
                    biggest_val = val
                            
            if biggest_num == -maxint:
                if default is KeyError:
                    raise KeyError
                return default, False
            
            return biggest_val, biggest_num
    
    def iterate_block_items(self, fork_name, *args, **kw):
        with self.the_lock:
            
            if fork_name != self.ANY_FORK:
                assert fork_name in self.forks
                for xx in self.forks[fork_name].iterate_block_items(*args, **kw):
                    yield xx
            
            do_keys = set()
            
            for fork_name, fork in self.forks.items():                
                   do_keys.update(fork.current_latest.keys()) 
            
            for kk in do_keys:
                try:
                    rr, bn = self.lookup(kk, start_block, end_block)
                except:
                    ## not yet present in db
                    continue
                yield (kk, rr)
    
    def prune_historical(self, fork_name, *args, **kw):
        with self.the_lock:
            if fork_name != self.ANY_FORK:
                assert fork_name in self.forks
                return self.forks[fork_name].prune_historical(*args, **kw)

            for fork_name, fork in self.forks.items():                
                fork.prune_historical(*args, **kw)
            
    def wipe_newer(self, fork_name, *args, **kw):
        with self.the_lock:
            if fork_name != self.ANY_FORK:
                assert fork_name in self.forks
                return self.forks[fork_name].wipe_newer(*args, **kw)

            for fork_name, fork in self.forks.items():                
                fork.wipe_newer(*args, **kw)


            
def test_temporal_table():
    print ('START test_temporal_table()')
    xx = TemporalTable()
    xx.store('a', 'b', start_block = 1)
    assert xx.lookup('a')[0] == 'b', xx.lookup('a')[0]
    xx.store('a', 'c', start_block = 3)
    assert xx.lookup('a')[0] == 'c', xx.lookup('a')[0]
    xx.store('a', 'd', start_block = 2)
    assert xx.lookup('a')[0] == 'c', xx.lookup('a')[0]
    assert xx.lookup('a', end_block = 2)[0] == 'd', xx.lookup('a', end_block = 2)[0]
    xx.store('e','h',1)
    xx.store('e','f',2)
    xx.store('e','g',3)
    assert tuple(xx.iterate_block_items()) == (('a', 'c'), ('e', 'g'))
    assert tuple(xx.iterate_block_items(end_block = 1)) == (('a', 'b'), ('e', 'h'))
    print ('PASSED')


def test_temporal_forks():
    print ('START test_temporal_forks()')
    xx = TemporalForks(master_name = 'fork1', fork_names = ['fork1', 'fork2'])
    xx.update_latest_master_block_num(1)
    xx.store('fork1', 'a', 'b', start_block = 1)
    assert xx.lookup('fork1', 'a')[0] == 'b'
    xx.update_latest_master_block_num(3)
    xx.store('fork1', 'a', 'c', start_block = 3)
    assert xx.lookup('fork1', 'a')[0] == 'c'
    xx.update_latest_master_block_num(2)
    xx.store('fork1', 'a', 'd', start_block = 2)
    assert xx.lookup('fork1', 'a')[0] == 'c'
    assert xx.lookup('fork1', 'a', end_block = 2)[0] == 'd'
    xx.update_latest_master_block_num(1)
    xx.store('fork1', 'e','h',1)
    xx.update_latest_master_block_num(2)
    xx.store('fork1', 'e','f',2)
    xx.update_latest_master_block_num(3)
    xx.store('fork1', 'e','g',3)
    assert tuple(xx.iterate_block_items('fork1')) == (('a', 'c'), ('e', 'g'))
    assert tuple(xx.iterate_block_items('fork1', end_block = 1)) == (('a', 'b'), ('e', 'h'))
    print ('PASSED_BASIC')

    xx = TemporalForks(master_name = 'fork1', fork_names = ['fork1', 'fork2'], max_non_master_age = 5)
    xx.update_latest_master_block_num(1)
    xx.store('fork1', 'z', 'e', start_block = 1)
    xx.update_latest_master_block_num(2)
    xx.store('fork2', 'z', 'g', start_block = 2)
    assert xx.lookup('ANY_FORK', 'z')[0] == 'g'
    xx.update_latest_master_block_num(50)
    assert xx.lookup('ANY_FORK', 'z')[0] == 'e'

    print ('PASSED_FORKS')

if __name__ == '__main__':
    test_temporal_table()
    test_temporal_forks()
