#!/usr/bin/env python

from random import choice
from time import time

import numpy as np
import scipy.stats as stats
import matplotlib.pyplot as plt

def truncated_power_law(a, m):
    x = np.arange(1, m+1, dtype='float')
    pmf = 1/x**a
    pmf /= pmf.sum()
    return stats.rv_discrete(values=(range(1, m+1), pmf))

def make_votes(N = 50):
    a, m = 2, 10
    d = truncated_power_law(a=a, m=m)
    sample = d.rvs(size=N)
    return sample

def doit():


    CONST_CURATION_DAILY = 2.5

    minute = 60
    hour = 60 * 60
    day = 60 * 60 * 24

    lock_power_daily_today = 0

    item_ids = ['i' + str(x) for x in range(10)]
    voter_ids = ['v' + str(x) for x in range(10)]
    
    lock_power_daily_avg = sum([sum(make_votes(24)) for x in xrange(100)]) / 100.0 ## cheat to get good estimate for first day

    print ('lock_power_daily_avg', lock_power_daily_avg)
    
    past_voters = {} ## {item_id:[voter_id, ...]}
    past_lock = {} ## {item_id:[lock_amount, ...]}
    rr = {}

    tm = time()
    
    power_hist = [0] * (24 * 60)
    power_num = [0] * (24 * 60)
    
    prev_key = -1
    for  xc, p in enumerate(make_votes(24 * 60)):
        cur_key = int((tm + xc * 60) / 60) % (24 * 60)
        #print 'cur_key', cur_key, tm + xc, int((tm + xc * 60) / 60)
        if cur_key == prev_key:
            power_hist[cur_key] += p
            power_num[cur_key] += 1
        else:
            power_hist[cur_key] = p
            power_num[cur_key] = 1
        prev_key = cur_key
    
    print ('power_hist', power_hist)
    
    tm += 2 * day

    prev_key = -1
    for c, user_lock_size in enumerate(make_votes(60 * 24 * 10)):
        
        voter_id = choice(voter_ids)
        item_id = choice(item_ids) #item_ids[make_votes(len(item_ids))[0]] ## TODO..
        
        if item_id not in past_voters:
            past_voters[item_id] = []
            
        if item_id not in past_lock:
            past_lock[item_id] = []
        
        tm += 1 * minute
        
        cur_day = int(tm / (1 * day))

        cur_key = int(tm / 60) % (24 * 60)
        if cur_key == prev_key:
            power_hist[cur_key] += user_lock_size
            power_num[cur_key] += 1
        else:
            power_hist[cur_key] = user_lock_size
            power_num[cur_key] = 1
        prev_key = cur_key
        
        lock_power_past_24h = float(sum(power_hist))# / sum(power_num)
        
        tot_reward = lock_power_daily_avg / lock_power_past_24h * CONST_CURATION_DAILY * (user_lock_size / lock_power_daily_avg)

        if False:
            print ('user_lock_size:', user_lock_size,
                   'lock_power_daily_avg:', lock_power_daily_avg,
                   'lock_power_past_24h', lock_power_past_24h,
                   'tot_reward:', tot_reward,
                   )
        
        tot_past = float(sum(past_lock[item_id]))

        rr[cur_day] = rr.get(cur_day, 0) + tot_reward
        
        ## Immediately distribute reward to past voters, until gas fees no longer worth it:
        
        for cc, xlock in enumerate(past_lock[item_id]):
            
            reward = (xlock / tot_past) * tot_reward

            if False:
                print ('YY', 'c:', c, 'cc:', cc, 'cur_day:', cur_day, 'tot_reward:', tot_reward, 'reward:', reward)
        
        past_voters[item_id].append(voter_id)
        past_lock[item_id].append(user_lock_size)
    
    print rr

    print ('AVG', sum(rr.values()) / float(len(rr)))

    print 'plotting...'
    
    plt.hist(rr.values(), bins=10)
    plt.show()

    
if __name__ == '__main__':
    doit()
