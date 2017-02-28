
force_redeploy_contract = True

contract_wrapper_args = {'start_at_current_block': True,
                         'settings_confirm_states': {'BLOCKCHAIN_CONFIRMED': 0}, ## Confirm instantly
                        }

cccoin_core_args = {'fake_id_testing_mode': True,
                    'genesis_users': ['u1','u2','u3'] ## Give these users free genesis LOCK, to bootstrap rewards.
                    }

cccoin_rewards_settings = {'REWARDS_FREQUENCY':1, ## Compute after every block.
                           'REWARDS_CURATION':1.0,##
                           'REWARDS_WITNESS':1.0, ##
                           'REWARDS_SPONSOR':1.0, ##
                           'MAX_UNBLIND_DELAY':0, ## Wait zero extra blocks for unblindings.
                           }

def test_rewards(cccoin_core):
    """
    Variety of tests for the rewards function.
    """

    cccoin_core.test_feed_round([
        {'user_id':'u3','action':'post','use_id':'p1','image_title':'a'},
        {'user_id':'u3','action':'post','use_id':'p2','image_title':'b'}
        ])

    cccoin_core.test_feed_round([
        {'user_id':'u1','action':'vote','item_id':'p1','direction':1},
        {'user_id':'u2','action':'vote','item_id':'p2','direction':1},
        ])

    ## u1 should have a vote reward, u3 should have a post reward:
    u1 = cccoin_core.map_fake_to_real_user_ids['u1']
    u3 = cccoin_core.map_fake_to_real_user_ids['u3']
    u1_rewards = cccoin_core.confirmed_owed_rewards_lock.lookup('u1', default=None)
    u3_rewards = cccoin_core.confirmed_owed_rewards_lock.lookup('u3', default=None)

    # TODO: doesn't seem like I'm testing the right thing here..
    #assert(u1_rewards is not None)
    #assert(u3_rewards is not None)