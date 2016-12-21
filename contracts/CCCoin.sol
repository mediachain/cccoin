pragma solidity ^0.4.2;

import "dev.oraclize.it/api.sol";

import "math.sol"


/*
*/

contract NewCCCoin is usingOraclize {
    
    // Voting shard definition:
    struct VoteShard {
        address owner;
        string name;
        string options;
        bool status;
	
	address[] public prev_voted;
	address[] public voted;
	
	uint num_pending_votes;
	mapping (address => uint) pending_votes_per_user;
	
	uint num_pending_submits;
	mapping (address => uint) pending_submits_per_user;

	string[] pending_votes;
	
	mapping (string => uint) user_and_vote_to_old_reward; // total LOCK for this post at time when vote was made.
	
	mapping (string => uint) item_total_rewards; // total rewards on item.
	
	
	mapping (string => address[]) early_voters; // {item_id:[voter_1, voter_2, ...]}

	string[] pending_items;
	mapping (string => address[]) pending_votes;// {item_id:[voter_1, voter_2, ...]}

	uint tot_pending_power;
	mapping (string => uint) pending_power; // {item_id:power}

	//

	uint global_votes_num;
	
	mapping (string => mapping (string => uint)) all_votes_mapping; // {item_id:{voter:int}}
	mapping (string => uint) all_votes_num;                         // {item_id:int}
	mapping (string => uint) all_votes_power;                       // {item_id:int}
	mapping (string => uint) last_rewards_time;                     // {item_id:int}
	
	mapping (string => address[50]) all_votes_first;                // {item_id:[voter, voter, voter]}
	mapping (string => address[50]) all_votes_last;                  // {item_id:[voter, voter, voter]}

	
    }
    
    // Storing vote to event log:
    event StoreVote(string votestring);
    
    // Public VoteShard called vs:
    VoteShard public vs;

    // 
    mapping (address => item_id) voters_to_items;
    
    // Setup this voting shard:
    function NewVoteShard(string x_options, string x_name, uint _votelimit) {
        vs.owner = msg.sender;
        vs.title = x_name;
        vs.options = x_options;
	
	//ScheduleAlarm();
    }
    
    // Recurring token minting and rewards calculations. TODO: Note, not so trustless:
    function ScheduleAlarm() {
       oraclize_query(10 * minutes, "URL", "");
    }

    // Callback for alarm oracle:
    function __callback(bytes32 myid, string result) {
        if (msg.sender != oraclize_cbAddress()) throw;

	// Minting & Rewards:
	
	portion = 100 / tot_pending_power;
	
	for (i = 0; i < pending_items.length; i++){

	    x_item = pending_items[i];
	    
	    for (j = 0; j < early_voters[x_item].length; i++){

		x_voter = early_voters[x_item][j];

		balances[x_voter] += portion * pending_power[x_item];
	    }
	    
	}
	
	// Recurse:
	
	ScheduleAlarm();
    }

    // Store vote in event logs, to be later interpreted by web app:
    // direction == 1: upvote
    // direction == 0: cancel upvote
    function vote(string item_id, bool direction) returns (bool) {

	// NOTE: Not yet ready.
	
	voter_id = msg.sender;
	
	// Accept or reject vote, based on user's LOCK balance:
	
	if (vs.lock_balances[voter_id] < ((1 * vs.pending_votes_per_user[voter_id]) ** 3) + 100) {
	    // Reject vote, not enough LOCK.
	    return false;
	}
	
	// Accept vote:
	
        vs.num_pending_votes += 1;
	
	vs.pending_votes_per_user[voter_id] += 1;
	
	// Distribute rewards, to first 50 and last 50:
	
	if (all_votes_mapping[item_id][voter_id] == 0){
	    
	    if (all_votes_first[item_id].length < 50) {
		// First 50 voters:
		all_votes_first[item_id].push(voter_id);
	    }
	    else {
		// Last 50 voters:
		all_votes_last[item_id][all_votes_num[item_id] % 50] = voter_id;
	    }
	    
	    all_votes_power[item_id] += lock_balances[msg.sender];
	    pending_votes_power[item_id] += lock_balances[msg.sender];
	    pending_global_power += lock_balances[msg.sender];
	    all_votes_num[item_id] += 1;
	    global_votes_num += 1;
	    
	    // Calcuate total rewards for this item:

	    this_hour = int(now / 60 / 60);

	    one_day = 60 * 60 * 24;
	    
	    end_of_day = int(now + one_day)
	    
	    this_reward = (all_power_pending[item_id] / global_pending_power) / ((end_of_day - now) / one_day) / (target_daily_curation_rewards / median_daily_curation_rewards);
	    
	    // Distribute rewards, every: max(50 votes, 10 minutes):
	    
	    if ((all_votes_num[item_id] % 50 == 0) && (now - last_rewards_time[item_id] > 60 * 10)){

		// iterate voters:
		
		for (i = 0; i < all_votes_first[item_id].length; i++){
		    
		    xvoter = all_votes_first[item_id][i];
		    user_power = all_votes_power_first[item_id][i];
		    total_power = all_votes_power[item_id];
		    
		    // Voter didn't delete vote:
		    
		    if (xvoter != 0){
			
			lock_balances[xvoter] += (xpower / this_reward);
			
			pending_global_power -= xpower;
			pending_votes_power[item_id] -= xpower;
		    }
		}
		
		last_rewards_time[item_id] = now;
	    
	    }
	    

	}
	
	// Emit vote event:

	string votestring = item_id;
	
        StoreVote(votestring);
	
        return true;
    }

    
    // 
    function createHumanStandardToken(uint256 _initialAmount, string _name, uint8 _decimals, string _symbol) returns (address) {
	
        HumanStandardToken newToken = (new HumanStandardToken(_initialAmount, _name, _decimals, _symbol));
        created[msg.sender].push(address(newToken));
        isHumanToken[address(newToken)] = true;
        newToken.transfer(msg.sender, _initialAmount); //the factory will own the created tokens. You must transfer them.
        return address(newToken);
    }


    
    function transferOwnership(address newOwner) {
        if (msg.sender != vs.owner) {
	    return;
	}
        vs.owner = newOwner;
    }

    
}
