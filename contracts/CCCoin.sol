pragma solidity ^0.4.2;

import "dev.oraclize.it/api.sol";

import "math.sol"


/*
*/

contract NewCCCoin is usingOraclize {

    // Constants:

    uint const CONST_BLOCK_INTERVAL = 10 * minutes; // How frequent 
    uint const CONST_LOCK_PERCENT = 1.001; // Percent that LOCK appreciates per block.
    uint const CONT_LOCK_PAYOUTS = 20;     // Number of LOCK interest payouts.
    uint const CONST_MIN_VEST = 100;       // Minimum amount that can vest, to mitigate vesting payout costs.
    uint const CONST_MIN_GAS = 100;        // Minimum gas needed to run some operations and schedule next alarm.
    
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

	uint global_rewards_today;
	
    }
    
    // Storing votes to event log:
    event StoreVote(string votestring);
    event StoreSealedVote(string vote_hash);
    event StoreUnsealedVote(string vote_hash, string unsealed_vote);
    
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
       oraclize_query(CONST_BLOCK_INTERVAL, "URL", "");
    }
    
    // Callback for alarm oracle:
    function __callback(bytes32 myid, string result) {
        if (msg.sender != oraclize_cbAddress()) throw;

	start_gas = msg.gas;
	kill_gas = min(msg.gas / 2, block.gasLimit() / 2); // kill contract when it reaches this amount
	
	if (start_gas - kill_gas < CONST_MIN_GAS) {
	    throw;
	}
	
	// CURATION REWARDS:

	vs.curation_iter += 1;

	if (vs.curation_iter >= pending_items.length){
	    vs.curation_iter = 0;
	}
	
	portion = 100 / tot_pending_power;
	
	x_item = pending_items[vs.curation_iter];
	
	for (j = 0; j < early_voters[x_item].length; i++){
	    
	    x_voter = early_voters[x_item][j];
	    
	    balances[x_voter] += portion * pending_power[x_item];
	    
	    if (msg.gas <= kill_gas) {
		ScheduleAlarm();
		return true;
	    }
	}
	
	// LOCK UPDATES:
	
	vs.cur_track_lock_iter += 1;

	if (vs.cur_track_lock_iter >= track_lock_users.length){
	    vs.cur_track_lock_iter = 0;
	}
		    
	user_id = track_lock_users[vs.cur_track_lock_iter];

	if (user_id == 0){
	    continue;
	}
	
	for (j=0; j < vs.track_lock_times[user_id].length; j++){
	    stm = vs.track_lock_start_times[user_id][vs.cur_track_lock_iter];
	    ltm = vs.track_lock_last_times[user_id][vs.cur_track_lock_iter];
	    am = vs.track_lock_amounts[user_id][vs.cur_track_lock_iter];
	    
	    num_payouts = (now - ltm) / ;
	    
	    if (now - tm < CONST_BLOCK_TIME){
		vs.lock_balances[user_id] *= CONST_LOCK_PERCENT;
		vs.track_lock_last_times[user_id] = now;
		vs.track_payouts[user_id] += 1;

		if (vs.track_payouts[user_id] > CONST_LOCK_PAYOUTS) {
		    // payout done, delete user:
		    track_lock_users[vs.cur_track_lock_iter] = 0;
		}
		
	    }

	    if (msg.gas <= kill_gas) {
		ScheduleAlarm();
		return true;
	    }
	    
	}
	
	
	
	if (msg.gas <= kill_gass) {
	    ScheduleAlarm();
	    return true;
	}

	
	
	ScheduleAlarm();
	return true;
    }
    
    
    // Start vesting of some TOK:
    function vest(uint amount) {

	if (amount < CONST_MIN_VEST){
	    throw;
	}
	
	if (amount > vs.tok_balances[msg.sender]) {
	    throw;
	}

	vs.track_lock_num += 1;
	vs.track_lock_users.push(msg.sender);
	vs.track_lock_times[msg.sender].push(now);
	vs.track_lock_amounts[msg.sender].push(amount);
	
	vs.lock_balances[msg.sender] += amount;
	vs.tok_balances[msg.sender] -= amount;
	
    }

    /*
      1) After at least 1 block has passed, sealed votes submitted.
     */
    function vote_sealed(string vote_hash) {
	
	voter_id = msg.sender;
	
	// Accept or reject vote, based on user's LOCK balance:
	
	if (vs.lock_balances[voter_id] < ((1 * vs.pending_votes_per_user[voter_id]) ** 3) + 100) {
	    // Reject vote, not enough LOCK.
	    return false;
	}

	vs.num_pending_votes += 1;
	
	vs.pending_votes_per_user[voter_id] += 1;

	vs.sealed_votes[vote_hash] = now;
	
	StoreSealedVote(vote_hash);
    }
    
    /*
      1) Unseal previously sealed vote.
      2) Operate on votes in order of rewards size.
     */
    function vote_sealed(string vote_hash, string unsealed_vote) {
	
	voter_id = msg.sender;
	
	
	// Reject if not enough LOCK:
	if (vs.lock_balances[voter_id] < ((1 * vs.pending_votes_per_user[voter_id]) ** 3) + 100) {
	    throw;
	}

	// Ensure previously sealed vote exists:
	if (vs.sealed_votes[vote_hash] == 0) {
	    throw;
	}

	// Ignore invalidly sealed votes:
	if (sha3(vote_hash) != unsealed_vote) {
	    throw;
	}

	// Record:
	StoreUnsealedVote(vote_hash, unsealed_vote);

	// Reward all previous voters:

	uint tm = now;
	
	//uint bin = Math.floor(tm / (1 hour)) % (1 hour);
	//uint pct_of_hour = math.floor(tm / (1 hour)) - (tm / (1 hour));

	//vs.lock_power_hourly[bin] += vs.lock_balances[voter_id];

	uint pct_of_day = Math.floor(tm / (1 day)) - (tm / (1 day));
	
	vs.lock_power_daily_today += vs.lock_balances[voter_id];
	
	if ((vs.all_votes_num[unsealed_vote] % 50 == 0) && ( vs.last_rewards_amount[unsealed_vote])){

	    // iterate previous voters, until gas is no longer worth it:
	    
	    // TODO - rewards from simulator.
	    
	}

	
	
    }
    

    /*
      Store vote in event logs, to be later interpreted by web app:
        direction == 1: upvote
        direction == 0: cancel upvote
    */
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
	    median_daily_curation_rewards = 100 * 10;
	    all_votes_num[item_id] += 1;
	    global_votes_num += 1;
	    
	    // Calcuate total rewards for this item:

	    this_hour = Math.floor(now / 60 / 60);

	    end_of_day = Math.floor(now + 1 days)
	    
	    // TODO, about to swap for another:
	    
	    this_reward = ((end_of_day - now) / one_day) / (all_power_pending[item_id] / global_pending_power) / (global_rewards_today / median_daily_curation_rewards);
	    
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

		global_rewards_today += this_reward;

	    }
	    

	}
	
	// Emit vote event:

	string votestring = item_id;

	
	//string locked_vote = sha3(votestring)
	
        //StoreLockedVote(locked_vote);

	StoreVote(locked_vote);
	
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
