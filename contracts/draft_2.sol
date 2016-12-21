

import "dev.oraclize.it/api.sol";

import "math.sol"


/*
CCCoin Voting:
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
	
	Alarm();
    }
    
    //Recurring token minting and rewards calculations. TODO: Switch to a more trustless approach:
    function Alarm() {

       oraclize_query(10 * minutes, "URL", "");
    }

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
	
	Alarm();
	
    }

    // Store votestring in event logs, to be later interpreted by web app:
    // Format: "address|direction"
    function vote(string votestring) returns (bool) {
	
	voter_id = msg.sender;
	
	// Decide whether to accept or reject vote:
	
	if (vs.lock_balances[voter_id] < ((1 * vs.pending_votes_per_user[voter_id]) ** 3) + 100) {
	    // Reject vote, not enough LOCK.
	    return false;
	}
	
	// Accept vote:
	
        vs.num_pending_votes += 1;
	
	vs.pending_votes_per_user[voter_id] += 1;

	// Distribute rewards:

	

	// Emit vote message:
	
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
