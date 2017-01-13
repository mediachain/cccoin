pragma solidity ^0.4.0;

contract CCCoin {

   // This declares a user participating in the upvoting
   struct User {
     bytes32 username;
     bool created;
     uint time_created;
     uint block_created;
     uint tok;
     uint lock;
     uint time_num_recent_votes;
     uint num_recent_votes;
     uint block_num_recent_posts;
     uint num_recent_posts;
     uint reward_points;
   }

   // This declares an item type for a posted item, and its state
   struct Item {
     bytes32 itemname;
     uint time_created;
     uint block_created;
     User posted_by;
//     uint reward_points;
     uint votes;
   }

   address public root;      // creator of this contract

   mapping(address => User) public users;  // User struct for each address
   bytes32[] knownUsers;   // names of known users
   address[] knownAddrs;   // addrs of known users

   Item[] items;           // dynamically sized array of Items

   uint lastnonce;         // trivial nonce

   // create a user, making sure that its address and name have not
   // already been used

   function createUser(bytes32 name) returns (bool) {
     address xr = msg.sender;
     if ( xr != root )
       return false;
     User u = users[xr];
     if ( u.created == true )
       return false;
     for (uint i=0; i < knownUsers.length; i++) {
       if ( knownUsers[i] == name )
         return false;
     }
     u.username = name;
     knownUsers.push(name);
     knownAddrs.push(xr);
     u.created = true;
     u.time_created = now;
     u.block_created = block.number;
     u.tok = 25 * 1000 finney;
     u.lock = 0;
     u.time_num_recent_votes = u.time_created;
     u.num_recent_votes = 0;
     u.block_num_recent_posts = u.block_created;
     u.num_recent_posts = 0;
     u.reward_points = 0;
     return true;
   }

   // get the TOK balance for the current user

   function getTOK() returns (uint) {
     address user = msg.sender;
     User u = users[user];
     if ( u.created == false )
       throw;
     uint x = u.tok;
     return x;
   }

   // get the lock balance for the current user

   function getLOCK() returns (uint) {
     address user = msg.sender;
     User u = users[user];
     if ( u.created == false )
       throw;
     uint x = u.lock;
     return x;
   }

   // transfer xtok TOK (which could be 0) and/or xlock LOCK (which could
   // be 0), from the current user to the range of addresses given

   function transfer(uint xtok, uint xlock, address[] tos)
   returns (bool) {
     address from = msg.sender;
     User u = users[from];
     if ( u.created == false )
       return false;
     uint totxtok = xtok * (tos.length);
     uint totxlock = xlock * (tos.length);
     if ( totxtok > u.tok )
       return false;
     if ( totxlock > u.lock )
       return false;
     uint success = 0;
     for (uint i=0; i < tos.length; i++) {
       User t = users[tos[i]];
       if ( t.created == false )
         continue;
       t.tok += xtok;
       t.lock += xlock;
       success++;
     }
     if ( success == 0 )
       return false;
     u.tok -= success*xtok;
     u.lock -= success*xlock;
     return true;
   }

   // lock up a given amount of TOK of the current user

   function dolock(uint amount) returns (bool) {
     address user = msg.sender;
     User u = users[user];
     if ( u.created == false )
       return false;
     if ( amount > u.tok )
       return false;
     u.tok -= amount;
     u.lock += amount;
     return true;
   }

   // submit an item

   function submit(bytes32 name) returns (bool) {
     User u = users[msg.sender];
     if ( u.created == false )
       return false;
     uint nrp = u.num_recent_posts;
     uint lmt = nrp*nrp*nrp + 1;
     if ( u.lock < lmt )
       return false;
     uint tc = now;
     uint bc = block.number;
     items.push(Item({
       itemname : name,
       time_created : tc,
       block_created: bc,
       posted_by: u,
//       reward_points: 0,
       votes: 0
       }));
     if ( ( bc - u.block_num_recent_posts ) <= 10 ) {
       u.num_recent_posts++;
     } else {
       u.block_num_recent_posts = bc;
       u.num_recent_posts = 1;
     }
     return true;
   }

   // constructor

   function Upvote(bytes32 name) payable {
     root = msg.sender;
     bool b = createUser(name);
     if ( b == false )
       selfdestruct;
     lastnonce = 0;
   }

   // preliminary implementation of vote() without 2phase commit

   function vote(uint itemidx) returns (bool) {
     User u = users[msg.sender];
     if ( u.created == false )
       return false;
     if ( itemidx >= items.length )
       return false;
     Item itm = items[itemidx];
     uint tc = now;
     uint bc = block.number;
     uint vt = msg.value;
     uint nrc = u.num_recent_votes;
     uint lmt = nrc*nrc*nrc + 1;
     if ( u.lock < lmt )
       return false;
     itm.votes += vt;
     if ( ( tc - itm.time_created ) <= (24 * 3600) ) {
       u.num_recent_votes += vt;
     } else {
       u.time_num_recent_votes = tc;
       u.num_recent_votes = vt;
     }
     return true;
   }

   // the rewards distribution function, only callable by root

   function send_rewards(uint[] amounts_tok, uint[] amounts_lock, address[]
   tos, uint nonce) returns (bool) {
     address callr = msg.sender;
     if ( callr != root )
       return false;
     uint L1 = amounts_tok.length;
     uint L2 = amounts_lock.length;
     uint L3 = tos.length;
     if ( L1 != L2 )
       return false;
     if ( L2 != L3 )
       return false;
     if ( lastnonce == nonce )
       return false;
     lastnonce = nonce;
     bool atleastonevalid = false;
     for (uint i=0; i < L1; i++) {
       User u = users[tos[i]];
       if ( u.created == false )
         continue;
       atleastonevalid = true;
       u.tok += amounts_tok[i];
       u.lock += amounts_lock[i];
     }
     return atleastonevalid;
   }

   function total_reward_points() returns (uint) {
     uint accum = 0;
     for (uint i=0; i < knownAddrs.length; i++) {
       accum += users[knownAddrs[i]].reward_points;
     }
     return accum;
   }

   function total_poster_reward_points() returns (uint) {
     uint accum = 0;
     for (uint i=0; i < items.length; i++) {
       User u = items[i].posted_by;
       accum += u.reward_points;
     }
     return accum;
   }

   function total_lock_points() returns (uint) {
     uint accum = 0;
     for (uint i=0; i < knownAddrs.length; i++) {
       accum += users[knownAddrs[i]].lock;
     }
     return accum;
   }

   // timer function, called by root every 5 minutes

   function tick5m() {
     if ( msg.sender != root )
       return;
     // task 1: GAS
     bool dbg = root.send(25);
     if ( dbg == false )
       return;
     // task 2: distribute 25 to users weighted by reward points
     uint totrp = total_reward_points();
     uint run_totrp = totrp;
     while ( run_totrp > 0 ) {
       for (uint i=0; i < knownAddrs.length; i++) {
         address a = knownAddrs[i];
         User u = users[a];
         uint x = (u.reward_points * 25 * 1000)/totrp;
         u.tok += x; // we have converted to finney
         run_totrp -= u.reward_points;
       }
     }
     // task 3: distribute 25 to posters weighted by reward points
     uint totpp = total_poster_reward_points();
     uint run_totpp = totpp;
     while ( run_totpp > 0 ) {
       for (uint j=0; j < items.length; j++) {
         User u2 = items[j].posted_by;
         uint x2 = (u2.reward_points * 25 * 1000)/totpp;
         u2.tok += x2; // in finney
	 run_totpp -= u2.reward_points;
       }
     }
     // reset reward points
     for (uint k=0; k < knownAddrs.length; k++) {
       users[knownAddrs[k]].reward_points = 0;
     }
     // task 4: distribute 25 among lock holders
     uint totlk = total_lock_points();
     uint run_totlk = totlk;
     while ( run_totlk > 0 ) {
       for (uint m=0; m < knownAddrs.length; m++) {
         address a2 = knownAddrs[m];
         User u3 = users[a2];
         uint x3 = (u3.lock * 25)/totlk;
         u.lock += x3;
	 run_totlk -= u3.lock;
       }
     }
     // task 5: migrate lock to tok
     for (uint n=0; n < knownAddrs.length; n++) {
       address a3 = knownAddrs[n];
       User u4 = users[a3];
       if ( u4.lock > 0 ) {
         u4.lock -= 1 finney;
         u4.tok += 1 finney;
       }
     }
   }
}
