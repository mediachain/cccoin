pragma solidity ^0.4.0;

/// @title upvoting style auction/posting contract
contract Upvote {

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
     uint reward_points;
     uint votes;
   }

   address public root;      // creator of this contract

   mapping(address => User) public users;  // User struct for each address

   Item[] items;           // dynamically sized array of Items
   bytes32[] knownUsers;   // names of known users. this will go
                                  // away when we have an iterable map

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
     u.created = true;
     u.time_created = now;
     u.block_created = block.number;
     u.tok = 0;
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
       reward_points: 0,
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
   }

   // need a vote() function and a tick() function
   // need an iterable mapping for users
   // dapp-bin/library/iterable_mapping.sol

}
