pragma solidity ^0.4.0;
contract owned { 
    address owner;

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }
    function owned() { 
        owner = msg.sender; 
    }

}
contract mortal is owned {
    function kill() {
        if (msg.sender == owner) selfdestruct(owner);
    }
}
contract TokFactory is owned, mortal{ 

    mapping(address => address[]) public created;
    mapping(address => bool) public isToken; //verify without having to do a bytecode check.
    bytes public tokByteCode;
    address public verifiedToken;
    event tokenCreated(uint256 amount, address tokenAddress, address owner);
    Tok tok;

    function () { 
      throw; 
    }

    modifier noEther { 
      if (msg.value > 0) { throw; }
      _; 
    }

    modifier needTok { 
      if (address(tok) == 0x0) { throw; }
      _;
    }

    function TokFactory() {
      //upon creation of the factory, deploy a Token (parameters are meaningless) and store the bytecode provably.
      owner = msg.sender;
    }

    function getOwner() constant returns (address) { 
      return owner; 
    }

    function getTokenAddress() constant returns (address) { 
      // if (verifiedToken == 0x0) { throw; }
      return verifiedToken;
    } 

    //verifies if a contract that has been deployed is a validToken.
    //NOTE: This is a very expensive function, and should only be used in an eth_call. ~800k gas
    function verifyToken(address _tokenContract) returns (bool) {
      bytes memory fetchedTokenByteCode = codeAt(_tokenContract);

      if (fetchedTokenByteCode.length != tokByteCode.length) {
        return false; //clear mismatch
      }
      //starting iterating through it if lengths match
      for (uint i = 0; i < fetchedTokenByteCode.length; i ++) {
        if (fetchedTokenByteCode[i] != tokByteCode[i]) {
          return false;
        }
      }

      return true;
    }

    //for now, keeping this internal. Ideally there should also be a live version of this that any contract can use, lib-style.
    //retrieves the bytecode at a specific address.
    function codeAt(address _addr) internal returns (bytes o_code) {
      assembly {
          // retrieve the size of the code, this needs assembly
          let size := extcodesize(_addr)
          // allocate output byte array - this could also be done without assembly
          // by using o_code = new bytes(size)
          o_code := mload(0x40)
          // new "memory end" including padding
          mstore(0x40, add(o_code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
          // store length in memory
          mstore(o_code, size)
          // actually retrieve the code, this needs assembly
          extcodecopy(_addr, add(o_code, 0x20), 0, size)
      }
    }

    function createTok(uint256 _initialAmount, string _name, uint8 _decimals, string _symbol) onlyOwner  returns (address) {
        tok = new Tok(_initialAmount, _name, _decimals, _symbol);
        created[msg.sender].push(address(tok));
        isToken[address(tok)] = true;
        // tok.transfer(owner, _initialAmount); //the creator will own the created tokens. You must transfer them.
        verifiedToken = address(tok); 
        tokByteCode = codeAt(verifiedToken);
        tokenCreated(_initialAmount, verifiedToken, msg.sender);
        return address(tok);
    }
    function rewardToken(address _buyer, uint256 _amount)  onlyOwner returns (bool) {
      return tok.transfer(_buyer, _amount); 
  }
}
contract StandardToken is owned, mortal{

    event Transfer(address sender, address to, uint256 amount);
    event Approval(address sender, address spender, uint256 value);
    /*
     *  Data structures
     */
    struct User {
      bool initialized; 
      address userAddress; 
      bytes32 userName;
      uint256 registerDate;
      uint8 blockVoteCount;    // number of votes this block
      uint256 currentBlock; 
      uint8 totalVotes; 
      mapping (uint8 => Post) votedContent;  // mapping of each vote to post 
    }

    struct Lock {
      uint256 amount; 
      uint256 unlockDate;
    }

    struct Post {
      bool initialized; 
      address creator; 
      bytes32 title;
      bytes32 content; 
      uint256 creationDate; 
      uint8 voteCount;     // total + or - 
      address[] voters;
      mapping (address => uint8) voteResult;     // -1 = downvote , 0 = no vote,  1 = upvote 
    }


    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;
    mapping (address => Lock[]) public lockedTokens;
    mapping (address => Post[]) public posts;
    uint8 public numUsers;
    mapping (address => User) public users;
    address[] userAddress; 

    
    /*
     *  Read and write storage functions
     */
    /// @dev Transfers sender's tokens to a given address. Returns success.
    /// @param _to Address of token receiver.
    /// @param _value Number of tokens to transfer.
    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Allows allowed third party to transfer tokens from one address to another. Returns success.
    /// @param _from Address from where tokens are withdrawn.
    /// @param _to Address to where tokens are sent.
    /// @param _value Number of tokens to transfer.
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        }
        else {
            return false;
        }
    }

    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    /// @dev Sets approved amount of tokens for spender. Returns success.
    /// @param _spender Address of allowed account.
    /// @param _value Number of approved tokens.
    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /*
     * Read storage functions
     */
    /// @dev Returns number of allowed tokens for given address.
    /// @param _owner Address of token owner.
    /// @param _spender Address of token spender.
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

}
contract Tok is StandardToken{ 

    address tokFactory; 

    string name; 
    uint8 decimals;
    string symbol; 

    modifier noEther { 
      if (msg.value > 0) { throw; }
      _; 
    }

    modifier controlled { 
        if (msg.sender != tokFactory) throw; 
        _;
    }


    function () {
        //if ether is sent to this address, send it back.
        throw;
    }

    function Tok(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
        ) noEther{
        tokFactory = msg.sender;
        balances[msg.sender] = _initialAmount;               // Give the TokFactory all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function getUserAddress(address _user) noEther returns (address) { 
      return users[_user].userAddress; 
    }
    function getUserName(address _user) noEther returns (bytes32) { 
      return users[_user].userName; 
    }

    function register(bytes32 _username) noEther returns (bool success) { 
      User newUser = users[msg.sender];
      newUser.userName = _username;
      newUser.userAddress = msg.sender;
      newUser.registerDate = block.timestamp;
      return true; 

    }

    function lockTokens( uint256 _amount) noEther  returns (bool) { 
      if (balances[msg.sender] < _amount) { return false; }
      Lock[] lock = lockedTokens[msg.sender];
      uint256 unlockTime = block.timestamp + 4 weeks;
      balances[msg.sender] -= _amount;
      totalSupply -= _amount;
      lock.push(Lock({amount: _amount, unlockDate: unlockTime}));
      return true; 
    } 

    function mintToken(address _target, uint256 _mintedAmount) controlled {
        balances[_target] += _mintedAmount;
        totalSupply += _mintedAmount;
        Transfer(owner, _target, _mintedAmount);
}

    // function numRecentVotes(address voter) internal constant returns (uint256) {
    //   User user = users[voter]; 
    //   uint8 recentVotes = 0; 
    //   for (uint8 i = 0; i < user.voteCount; i++) { 
    //     if (user.blockVoteCount ) { 
    //       recentVotes++;
    //     }
    //   }
    //   return recentVotes; 
    // }

    
    function  post(bytes32 _title, bytes32 _content) noEther{
      Post[] posts = posts[msg.sender];
      posts.push(Post({creator: msg.sender, title: _title, content: _content, creationDate: block.timestamp, voteCount: 0}));
    }

    function vote(uint8 _postID, address _creator) noEther {
           User voter = users[msg.sender];
           Post postVotedOn = posts[_creator][_postID];
           if (voter.currentBlock == block.number) {
             // uint256 requiredLock =  (1 * numVotes) ** 3) + 100);  
             // uint256 lockBalance = lockBalance(msg.sender);
             // if (lockBalance < requiredLock) { throw;     }  
           }
           else { 
            voter.blockVoteCount = 0; 
            voter.currentBlock = block.number;
            uint256 totalLock = lockBalance(msg.sender);
            if (totalLock > 100) { 

            } 
           }
    }

    function lockBalance(address lockAccount)  constant returns (uint256) { 
      Lock[] lockedList = lockedTokens[lockAccount];
      uint256 total = 0;  
      for (uint8 i = 0; i < lockedList.length; i++) { 
        total += lockedList[i].amount; 
        }
      return total;
    }
    function calculateLockPayout(uint256 _amount) internal constant controlled { 
      for (uint8 i = 0; i < numUsers; i++) { 
         address temp = userAddress[i]; 
         User user = users[temp]; 
         uint256 userLockBalance = lockBalance(temp);

      }
    }


}