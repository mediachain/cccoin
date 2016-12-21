contract owned { 
    address owner;

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _
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
   contract TokFactory is owned{ 

    // modifier onlyOwner {
    //     if (msg.sender != owner) throw;
    //     _
    // }

    mapping(address => address[]) public created;
    mapping(address => bool) public isToken; //verify without having to do a bytecode check.
    bytes public tokByteCode;

    function () { 
      throw; 
    }

    function TokFactory() {
      //upon creation of the factory, deploy a Token (parameters are meaningless) and store the bytecode provably.
      owner = msg.sender;
      address verifiedToken = createTok(100000, "Tok", 3, "Tok");
      tokByteCode = codeAt(verifiedToken);
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

    function createTok(uint256 _initialAmount, string _name, uint8 _decimals, string _symbol) internal returns (address) {
        Tok tok = (new Tok(_initialAmount, _name, _decimals, _symbol));
        created[msg.sender].push(address(tok));
        isToken[address(tok)] = true;
        tok.transfer(msg.sender, _initialAmount); //the factory will own the created tokens. You must transfer them.
        return address(tok);
    }

  }


contract StandardToken {

    event Transfer(address sender, address to, uint256 amount);
    event Approval(address sender, address spender, uint256 value);
    /*
     *  Data structures
     */
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;

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

contract Tok is StandardToken, owned{ 

    address owner;
    address tokFactory; 

    string name; 
    uint8 decimals;
    string symbol; 

    modifier noEther { 
      if (msg.value > 0) { throw; }
    }

    modifier controlled { 
        if (msg.sender != tokFactory) throw; 
        _
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
        ) {
        tokFactory = msg.sender;
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function lockTokens(address _tokenHolder, uint256 _amount) controlled { 
      if (balances[_tokenHolder] < _amount) { throw; }
    } 

    function mintToken(address target, uint256 mintedAmount) controlled {
        balances[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(owner, target, mintedAmount);
}


}