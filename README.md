[<img src="https://github.com/mediachainlabs/cccoin/raw/master/images/cccoin_18.png">](https://github.com/mediachainlabs/cccoin/raw/master/images/cccoin_18.png)

**CCCoin** - Image creation, curation, and sharing incentivization network.

## [Join CCCoin Now](http://52.168.175.195)

|          |             | 
| ------------- | :------------- | 
| **Rewards users** for submitting images.      | **Rewards voters** for curating images. | 
| **Rewards servers** for contributing website hosting.      | **Rewards sponsors** for sponsoring gas fees.      | 
| **No downloads** runs instantly in any web browser. | **Zero fees** for regular users, not micro-tipping.      | 
| **ERC20 standard** token rewards. | **Rewards commitment** with long-term staking interest. |


## Technologies

- **Mediachain** - Metadata storage, metadata search, and metadata organization.
- **Ethereum** - ERC20 for the token and blockchain for resolving concurrency conflicts into a single universal ordering.
- **CCCoin Core** - Custom blockchain consensus and incentives mechanisms that build upon the above foundations.

## Blockchain Rewards in Depth

CCCoin's blockchain, layered above the Ethereum blockchain, mints rewards for wide variety of contributions,

1. **Submit your images** - Submit images that get sufficient votes, and you earn tokens. Submit images that don't get sufficient votes, you start to lose visibility for your newly submitted images.
2. **Vote on images** - Vote on images that receive sufficient subsequent votes after your vote, and you earn tokens. Vote on images that don't receive sufficient subsequent votes, you start to lose voting power.
3. **Run a web node** - Run a web node, optionally develop custom anti-spam controls, provide hosting to and front Gas fees to end users. If the end users your node chooses to host subsequently earn sufficient tokens through any of the actions above, you earn tokens too. Front these resources to users who are a net loss, and you can't recoup the upfront costs.
4. **Fund others' web nodes** - Fund the resource fees for web nodes that are fronting resources to users in a net profitable way, and receive a share of the net rewards. Fund web nodes that are not, incur net a loss. Web nodes are currently responsible for implementing this.
5. **Run rewards node** - Properly carry out the computations for distributing rewards, and you earn tokens. Distribute rewards poorly, you get forked and cut out.
6. **Buy the CCCoin token** - Fund the advancement of the entire CCCoin ecosystem of resource providers by supporting the price of CCCoin. Feel the rewards of knowing you're contributing to creative good!
7. **Loan CCCoin your tokens** - Commit to locking up your CCCoin tokens on the platform for a period of time, in the form of CCLock, and you'll receive interest bearing CCCoin payments back over time. Redeem too much of your CCLock too soon, and face an early withdrawal penalty.

## Properties in Depth

CCCoin aims to achieve all of the properties expected from a dApp,

- **Trustless** - meritocratic incentives system allowing bad actors to be automatically replaced by good actors.
- **Permissionless** - anyone can contribute without permission, by submitting directly to the blockchain, though those who make negative contributions will likely face penalties.
- **Zero fee** - unlike micro-tipping platforms, CCCoin aims to be completely free to use for content viewers, voters, and submitters who are expected to make net-positive contributions. Funds to front the necessary fees are funded by web node operators or those who invest in them.
- **Fault tolerant** - resource providers that disappear or go rogue can be replaced in a meritocratic, permissionless, automated way.
- **Distributed Computation**, **Distributed Control**, **Decentralized Control** - See trustlessness and fault tolerance.


## Token Types

- **CCCoin (CCC)** - The currency of the CCCoin network. It is a ERC20 standard token that can be freely used independently of the CCCoin network.
- **CCLock (CCL)** - Virtual token of CCCoin that represents locked-up CCC, and can only be slowly disbursed back to its owners over many months in the form of CCC interest bearing payments. Meant to incentivize long-term good behavior by certain participants, in addition to rewarding those wanting to make a long term financial commitment to CCCoin.


## Getting Started

Visit [this web node](http://52.168.175.195) on any regular web browser to get started right away!

Or run your own web node,

1. Setup either [Geth](https://ethereum.github.io/go-ethereum/downloads/), [Parity](https://ethcore.io/parity.html), or [Test-RPC](https://github.com/ethereumjs/testrpc). Configure its settings in `truffle.js`. Settings for connecting to the CCCoin network with Geth 1.5.2 can be found [here](https://gist.github.com/parkan/5b99978279b5c58ca0fdff0c18ed6d88).

2. Clone:
   ```bash
   $ git clone https://github.com/mediachainlabs/cccoin.git
   ```

3. Install dependencies:
   ```bash
   $ curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
   $ sudo apt-get install nodejs libssl-dev npm
   $ cd cccoin/node/ && pip install -r requirements.txt 
   $ cd frontend/ && npm install && npm run build # OPTIONAL
   $ sudo npm install -g git+https://github.com/ethereumjs/testrpc # OPTIONAL
   ```

4. Launch your Ethereum node. Refer to the instructions for your chosen variant from step #1:
   
   ```bash
   $ testrpc -p 9999 --gasLimit 0xFFFFFFFFF --gasPrice 1
   ```

5. Either deploy new instance of the contract, or record the address of an already deployed contract:

    ```bash
    $ cd cccoin/ && truffle migrate --verbose-rpc
    # OR:
    $ echo "CONTRACT_ADDRESS_HERE" > cccoin/node/build_contracts/cccoin_contract_address.txt
    ```

6. Launch your own web node:

    ```bash
    $ cd cccoin/node/ && python node_main.py start_web
    ```

## Status

- **Planned:** Rewards Nodes vote on rewards, with M of N consensus required. Voting elects rewards nodes.
- **Planned:** Streamlining of web node financier process.
- **Planned:** More comprehensive in-browser light wallet functionality.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
