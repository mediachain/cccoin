[<img src="https://github.com/mediachainlabs/cccoin/raw/master/images/cccoin_3.png">](https://github.com/mediachainlabs/cccoin/raw/master/images/cccoin_3.png)

**CCCoin** - Image creation, curation, and sharing incentivization network.

## Why

- **Pays you** for positive contributions.
- **No downloads** runs instantly in web browser.
- **Zero fees** for regular users, not micro-tipping.
- **ERC20 standard** token compatibility.

## Run

Any regular web browser can instantly and safely use CCCoin just by going to the URL of anyone running a `web node`. Or, follow the instructions below to run your own private `web node`.

Setup a [Geth](https://ethereum.github.io/go-ethereum/downloads/), [Parity](https://ethcore.io/parity.html), or [Test-RPC](https://github.com/ethereumjs/testrpc) Ethereum node, and configure its settings in `truffle.js`.

Instructions for setting up a private testnet with geth (current for 1.5.2) can be found [here](https://gist.github.com/parkan/5b99978279b5c58ca0fdff0c18ed6d88).

Then,

1. Launch your Ethereum node. Refer to the setup instructions for your chosen variant:
   
   ```bash
   testrpc -p 9999 --gasLimit 0xFFFFFFFFF --gasPrice 1
   ```

2. Build frontend:

    ```bash
    $ cd node/frontend/ && npm install && npm run build
    ```
3. (Optional) Deploy new instance of the contract:

    ```bash
    $ truffle migrate --verbose-rpc
    ```

4. Or, Paste address of the deployed contract into file:

    ```bash
    $ echo "CONTRACT_ADDRESS_HERE" > node/build_contracts/cccoin_contract_address.txt
    ```

5. Launch your own web node:

    ```bash
    $ cd node/ && pip install -r requirements.tx && python node_main.py start_web
    ```

## Incentives

CCCoin has a rich incentives ecosystem that rewards users for a wide variety of contributions,

1. **Submit your images** - Submit images that get sufficient votes, and you earn tokens. Submit images that don't get sufficient votes, you start to lose visibility for your newly submitted images.
2. **Vote on images** - Vote on images that receive sufficient subsequent votes after your vote, and you earn tokens. Vote on images that don't receive sufficient subsequent votes, you start to lose voting power.
3. **Run a web node** - Run a web node, optionally develop custom anti-spam controls, provide hosting to and front Gas fees to end users. If the end users your node chooses to host subsequently earn sufficient tokens through any of the actions above, you earn tokens too. Front these resources to users who are a net loss, and you can't recoup the upfront costs.
4. **Fund others' web nodes** - Fund the resource fees for web nodes that are fronting resources to users in a net profitable way, and receive a share of the net rewards. Fund web nodes that are not, incur net a loss. Web nodes are currently responsible for implementing this.
5. **Run rewards node** - Properly carry out the computations for distributing rewards, and you earn tokens. Distribute rewards poorly, you get forked and cut out.
6. **Buy the CCCoin token** - Fund the advancement of the entire CCCoin ecosystem of resource providers by supporting the price of CCCoin. Feel the rewards of knowing you're contributing to creative good!
7. **Loan CCCoin your tokens** - Commit to locking up your CCCoin tokens on the platform for a period of time, in the form of CCLock, and you'll receive interest bearing CCCoin payments back over time. Redeem too much of your CCLock too soon, and face an early withdrawal penalty.

## Properties

CCCoin has all of the stadard properties you expect from a dApp,

- **Trustless** - meritocratic incentives system allowing bad actors to be automatically replaced by good actors.
- **Permissionless** - anyone can contribute without permission, by submitting directly to the blockchain, though those who make negative contributions will likely face penalties.
- **Zero fee** - unlike micro-tipping platforms, CCCoin aims to be completely free to use for content viewers, voters, and submitters who are expected to make net-positive contributions. Funds to front the necessary fees are funded by web node operators or those who invest in them.
- **Fault tolerant** - resource providers that disappear or go rogue can be replaced in a meritocratic, permissionless, automated way.
- **Distributed Computation**, **Distributed Control**, **Decentralized Control** - See trustlessness and fault tolerance.

*Distributed - hiring a thousand guards to protect you with the hope that more is simply better. Trustless - ensuring there's always geater monetary benefit to your guards for them to protect you, rather than to accept bribes to harm you.*

## Tokens

- **CCCoin (CCC)** - The currency of the CCCoin network. It is a ERC20 standard token that can be freely used independently of the CCCoin network.
- **CCLock (CCL)** - Virtual token of CCCoin that represents locked-up CCC, and can only be slowly disbursed back to its owners over many months in the form of CCC interest bearing payments. Meant to incentivize long-term good behavior by certain participants, in addition to rewarding those wanting to make a long term financial commitment to CCCoin.

## Technologies

- **Mediachain** - Metadata storage, metadata search, and metadata organization.
- **Ethereum** - ERC20 for the token and blockchain for resolving concurrency conflicts into a single universal ordering.
- **CCCoin Core** - Custom blockchain consensus and incentives mechanisms that build upon the above foundations.

## Status

Future plans include evolving from a single rewards node operating at a time, which can be fired and replaced at any time via a hard fork performed by the users of the network if they collectively choose to do so, toward a softer hiring and firing mechanism which will instead allow users to continually vote to elect a consortium of operators for rewards nodes. Further streamlining third party funding of web nodes is also planned.

