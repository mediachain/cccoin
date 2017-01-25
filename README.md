# Overview:

Steemit-like blockchain app, consisting of:

- Ethereum contract implementing ERC20 StandardToken interface and event logging functions.
- Off-chain app in Deploy mode: (MC runs) Features: Performs initial deployment of the contract. Deployer will be in charge of distributing rewards. Only done once.
- Off-chain app in Witness mode: (MC runs) Features: Web server = No, Distribute rewards = Yes, Audit rewards = No.
- Off-chain app in Web mode: (Anyone can run) Features: Web server = Yes, Distribute rewards = No, Audit rewards = No.
- Off-chain app in Audit mode: (Anyone can run) Features: Web server = No, Distribute rewards = No, Audit rewards = Yes.

Rewards are computed offchain for V1, due to extremely high GAS costs, low maximum GAS limits per call, and other scalability factors. This decision may be revisited later. Likewise, the web server is implemented in a partially-decentralized off-chain app, much like Steemit, instead of using the fully decentralized web3.js approach. See "future" plans below for how this architecture may evolve.

## Token types:

- TOK = This is the "real" token type represented by the StandardToken Ethereum contract.

- LOCK = This is a synthetic token type that can't be directly spent or transferred. But, the user's LOCK balance affects his voting power, and determines how frequently the user can vote or post. To get this token type, a user sends some of their TOK to a special function. This TOK balance is then effectively destroyed, and in return the user is given a LOCK balance which they cannot spend or transfer. New TOK is then created over time, to slowly compensate the user for their TOK plus interest. The amount of new TOK eventually created is larger than the original amount of TOK that was locked up, effectively paying the user interest for having converted TOK into un-spendable LOCK for a period of time.

## Trustlessness:

Distrusting the Witness:

- Any users can run the offline app in Audit mode, to verify that minting rewards are being paid out appropriately. The Ethereum blockchain contains a the full history of actions necessary to perform the audit.

Disappearance of the Witness:

- When using a Web mode server run by another user, users receive a file containing their private keys. This gives users access to their tokens, and allows them to continue to post votes and comments, even while the central Witness is down.

Forking:

- In the event that the Witness disappears or goes rogue, the community may collectively choose to fork the network, which involves pointing their nodes to a new contract address. This can be called a "dApp fork", in contrast to an ethereum "blockchain fork".

Future:

- Instead of a single witness run by MC whose power may be forked if necessary, instead ~20 Witnesses will be voted into power by LOCK holders. These Witnesses will work together to form a consensus on rewards payouts, instead of the current 1 Witness system.
- Additional logic may be moved on-chain, into the Ethereum contract.


## Reward types:

- Curation rewards = 49 TOK from each block are split among good voters. These rewards are in proportion to the "weight" of people who vote on something, after you've voted on it. The "weight" is proportional to the amount of TOK that each voting user has locked for a long period of time.

- Posting rewards = 49 TOK from each block are awarded to users who post items.

- Sponsor rewards = 1 TOK from each block awarded to sponsors. Background -- Two of the goals necessitate sponsors, given in the current architecture: (1) to not burdening regular users with micro-transaction fees, a sponsors award new users Ethereum GAS per each transaction they perform and the initial minimum CCCoin TOK required to perform actions (2) users should be able to access the dApp without installing anything, much like Steemit. A distributed network of sponsors front the money and resources for these two goals. To compensate sponsors, they will receive 1% of all future rewards of that users who use the network through their nodes. This balance of fees and rewards also incentivizes sponsors to filter out spam before it hits the blockchain, so they won't face a net loss.


## Temporary blockchain forks:

The off-chain app handles blockchain forks of less than 10 confirmations, which are common on ethereum, by:

1) Reward payouts are delayed ~10 confirmations.
2) Internal datastructures tracking write operations such as voting and item posting maintain 2 copies = 1 copy just for confirmed transactions, and 1 copy for pending transactions including locally initiated transactions. These 2 copies are merged together on the fly when accessed. Actions from the "pending" copy are automatically deleted once they are seen "confirmed", periodically re-checked, and ultimately "deleted" if they can never be confirmed.

Dealing with Ethereum miners permanently refusing some transactions is an open question.


## Hard blockchain forks:

Off-chain apps that maintain an internal state require special care in dealing with blockchain forks, which may occur an arbitrary number of confirmations in the past. Blockchain clients usually provide little or no indication that your node's code is outdated due to a hardfork, and confirmations may continue to arrive on the old fork due to not all miners immediately switching.

To handle arbitrarily distant hardforks, the Witness may be re-run from the beginning against the new fork. Incremental snapshots every N blocks of the offchain app's internal state, along with block hashes, may also be used to speed up this reboot.

Future Note: When we switch over to a voting witness system, hard forks that prevent a considerable amount of the voting power from voting on the fork that's eventually determined to be the winner will be a problem.


## Rewards schedule:

100 TOK each 7 hours -- Arbitrarily chosen. Made to be infrequent so that many rewards can be combined into a single (expensive) on-chain payment.


## Web Mode JSON API:

Endpoints:

Non-authenticated: list, create_account
Authenticated: login, submit, vote

Authentication Headers:

Key - Authorization key. May have full permissions, or user may have multiple keys with different permission levels.
Sig - Signature of query's POST data and your "secret" using HMAC-SHA256.
Nonce - Monotonically increasing number. Must increase with each API call. E.g. int(time() * 1000).

Tracking ids:

Some commands cannot immediately produce results, in which case a tracking_id is given for later polling. Using tracking IDs shouldn't be critical for most use cases.

Example:

### user_1 create user:
```
$ curl -S http://big-indexer-1:50000/api -d '{"command":"create_account"}'
{
	"success": true,
	"user_id": "b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399",
	"user_info": {
    	"private_key": "c59ddbaedf5adc65a74008c072f0bcd763bef225968dc2de1fdaa2f00c361c8c",
    	"public_key": "b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399",
    	"sponsor": "352443f8fd87701c9ee3e7ceb79c0a641d3021f55e3735df8c9042981d290bb6"
	}
}
```

### user_2 create user:
```
curl -S http://big-indexer-1:50000/api -d '{"command":"create_account"}'
{
	"success": true,
	"user_id": "f16fdbe7682c0f4ee08ed44c4d44c796a385a46269f64ab6f93b34c30c6085fd",
	"user_info": {
    	"private_key": "1e721173b1044206d6d2d1f152109fe3eb3062b680e5168e4cecd2fe5e85174b",
    	"public_key": "f16fdbe7682c0f4ee08ed44c4d44c796a385a46269f64ab6f93b34c30c6085fd",
    	"sponsor": "352443f8fd87701c9ee3e7ceb79c0a641d3021f55e3735df8c9042981d290bb6"
	}
}
```

### user_1 submit URL:

**Generate request signature:**
```
$ python offchain.py sig_helper "b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399" "c59ddbaedf5adc65a74008c072f0bcd763bef225968dc2de1fdaa2f00c361c8c" '{"command":"submit", "item_data":{"url":"test_url", "title":"test post"}}'
```

**Perform request:**
```
$ curl -silent http://big-indexer-1:50000/api -d '{"command":"submit","item_data":{"title":"test post","url":"test_url"},"nonce":1485295066774}' -H 'Sig: ddd92d090fa9a1eca7642945cd800e34a84692e01dd926f4368ee22ddb5a798f922a2daf702ea2bd95f764d57f576b89e3dceda054faae310fcd4fc0ae53a822' -H 'Key: b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399'
{
	"success": true,
	"item_id": "0x4c13a3bf3658d38e947e97ab75b909647aec8a5f7dbddabd971815545377dcc7",
}
```

**Attempt to replay request:**
```
$ curl -S http://127.0.0.1:50000/api -d '{"command":"submit","item_data":{"title":"test post","url":"test_url"},"nonce":1485295066774}' -H 'Sig: ddd92d090fa9a1eca7642945cd800e34a84692e01dd926f4368ee22ddb5a798f922a2daf702ea2bd95f764d57f576b89e3dceda054faae310fcd4fc0ae53a822' -H 'Key: b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399'

{
	"error": "AUTH_FAILED",
	"message": "OUTDATED NONCE"
}
```

### user_2 vote on URL:

**Generate blinded vote signature:**
```
$ python offchain.py sig_helper "b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399" "c59ddbaedf5adc65a74008c072f0bcd763bef225968dc2de1fdaa2f00c361c8c" '{"votes":[{"item_id": "0x4c13a3bf3658d38e947e97ab75b909647aec8a5f7dbddabd971815545377dcc7", "direction":1}]}'
```

**Submit blind vote, using signature generated above:**
```
$ curl -S http://127.0.0.1:50000/api -d '{"command":"blind_vote", "key":"b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399", "sig":"84d70e4bb126c152348ea49c4683b3ddb1aa9a83d1e1531f3954a097c4ac027e2e8c233cdb7b1a44aa7ddc316694054b81959cccc6413f892754796603459d33"}'

{
	"success": true
}
```

### user_2 unblind vote:

**Sign unblind call:**
```
python offchain.py sig_helper "b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399" "c59ddbaedf5adc65a74008c072f0bcd763bef225968dc2de1fdaa2f00c361c8c" '{"command":"unblind_vote", "vote_string":"{\"votes\":[{\"item_id\": \"0x4c13a3bf3658d38e947e97ab75b909647aec8a5f7dbddabd971815545377dcc7\", \"direction\":1}]}"}'
```

**Unblind vote:**
```
curl -S http://127.0.0.1:50000/api -d '{"command":"unblind_vote","nonce":1485297601257,"vote_string":"{\"votes\":[{\"item_id\": \"0x4c13a3bf3658d38e947e97ab75b909647aec8a5f7dbddabd971815545377dcc7\", \"direction\":1}]}"}' -H 'Sig: 2f521be552bf77b7031037564f1ade6da05875019631edc37ff2c45e43e614f4ec01fa2fdbaa7284eff81d8fb352a217ec7fa6324f2f4331b409a3a67d89c8be' -H 'Key: b1b790cc80031664c4629829ba1ef718242023aacee2866eeab5bc8452cc9399'

{
	"success": true
}
```

### list new posts:
```
$ curl http://big-indexer-1:50000/

{
	"items": [{"command":"submit", "item_data":{"url":"test_url", "title":"test post"}, "score":2, "created":"1485296972"}],
	"sort": "score",
	"success": true
}
```

## Details:
- Core of the Ethereum contract is a ERC20 StandardToken, plus a few lines of code for event logging. (Have also drafted out smart contract versions of some other functions, but that's not for V1.)
- "Web Mode" has the ability to post votes or comments, but not mint new tokens. Allows us to run multiple web nodes. If hacked, damage is limited.
- "Witness Mode" has the ability to mint new coins and distribute them as rewards. The node running this mode can be better isolated from the Internet than the "web mode" workers, for better security.
- "Auditor Mode" is identical to Witness mode, but only tracks the differences between what it would write to the blockchain, and what the existing witness actually wrote to the blockchain. Note: Exact replication of the central node's actions may not be possible, due to reordering, delaying, or even rejection of transactions by miners, but, looser deadline windows on the central node performing actions should be enough to detect that the trusted node is operating within reasonable reward size and time limit bounds.
- Most types of actions are sent to the blockchain via "event logs", which are picked up later by the Witness node, and by other auditors.
- Multiple votes within a short time span (1 block?) from a single user can be batched into a dense format by the user's Web mode node, for storage efficiency in the blockchain event logs. Further batching can also reduce gas costs, at the expense of possibly missing out on some curation rewards. At the global level, voting granularity can be made less infrequent than every 1 block, for further gas savings.
- Periodically, token balances are actually updated in users' wallets on the blockchain. Currently this update interval is arbitrarily set to 7 hours.
- For user convenience, e.g. seeing the post or vote you just made, or another web node just made, without having to wait a significant amount of time (10 confirmations = 30 minutes), the node will have accept properly signed but unconfirmed transactions, which will then be monitored for confirmation, or else the results of those transactions will be deleted (but not rolled back in a DB sense) after a time limit.
- There's a relatively simple path from here to allowing both upvotes and downvotes, in addition to other types of flagging, if desired.
- In this initial form, to mitigate certain classes of attacks, all curation rewards should probably be strictly positive - there can't be penalties for bad voting that could potentially bring a user's balance negative.  A penalty that is viable is fees that are charged for all votes regardless of the vote contents. (I can think through alternate mechanisms to see if there are ways around this, if needed.)


