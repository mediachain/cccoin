module.exports = {
    rpc: {
	from: "0x739cba11ff90dfef906287756c6b8adc183ba3c1",
	host:       "localhost",
	port:       8645,
	gas:        8645999, // For the Solidity tests.
	network_id: 12345
    },
    networks: {
	development: {
	    host: "localhost",
	    port: 8645,
	    network_id: "*" // Match any network id
	},
	live: {
	    from: "0x739cba11ff90dfef906287756c6b8adc183ba3c1",
	    host: "localhost",
	    port: 8645,
	    network_id: 12345
	}
    }
};
