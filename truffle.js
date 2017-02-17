module.exports = {
  rpc: {
    host:       "localhost",
    port:       9999,
    gas:        9999999 // For the Solidity tests.
  },
  networks: {
    development: {
      host: "localhost",
      port: 9999,
      network_id: "*" // Match any network id
    },
    live: {
      host: "localhost",
      port: 8545,
      network_id: 1
    }
  }
};
