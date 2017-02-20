module.exports = {
  rpc: {
    host:       "localhost",
    port:       8645,
    gas:        8645999 // For the Solidity tests.
  },
  networks: {
    development: {
      host: "localhost",
      port: 8645,
      network_id: "*" // Match any network id
    },
    live: {
      host: "localhost",
      port: 8645,
      network_id: 1
    }
  }
};
