var CCCoinToken = artifacts.require("./CCCoinToken.sol");

module.exports = function(deployer) {
  deployer.deploy(CCCoinToken);
};
