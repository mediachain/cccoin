module.exports = function(deployer) {
  deployer.deploy(CCCoinToken);
  deployer.autolink();
};
