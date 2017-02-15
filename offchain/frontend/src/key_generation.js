const ethUtils = require('ethereumjs-util')
const bip39 = require('bip39')

module.exports = exports = {
  generatePassphrase() {
    let mnemonic
    do {
      mnemonic = bip39.generateMnemonic()
    } while (!exports.isValidPassphrase(mnemonic))

    return mnemonic
  },

  isValidPassphrase (passphrase) {
    const privateKey = exports.privateKeyForPassphrase(passphrase)
    return ethUtils.isValidPrivate(privateKey)
  },

  privateKeyForPassphrase(passphrase) {
    return ethUtils.sha256(bip39.mnemonicToEntropy(passphrase))
  },

  keypairForPassphrase (passphrase) {
    const priv = exports.privateKeyForPassphrase(passphrase)
    const privateKey = priv.toString('hex')
    const publicKey = ethUtils.privateToPublic(priv).toString('hex')
    const address = ethUtils.privateToAddress(priv)
    return {privateKey, publicKey, address}
  }
}
