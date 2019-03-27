const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const utils = require("./utils");

const enc = util.encodeBase64;
const dec = util.decodeBase64;

module.exports = () => {
  let keypair = null;
  return {
    get_secretKey: () => keypair.secretKey,
    init_keypair: secretKey => {
      keypair = secretKey
        ? nacl.sign.keyPair.fromSecretKey(dec(secretKey))
        : nacl.sign.keyPair();
    },
    sign_message: message => {
      return enc(nacl.sign.detached(dec(message), keypair.secretKey));
    },
    hash_message: message => {
      return enc(nacl.hash(utils.str2ab(JSON.stringify(message))));
    },
    sign_message_hash: message => {
      return self.sign_message(dec(self.hash_message(message)));
    },
    sign_transaction: transaction => {
      return enc(self.sign_message_hash(transaction));
    },
    check_signature: (message, signature, pubkey) => {
      return nacl.sign.detached.verify(
        dec(self.hash_message(message)),
        dec(signature),
        dec(pubkey)
      );
    }
  };
};
