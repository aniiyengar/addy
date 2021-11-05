#!/usr/local/bin/node

const hd = require('hdaddressgenerator');
const {randomBytes} = require('crypto');
const secp256k1 = require('secp256k1');
const keccak = require('keccak');

const help = () => {
  console.log(`
addy [command] [args]

commands:
addy calc [n] [mnemonic] - for given mnemonic generate N addresses
                           and private keys
addy gen [prefix]? [suffix]? - generate a new eth address with given
                               prefix and suffix if supplied
`);

}

// From a given mnemonic print first N addresses with private keys
const calc = async () => {
  const numAddresses = parseInt(process.argv[3]);
  if (!numAddresses || numAddresses <= 0) {
    console.error('Must supply a valid number of addresses.');
    process.exit(1);
  }

  let mnemonic = process.argv[4];
  if (!mnemonic) {
    console.error('Invalid mnemonic.');
    process.exit(1);
  }

  mnemonic = mnemonic.match(/\S+/g).join(' ');

  const bip44 = hd.withMnemonic(mnemonic, false, 'ETH');

  const addresses = await bip44.generate(numAddresses);

  addresses.forEach((address) => {
    console.log(address.address + ' - ' + address.privKey);
  });
}

const gen = async () => {
  let found = false;

  const prefix = process.argv[3];
  const suffix = process.argv[4];

  while (!found) {
    let privateKey;
    do { privateKey = randomBytes(32) } while (!secp256k1.privateKeyVerify(privateKey));
    const publicKey = secp256k1.publicKeyCreate(privateKey);

    const address = keccak('keccak256').update(Buffer.from(publicKey)).digest('hex').substring(24);

    let exists = true;
    if (prefix) {
      exists = exists && address.startsWith(prefix);
    }
    if (suffix) {
      exists = exists && address.endsWith(suffix);
    }

    found = found || exists;

    if (exists) {
      // print result
      console.log('0x' + address + ' - 0x' + Buffer.from(privateKey).toString('hex'));
    }
  }
}

(async () => {
  const cmd = process.argv[2];
  
  if (cmd === 'calc') {
    await calc();
  } else if (cmd === 'gen') {
    await gen();
  } else {
    help();
    process.exit(1);
  }
})();
