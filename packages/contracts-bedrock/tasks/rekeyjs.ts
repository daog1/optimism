import { task, types } from 'hardhat/config'
import { hdkey } from 'ethereumjs-wallet'
import * as bip39 from 'bip39'
const fs = require('fs');

task('rekeyjs', 'Generates a new set of keys for a test network')
  .addParam(
    'out',
    'out file',
    '.rekey.json',
    types.string
  )
  .setAction(
    async (args, hre) => {
      const { out, } = args
      const mnemonic = bip39.generateMnemonic()
      const pathPrefix = "m/44'/60'/0'/0"
      const labels = ['Admin', 'Proposer', 'Batcher', 'Sequencer']
      const hdwallet = hdkey.fromMasterSeed(await bip39.mnemonicToSeed(mnemonic))
      let rekey = {};
      rekey[`Mnemonic`] = `${mnemonic}`;
      for (let i = 0; i < labels.length; i++) {
        const label = labels[i]
        const wallet = hdwallet.derivePath(`${pathPrefix}/${i}`).getWallet()
        const addr = '0x' + wallet.getAddress().toString('hex')
        const pk = wallet.getPrivateKey().toString('hex')
        rekey[`${label}_key`] = pk
        rekey[`${label}_addr`] = addr
      }
      let data = JSON.stringify(rekey, null, 2);
      console.log(rekey);
      fs.writeFileSync(out, data);
    }
  )
