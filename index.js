const fetch = require('node-fetch');
const ecc = require('eosjs-ecc');
const { Api, JsonRpc, Serialize } = require('eosjs');
const { JsSignatureProvider } = require('eosjs/dist/eosjs-jssig');
const { base64ToBinary } = require('eosjs/dist/eosjs-numeric');

class Signer {

  constructor(props) {
    this.opts = props;
    this.esrAbiProvider = {
        getRawAbi: function (accountName="") {
          // base64 abi for eosio signing request; includes signing_request and identity structs
          // with {scope: name}
          // const base64Abi = "DmVvc2lvOjphYmkvMS4yBgxhY2NvdW50X25hbWUEbmFtZQthY3Rpb25fbmFtZQRuYW1lD3Blcm1pc3Npb25fbmFtZQRuYW1lC2NoYWluX2FsaWFzBXVpbnQ4CGNoYWluX2lkC2NoZWNrc3VtMjU2DXJlcXVlc3RfZmxhZ3MFdWludDgJEHBlcm1pc3Npb25fbGV2ZWwAAgVhY3RvcgxhY2NvdW50X25hbWUKcGVybWlzc2lvbg9wZXJtaXNzaW9uX25hbWUGYWN0aW9uAAQHYWNjb3VudAxhY2NvdW50X25hbWUEbmFtZQthY3Rpb25fbmFtZQ1hdXRob3JpemF0aW9uEnBlcm1pc3Npb25fbGV2ZWxbXQRkYXRhBWJ5dGVzCWV4dGVuc2lvbgACBHR5cGUGdWludDE2BGRhdGEFYnl0ZXMSdHJhbnNhY3Rpb25faGVhZGVyAAYKZXhwaXJhdGlvbg50aW1lX3BvaW50X3NlYw1yZWZfYmxvY2tfbnVtBnVpbnQxNhByZWZfYmxvY2tfcHJlZml4BnVpbnQzMhNtYXhfbmV0X3VzYWdlX3dvcmRzCXZhcnVpbnQzMhBtYXhfY3B1X3VzYWdlX21zBXVpbnQ4CWRlbGF5X3NlYwl2YXJ1aW50MzILdHJhbnNhY3Rpb24SdHJhbnNhY3Rpb25faGVhZGVyAxRjb250ZXh0X2ZyZWVfYWN0aW9ucwhhY3Rpb25bXQdhY3Rpb25zCGFjdGlvbltdFnRyYW5zYWN0aW9uX2V4dGVuc2lvbnMLZXh0ZW5zaW9uW10JaW5mb19wYWlyAAIDa2V5BnN0cmluZwV2YWx1ZQVieXRlcw9zaWduaW5nX3JlcXVlc3QABQhjaGFpbl9pZAp2YXJpYW50X2lkA3JlcQt2YXJpYW50X3JlcQVmbGFncw1yZXF1ZXN0X2ZsYWdzCGNhbGxiYWNrBnN0cmluZwRpbmZvC2luZm9fcGFpcltdCGlkZW50aXR5AAIFc2NvcGUEbmFtZQpwZXJtaXNzaW9uEXBlcm1pc3Npb25fbGV2ZWw/EXJlcXVlc3Rfc2lnbmF0dXJlAAIGc2lnbmVyBG5hbWUJc2lnbmF0dXJlCXNpZ25hdHVyZQEAAAA+uzxVcghpZGVudGl0eQAAAAAAAgp2YXJpYW50X2lkAgtjaGFpbl9hbGlhcwhjaGFpbl9pZAt2YXJpYW50X3JlcQQGYWN0aW9uCGFjdGlvbltdC3RyYW5zYWN0aW9uCGlkZW50aXR5AAA=="
          // without {scope: name}
          const base64Abi = "DmVvc2lvOjphYmkvMS4yBgxhY2NvdW50X25hbWUEbmFtZQthY3Rpb25fbmFtZQRuYW1lD3Blcm1pc3Npb25fbmFtZQRuYW1lC2NoYWluX2FsaWFzBXVpbnQ4CGNoYWluX2lkC2NoZWNrc3VtMjU2DXJlcXVlc3RfZmxhZ3MFdWludDgJEHBlcm1pc3Npb25fbGV2ZWwAAgVhY3RvcgxhY2NvdW50X25hbWUKcGVybWlzc2lvbg9wZXJtaXNzaW9uX25hbWUGYWN0aW9uAAQHYWNjb3VudAxhY2NvdW50X25hbWUEbmFtZQthY3Rpb25fbmFtZQ1hdXRob3JpemF0aW9uEnBlcm1pc3Npb25fbGV2ZWxbXQRkYXRhBWJ5dGVzCWV4dGVuc2lvbgACBHR5cGUGdWludDE2BGRhdGEFYnl0ZXMSdHJhbnNhY3Rpb25faGVhZGVyAAYKZXhwaXJhdGlvbg50aW1lX3BvaW50X3NlYw1yZWZfYmxvY2tfbnVtBnVpbnQxNhByZWZfYmxvY2tfcHJlZml4BnVpbnQzMhNtYXhfbmV0X3VzYWdlX3dvcmRzCXZhcnVpbnQzMhBtYXhfY3B1X3VzYWdlX21zBXVpbnQ4CWRlbGF5X3NlYwl2YXJ1aW50MzILdHJhbnNhY3Rpb24SdHJhbnNhY3Rpb25faGVhZGVyAxRjb250ZXh0X2ZyZWVfYWN0aW9ucwhhY3Rpb25bXQdhY3Rpb25zCGFjdGlvbltdFnRyYW5zYWN0aW9uX2V4dGVuc2lvbnMLZXh0ZW5zaW9uW10JaW5mb19wYWlyAAIDa2V5BnN0cmluZwV2YWx1ZQVieXRlcw9zaWduaW5nX3JlcXVlc3QABQhjaGFpbl9pZAp2YXJpYW50X2lkA3JlcQt2YXJpYW50X3JlcQVmbGFncw1yZXF1ZXN0X2ZsYWdzCGNhbGxiYWNrBnN0cmluZwRpbmZvC2luZm9fcGFpcltdCGlkZW50aXR5AAEKcGVybWlzc2lvbhFwZXJtaXNzaW9uX2xldmVsPxFyZXF1ZXN0X3NpZ25hdHVyZQACBnNpZ25lcgRuYW1lCXNpZ25hdHVyZQlzaWduYXR1cmUBAAAAPrs8VXIIaWRlbnRpdHkAAAAAAAIKdmFyaWFudF9pZAILY2hhaW5fYWxpYXMIY2hhaW5faWQLdmFyaWFudF9yZXEEBmFjdGlvbghhY3Rpb25bXQt0cmFuc2FjdGlvbghpZGVudGl0eQAA="
          return Promise.resolve({ abi: base64ToBinary(base64Abi), accountName: accountName });
        }
    };

    this.api = new Api({
        rpc: new JsonRpc(this.opts.server, { fetch }),
        chain_id: this.opts.chain_id,
        textDecoder: new TextDecoder(),
        textEncoder: new TextEncoder(),
        signatureProvider: new JsSignatureProvider(this.opts.signingKeys),
    });
  }

  checkTransactionHeader = async (transaction) => {
    if (!transaction.expiration || !transaction.ref_block_num || !transaction.ref_block_prefix) {
        const info = await this.api.rpc.get_info();
        const refBlockNum = info.head_block_num;
        const refBlock = await this.api.rpc.get_block(refBlockNum);
        transaction = { ...Serialize.transactionHeader(refBlock, 600), ...transaction };
    }
    return transaction;
  }

  deserializeActions = async (transaction) => {
    transaction.actions = await this.api.deserializeActions(transaction.actions);
    return transaction;
  }

  serializeTransaction = (transaction) => {
    return Buffer.from(this.api.serializeTransaction(transaction));
  }

  signTransaction = async (transaction) => {
    // override abi provider if the action is identity and account is undefined
    if( transaction.actions[0].account === '' && transaction.actions[0].name === 'identity' )
      this.api.abiProvider = this.esrAbiProvider;

    transaction = await this.checkTransactionHeader(transaction);
    transaction.actions = await this.api.serializeActions(transaction.actions);
    const serializedTransaction = this.serializeTransaction(transaction);

    const signatures = transaction.signatures || [];

    if(signatures && signatures.length > 0) {
        for (let sig of transaction.signatures) {
            for (let key of this.opts.signingKeys) {
                const signedKey = ecc.recoverHash(sig, Buffer.from(computeDigest(this.opts.chain_id, transaction, api)).toString('hex'));
                if (ecc.privateToPublic(key) === signedKey) removeItemAll(this.opts.signingKeys, key);
            }
        }
    }

    const signBuf = Buffer.concat([Buffer.from(this.opts.chain_id, "hex"), serializedTransaction, Buffer.from(new Uint8Array(32))]);

    for (let key of this.opts.signingKeys) { signatures.push(ecc.Signature.sign(signBuf, key).toString()); }
    transaction.signatures = signatures;

    return {transaction, serializedTransaction};
  }

  broadcastTransaction = async (transaction, serializedTransaction) => {
    return await this.api.pushSignedTransaction({signatures: transaction.signatures, serializedTransaction});
  }

}

module.exports = Signer;
