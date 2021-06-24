// IMPORT
const crypto = require('crypto');
const nacl = require('tweetnacl');
const axios = require('axios');

// FUNCTION
const SASEUL = {};
SASEUL.sha256 = x => crypto.createHash('sha256').update(x).digest('hex');
SASEUL.rmd160 = x => crypto.createHash('rmd160').update(x).digest('hex');

SASEUL.stringToUnicode = (str) => {
  if (!str) {
    return '';
  }

  let u = '';

  for (let i = 0; i < str.length; i++) {
    let s = str[i].charCodeAt(0).toString(16);

    if (s.length > 2) {
      u+= '\\u' + s;
    } else {
      u+= str[i];
    }
  }

  return u;
};
SASEUL.randomHexString = (byte) => {
  let hex = '';

  for (let i = 0; i < byte * 2; i++) {
    let r = Math.floor(Math.random() * 16);
    hex += r.toString(16);
  }

  return hex;
};
SASEUL.hexToByte = (str) => {
  if (!str) {
    return new Uint8Array();
  }

  var a = [];
  for (var i = 0, len = str.length; i < len; i += 2) {
    a.push(parseInt(str.substr(i, 2), 16));
  }

  return new Uint8Array(a);
};
SASEUL.byteToHex = (byte) => {
  if (!byte) {
    return '';
  }

  var hexStr = '';
  for (var i = 0; i < byte.length; i++) {
    var hex = (byte[i] & 0xff).toString(16);
    hex = (hex.length === 1) ? '0' + hex : hex;
    hexStr += hex;
  }

  return hexStr.toLowerCase();
};
SASEUL.stringToByte = (str) => {
  var buf = new Uint8Array(new ArrayBuffer(str.length));
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    buf[i] = str.charCodeAt(i);
  }
  return buf;
};
SASEUL.thash = (str) => {
  if (typeof str !== 'string') {
    str = JSON.stringify(str).replace(/\//gi, '\\/');
  }

  str = SASEUL.stringToUnicode(str);

  return SASEUL.sha256(str);
};
SASEUL.makeAddress = (public_key) => {
  let p0 = '0x00';
  let p1 = '0x6f';
  let address, s0, s1, s2;

  s0 = SASEUL.sha256(p0 + public_key);
  s0 = SASEUL.rmd160(s0);
  s1 = p1 + s0;

  s2 = SASEUL.sha256(s1);
  s2 = SASEUL.sha256(s2);

  address = s1 + s2.substr(0, 4);

  return address;
};
SASEUL.makeCid = (hash, prefix) => {
  var p0 = '0x00';
  var p1 = prefix;
  var address, s0, s1, s2;

  s0 = SASEUL.sha256(p0 + hash);
  s0 = SASEUL.rmd160(s0);
  s1 = p1 + s0;

  s2 = SASEUL.sha256(s1);
  s2 = SASEUL.sha256(s2);

  address = s1 + s2.substr(0, 4);

  return address;
};
SASEUL.makeKeypair = () => {
  let salt = nacl.sign.keyPair();
  let keypair = {};

  keypair.private_key = SASEUL.byteToHex(salt.secretKey).substr(0, 64);
  keypair.public_key = SASEUL.byteToHex(salt.publicKey);
  keypair.address = SASEUL.makeAddress(keypair.public_key);

  return keypair;
};
SASEUL.makePublicKey = function (private_key) {
  let b = SASEUL.hexToByte(private_key);
  let salt = nacl.sign.keyPair.fromSeed(b);

  return SASEUL.byteToHex(salt.publicKey);
};
SASEUL.signature = function (str, private_key, public_key) {
  return SASEUL.byteToHex(nacl.sign.detached(
      SASEUL.stringToByte(str), SASEUL.hexToByte(private_key + public_key)
  ));
};
SASEUL.isValidSignature = function (str, public_key, signature) {
  return nacl.sign.detached.verify(
      SASEUL.stringToByte(str), SASEUL.hexToByte(signature), SASEUL.hexToByte(public_key)
  );
};
SASEUL.microseconds = function () {
  let d = new Date();

  return (d.getTime() * 1000) + d.getMilliseconds();
};

SASEUL.request = async (host, req) => {
  try {
    let form = {
      request: JSON.stringify(req)
    };

    let result = await axios(`${host}/request`, {
      method: 'POST',
      data: form
    });

    return result.data;
  } catch (e) {
    throw e.response.data;
  }
};
SASEUL.transaction = async (host, tx, privatekey) => {
  try {
    let thash = SASEUL.thash(tx);
    let publickey = SASEUL.makePublicKey(privatekey);
    let sign = SASEUL.signature(thash, privatekey, publickey);

    let form = {
      transaction: JSON.stringify(tx),
      public_key: publickey,
      signature: sign,
    };

    let result = await axios(`${host}/sendtransaction`, {
      method: 'POST',
      data: form
    });

    return result.data;
  } catch (e) {
    throw e.response.data;
  }
};

module.exports = {
  SASEUL
};
