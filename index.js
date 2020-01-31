const bigInt = require('big-integer');

class RSA {
  static generate(bits) {
    const e = bigInt(2).pow(16).next(); //2^16 + 1 = 65537.
    console.log();
    console.log();
    console.log("Public Key Exponent (e):" + e.toString())
    let p, q, totient;
  
    do {
      p = this.randomPrime(bits / 2);
      q = this.randomPrime(bits / 2);
      totient = bigInt.lcm( //Was changed in PKCS v2 from totient = p.prev().multiply(q.prev());
        p.prev(), //p-1
        q.prev() //q-1
      );
    } while (bigInt.gcd(e, totient).notEquals(1) || p.minus(q).abs().shiftRight(bits / 2 - 100).isZero());
    
    console.log("Random Prime (p): " + p.toString());
    console.log("Random Prime (q): " + q.toString());
    console.log("Totient (lcm of (p-1)(q-1)): " + totient.toString());

    return {
      e, 
      n: p.multiply(q), //Public Key
      d: e.modInv(totient), //Private Key
    };
  }

  static randomPrime(bits) {
    const min = bigInt.one.shiftLeft(bits - 1);
    const max = bigInt.one.shiftLeft(bits).prev();
    
    while (true) {
      let p = bigInt.randBetween(min, max);
      if (p.isProbablePrime(256)) {
        return p;
      } 
    }
  }

  static encrypt(encodedMsg, n, e) {
    return bigInt(encodedMsg).modPow(e, n);
  }

  static decrypt(encryptedMsg, d, n) {
    return bigInt(encryptedMsg).modPow(d, n); 
  }

  static encode(str) { //We encode (pad) the message to avoid attackers listening to the communication channel and creating a 
    //dictionary of likely ciphertexts that may match a existing known or entry.
    const codes = str
      .split('')
      .map(i => i.charCodeAt())
      .join('');

    return bigInt(codes);
  }

  static decode(code) {
    const stringified = code.toString();
    let string = '';

    for (let i = 0; i < stringified.length; i += 2) {
      let num = Number(stringified.substr(i, 2));
      
      if (num <= 30) {
        string += String.fromCharCode(Number(stringified.substr(i, 3)));
        i++;
      } else {
        string += String.fromCharCode(num);
      }
    }

    return string;
  }
}

//const RSA = require('.');

// Message
const message = 'Hello';

// Generate RSA keys (bits), max is 232 digits (768 bits), JS limit?
const keys = RSA.generate(100);

console.log();
console.log('-------------------------------------------------');
console.log();
console.log('Keys');
console.log('Public Key (n = p * q):', keys.n.toString()); //Public key
console.log('Public Key Length: ' + keys.n.toString().length + ' digits (' + keys.n.toString(2).length + ' bits)');
console.log();
console.log('Private Key (d = e multiplicative inverse (totient)):', keys.d.toString()); //Private Key
console.log('Private Key Length: ' + keys.d.toString().length + ' digits (' + keys.d.toString(2).length + ' bits)');
const encoded_message = RSA.encode(message);
const encrypted_message = RSA.encrypt(encoded_message, keys.n, keys.e);
const decrypted_message = RSA.decrypt(encrypted_message, keys.d, keys.n);
const decoded_message = RSA.decode(decrypted_message);

console.log();
console.log('-------------------------------------------------');
console.log();
console.log('Message:', message);
console.log('Encoded:', encoded_message.toString());
console.log('Encrypted (c = encoded message (m) ^ e modulo n):', encrypted_message.toString());
console.log('Decrypted (m = encrypted message (c) ^ d modulo n):', decrypted_message.toString());
console.log('Decoded:', decoded_message.toString());
console.log();
console.log('Correct?', message === decoded_message);
console.log();
console.log();