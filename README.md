<h1>A simplistic Node.js implementation of RSA encryption/decryption</h1>

This is a basic and simplistic implementation of RSA in JS which used to understand the implementation/math required for encryption/decryption and opportunities for hacking RSA using Quantum Computing.

<u>RSA in General</u>

If you are looking for a nice article on RSA and a small practical example, this might be helpful [https://simple.wikipedia.org/wiki/RSA_algorithm](https://simple.wikipedia.org/wiki/RSA_algorithm)

<u>Hacking RSA using Prime Number Factorization</u>

Hacking RSA uses the numeric public exponent from the public key and tries to calculate its largest common multiple factors (p and q) - from those two numbers you can calculate the Private Key. Using traditional computing to hack "small" RSA public keys can be done with a few modern algorithms, including the currently fastest General Number Field Sieve.

A nice library for General Number Field Sieves is http://cado-nfs.gforge.inria.fr/

You can use this site to factor a prime without having to install anything [https://asecuritysite.com/encryption/factors](https://asecuritysite.com/encryption/factors). Enter the Public Key which gets generated by the code (should be < 100 bits for the site to be able to factor)

<h2>Installation</h2>

```
npm install
```

<h2>Usage</h2>

Edit the index.js file if you would like to edit the size or message being encrypted:
```
// Message
const message = 'Hello';

// Generate RSA keys (bits), max is 232 digits (768 bits)
const keys = RSA.generate(80);
```

Run the code
```
npm run start
```

<h2>Example Output</h2>

```
Public Key Exponent (e):65537
Random Prime (p): 798000088811
Random Prime (q): 563631878177
Totient (lcm of (p-1)(q-1)): 224889144420297550405280

-------------------------------------------------

Keys
Public Key (n = p * q): 449778288841956732777547
Public Key Length: 24 digits (79 bits)

Private Key (d = e multiplicative inverse (totient)): 210473481577786144493313
Private Key Length: 24 digits (78 bits)

-------------------------------------------------

Message: Hello
Encoded: 72101108108111
Encrypted (c = encoded message (m) ^ e modulo n): 426078873740860671226694
Decrypted (m = encrypted message (c) ^ d modulo n): 72101108108111
Decoded: Hello

Correct? true
```

<u>To Do</u>

Utilize the outputs from calculations and format the Private and Public key according to the format. Feel free to submit a pull request :)

<u>Misc Notes</u>

RSA naming scheme changed from bits to digits. 
Then RSA-2048 = 617 digits = RSA-617 -> Now RSA-300 = 300 digits.

<u>Certificate Format</u>
```
-----BEGIN RSA PRIVATE KEY-----
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
-----END RSA PRIVATE KEY——

-----BEGIN RSA PUBLIC KEY-----
RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
-----END RSA PUBLIC KEY-----
```

<h2>Sources/References</h2>

 I utilized the code from [Denys Dovhan](https://github.com/denysdovhan/rsa-labwork) as a reference.