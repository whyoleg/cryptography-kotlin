# cryptography-kotlin

primitive f.e. Digest, has several kinds: Sync, Async, Stream, etc.
one algorithm implementation, f.e. Shake, Sha; can provide several kinds of Digest: Sync + Async
Parameters for one algorithm are be the same
Root Algorithm f.e. RSA or SHA, can have multiple child algorithms, f.e. RSA: RSA-OAEP, RSA-PSS, plain RSA; SHA: SHA1, SHA2 (256, 512),
SHA3 (256, 512)

primitive hierarchy - separate

parameters - separate

providing:

* digest - parameters only
* cipher/encryptor/decryptor - key, parameters
* signature/signer/verifier - key, parameters
* key generator/encoder/decoder - parameters
*

creating primitive:

* select supported kind of primitive - f.e. sync or async
* provide parameters - via parameters instance or via builder
    * required parameters - should be provided in place - like KEY
    * optional parameters - provided in builder - like key size of AES with default to 256


testing:
* hash:
  * random input generated
  * every engine creates digest from random input and store it to some file/server
  * check that all digests has the same digest
  * tests of predefined digests
* symmetric cipher:
  * random input generated
  * every engine encrypts data with random key and store it to some file/server
  * every engine decrypts data with that key
* mac:
  * generate
* asymmetric cipher:
  * generate
  * encrypt
  * decrypt
* signature:
  * generate
  * sign
  * verify




- from key
symmetric encryption - encryptor|boxEncryptor, decryptor|boxDecryptor, cipher|boxCipher (sync, async stream)
asymmetric - encryptor (public), decryptor (private)
signature|mac - same as symmetric vs asymmetric

hash(digest) - no key
random - no key, just parameters