# cryptography-kotlin






primitive f.e. Digest, has several kinds: Sync, Async, Stream, etc.
one algorithm implementation, f.e. Shake, Sha; can provide several kinds of Digest: Sync + Async
Parameters for one algorithm are be the same
Root Algorithm f.e. RSA or SHA, can have multiple child algorithms, f.e. RSA: RSA-OAEP, RSA-PSS, plain RSA; SHA: SHA1, SHA2 (256, 512), SHA3 (256, 512)


primitive hierarchy - separate

parameters - separate


providing:
* digest - parameters only
* cipher/encryptor/decryptor - key, parameters
* signature/signer/verifier - key, parameters
* key generator/encoder/decoder - parameters
* 
