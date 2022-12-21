package dev.whyoleg.cryptography.key

/**
 * TODO
 *  - key / keypair / symmetric(secret) key / asymmetric (private + public) key
 *  - derive key
 *  - key agreement (?)
 *  - key exchange (?)
 *  - keystore/keymanager/keychain/keyring
 *  - import key
 *  - export key
 *  - wrap key
 *  - unwrap key
 *  - key formats
 *  - key usages
 */

//Key format: RAW (Bytes), PEM, DER, JWK, PKCS-12
//Destination: java key store, key chain, file, secure enclave (?)

public sealed interface KeyFormat
public sealed interface KeyPairFormat
public sealed interface SymmetricKeyFormat
public sealed interface PublicKeyFormat
public sealed interface PrivateKeyFormat

