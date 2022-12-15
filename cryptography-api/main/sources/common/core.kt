package dev.whyoleg.cryptography.api

public typealias Buffer = ByteArray

//TODO expect/actual
public interface Closeable {
    public fun close()
}

/**
 * TODO
 *  - generate key
 *  - derive key
 *  - key agreement (?)
 *  - key exchange (?)
 *  - keystore/keymanager/keychain/keyring
 *  - import key
 *  - export key
 *  - wrap key
 *  - unwrap key
 *  - key vs key pair
 *  - key formats
 */


/*
    encryption/decryption: AES(CTR, CBC, GCM) +, RSA(OAEP)
    hash: SHA(1, 2, 3) +, SHAKE(128, 256) +
    mac: HMAC(ANY HASH) +, CMAC(AES-CBC) +, GMAC(AES-GCM) +
    sing/verify: RSA(SSA, PSS), ECDSA
    key wrap/unwrap: AES(all + KW), RSA(OAEP)
    derive key: ECDH, HKDF, PBKDF2
    importing key formats: RAW, JWK, PKCS-XXX
    JWT
    certificates (x509)
    decide on random
    key store
    TODO: decide on how to load algorithms -
     dynamic or static,
     cause even using RSA(OAEP) for encryption,
     can be not supported using it for singing
    TODO: does key usages needed?
 */

