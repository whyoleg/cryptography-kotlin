package dev.whyoleg.cryptography.key

//marker interfaces

public interface Key

public interface SecretKey : Key

public interface KeyPair : Key //TODO: add public + private as properties?

public interface PublicKey : Key

public interface PrivateKey : Key

//derive key, key aggreement

/*
    KeyGenerator - generate symmetric key
    KeyPairGenerator - generate public + private key

    KeyFactory/SecretKeyFactory - create/derive key from parameters

    KeyAgreement - derive shared secret key between two parties

    JCE has: KeyFactory, KeyPairGenerator, KeyAgreement, KeyGenerator, SecretKeyFactory
    WebCrypto has: import key, generate key, derive key
    //KeyStore
 */
