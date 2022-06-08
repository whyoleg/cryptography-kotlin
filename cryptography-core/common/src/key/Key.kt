package dev.whyoleg.cryptography.key

import dev.whyoleg.vio.*


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

//TODO: create keyStore - keychain, jce keystore, file, pkcs12, etc
//TODO: import from keyStore?

//marker interfaces

public interface Key

public interface SecretKey : Key {
    public fun encode(format: SecretKeyFormat): BufferView
    public fun encode(format: SecretKeyFormat, output: BufferView): BufferView
}

public interface KeyPair : Key {
    public val publicKey: PublicKey
    public val privateKey: PrivateKey

    public fun encode(format: KeyPairFormat): BufferView
    public fun encode(format: KeyPairFormat, output: BufferView): BufferView
}

public interface PublicKey : Key {
    public fun encode(format: PublicKeyFormat): BufferView
    public fun encode(format: PublicKeyFormat, output: BufferView): BufferView
}

public interface PrivateKey : Key {
    public fun encode(format: PrivateKeyFormat): BufferView
    public fun encode(format: PrivateKeyFormat, output: BufferView): BufferView
}
