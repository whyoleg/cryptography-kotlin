package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface CryptographyKey : CryptographyMaterial {
    public interface Symmetric : CryptographyKey
    public interface Asymmetric : CryptographyKey
    public interface Public : Asymmetric
    public interface Private : Asymmetric

    public interface Pair : CryptographyMaterial {
        public val publicKey: Public
        public val privateKey: Private
    }
}

//TODO: key agreement, exchange
//TODO: key derive, exchange
//TODO: key factory from some parameters?
//TODO: key store or key chain support

//TODO: decide on encoding and decoding of keys to binary format
//public sealed interface KeyFormat {
//    public sealed interface Symmetric : KeyFormat
//    public sealed interface Asymmetric : KeyFormat
//    public sealed interface Public : Asymmetric
//    public sealed interface Private : Asymmetric
//    public sealed interface Pair : KeyFormat
//
//    public object RAW : Symmetric
//    public object DER : Asymmetric
//    public object PEM : Asymmetric
//    public object PKCS12 : Pair
//    public object JWK : Symmetric, Asymmetric, Pair
//}


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
//TODO: key protection - usages

//TODO: rename to KeyEncodePrimitive?
