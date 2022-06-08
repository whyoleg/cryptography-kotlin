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
//TODO: key protection - usages

//marker interfaces

//why do we need this?
public interface Key

public interface SecretKey : Key

public interface KeyPair : Key {
    public val publicKey: PublicKey
    public val privateKey: PrivateKey
}

public interface PublicKey : Key

public interface PrivateKey : Key

public interface KeyGenerationParameters
public interface KeyImportParameters

//TODO: decide on export operation

//public interface KeyOperation<P, I, O> {
//    public operator fun invoke(parameters: P, input: I): O
//}
//
//// marker interface for getting key
//public interface KeyFactoryOperation<P, I, K : Key> : KeyOperation<P, I, K>
//
////generates new key from parameters
//public interface KeyGenerateOperation<P, K : Key> : KeyFactoryOperation<P, Unit, K>
//
////create key instance from some parameters that are already generated
//public interface KeyCreateOperation<P, K : Key> : KeyFactoryOperation<P, Unit, K>
//
////export and import of keys to some external storage: bytes, files, etc.
//public interface KeyImportOperation<P, K : Key> : KeyFactoryOperation<P, KeyStore, K>
//public interface KeyExportOperation<P, R> : KeyOperation<P, KeyStore, R>
//
////derive key from password or other key - TODO: separate interface for password and other key?
//public interface KeyDeriveOperation<P, I, K : Key> : KeyFactoryOperation<P, I, K>
//public interface KeyPasswordDeriveOperation<P, K : Key> : KeyDeriveOperation<P, BufferView, K>
//
////TODO: better name
//public interface KeyMasterKeyDeriveOperation<P, MK : Key, K : Key> : KeyDeriveOperation<P, MK, K>
//
////TODO: key agreement/exchange operation interface
