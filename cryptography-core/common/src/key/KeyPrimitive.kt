package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*
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

//TODO: rename to KeyEncodePrimitive?

public sealed interface KeyPrimitive2<Format : KeyFormat> : CryptographyPrimitive {
    public fun encode(data: KeyData<Format>): BufferView
    public fun encode(format: Format, output: BufferView): BufferView

    public suspend fun encodeSuspend(format: Format): BufferView
    public suspend fun encodeSuspend(format: Format, output: BufferView): BufferView
}

public interface SymmetricKeyPrimitive : KeyPrimitive<SymmetricKeyFormat>
public sealed interface AsymmetricKeyPrimitive<Format : AsymmetricKeyFormat> : KeyPrimitive<Format>

public interface PublicKeyPrimitive : AsymmetricKeyPrimitive<PublicKeyFormat>

public interface PrivateKeyPrimitive : AsymmetricKeyPrimitive<PrivateKeyFormat>

public interface KeyPairPrimitive : KeyPrimitive<KeyPairFormat> {
    public val publicKey: PublicKeyPrimitive
    public val privateKey: PrivateKeyPrimitive
}

//TODO!!!

//stores locally: f.e. android keychain or ios/mac keychain or windows keychain?
// or file? or remote?
//public interface KeyStorePrimitive {
//}

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
