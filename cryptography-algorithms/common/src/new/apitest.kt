package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.key.*
import kotlin.reflect.*

private fun test() {
    val keyPair = Rsa.KeyPairGenerator.Sync { //builder

    }.generateKeyPair()

    //or async
    RsaOaep.Encryptor.Sync(keyPair.publicKey) {

    }

    val key = Aes.KeyGenerator.Sync {

    }.generateKey()

    //both parameters and builder
    AesGcm.Encryptor.Sync(key)
    AesGcm.Encryptor.Async(key)
    AesGcm.Decryptor.Sync(key)
    AesGcm.Decryptor.Async(key)
    AesGcm.Cipher.Sync(key)
    AesGcm.Cipher.Async(key)

    AesGcm.StreamEncryptor(key)
    AesGcm.StreamDecryptor(key)
    AesGcm.StreamCipher(key)

    AesGcm.BoxEncryptor.Sync(key)
    AesGcm.BoxEncryptor.Async(key)
    AesGcm.BoxDecryptor.Sync(key)
    AesGcm.BoxDecryptor.Async(key)
    AesGcm.BoxCipher.Sync(key)
    AesGcm.BoxCipher.Async(key)

    val key2 = Hmac.KeyGenerator.Async {

    }.generateKey

    Hmac.Signature.Async(key2)
    Hmac.Signer.Async(key2)
    Hmac.Verifier.Sync(key2)

    //or digest?
    Sha1.Hasher.Async()
}

private inline fun <C : Any, B : BaseBoxEncryptor<C>> func(
    cls: KClass<C>,
    block: () -> Id<B>
): B {
    TODO()
}

private fun test2() {
    val s = Encryptor::Sync

    val r = func(String::class, BoxEncryptor::Sync)

    val keyPair = Rsa(KeyPairGenerator::Sync) {

    }

    RsaOaep(Encryptor::Sync, keyPair.publicKey) {

    }

    Aes(KeyGenerator::Sync) {

    }

    AesGcm(Encryptor::Sync, key)
    AesGcm(Cipher::Async, key)
}

public object Aes {
    public object KeyGenerator {
        public object Sync
        public object Async
    }
}

public interface Id<C>

public interface Encryptor {
    public interface Sync : Encryptor
    public companion object {
        public inline fun Sync(): Id<Sync> = TODO()
    }
}

public object SBEID : Id<SyncBoxEncryptor<Any?>>

public object BoxEncryptor {
    public inline fun <C> Sync(): Id<SyncBoxEncryptor<C>> = SBEID
}

public interface BaseBoxEncryptor<C>

public interface SyncBoxEncryptor<C> : BaseBoxEncryptor<C>





























