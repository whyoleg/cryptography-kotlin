package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.key.*
import kotlin.reflect.*

private inline fun <C : Any, B : BaseBoxEncryptor<C>> func(
    cls: KClass<C>,
    block: () -> Id<B>,
): B {
    TODO()
}

private fun test2() {
    val r = func(String::class, BoxEncryptor::sync)
    val r2 = func(String::class, BoxEncryptor::async)

    Encryptor::sync
    Encryptor::async
    Encryptor::stream

    val keyPair = Rsa(KeyPairGenerator::Sync) {

    }

    RsaOaep(Encryptor::Sync, keyPair.publicKey) {

    }

    Aes(KeyGenerator::Sync) {

    }

    val encryptor = AesGcm(Encryptor::sync)
    val boxEncryptor = AesGcm(BoxEncryptor::async)

    AesGcm(Cipher::Async, key)

    BoxEncryptor.sync(AesGcm, key, parameters)

    Cipher.async(AesGcm, key, parameters)
    Cipher.stream(AesGcm, key) {

    }

    BoxCipher.sync(AesGcm, key) {

    }

    Encryptor.sync(RsaOaep, key) {

    }

    GCP KMS :
    async: generate key, import public key, export public key, encrypt S, decrypt S, decrypt A, sign A
    sync: encrypt A, verify A

    //encode/decode key
    //intro: import(from remote, or from paramteres)/generate key per algorithm -> cipher, signature
    //intro: digest
    //intro: random


    //algorithm(type of primitive) + id(kind of primitive) + parameters
    //algorithm + id + key + parameters
}

public interface BoxEncryptorProvider {
    public fun BoxEncryptor.sync2()
}

public object AesGcm<C>

public inline operator fun <R : BaseEncryptor> AesGcm<*>.invoke(
    block: () -> Id<R>
): R {

}

public inline operator fun <C, R : BaseBoxEncryptor<C>> AesGcm<C>.invoke(
    block: () -> Id<R>
): R {

}

public interface Id<C>

public interface EncryptorProvider {
    public operator fun <E : BaseEncryptor, K> invoke(
        block: () -> Id<E>,
        key: K
    ): E
}

public object Encryptor {
    public inline fun sync(): Id<SyncEncryptor> = TODO()
    public inline fun async(): Id<AsyncEncryptor> = TODO()
    public inline fun stream(): Id<StreamEncryptor> = TODO()
}

public interface BaseEncryptor
public interface SyncEncryptor : BaseEncryptor
public interface AsyncEncryptor : BaseEncryptor
public interface StreamEncryptor : BaseEncryptor

public object BoxEncryptor {
    public inline fun <C> sync(): Id<SyncBoxEncryptor<C>> = TODO()
    public inline fun <C> async(): Id<AsyncBoxEncryptor<C>> = TODO()
}

public interface BaseBoxEncryptor<C>

public interface SyncBoxEncryptor<C> : BaseBoxEncryptor<C>
public interface AsyncBoxEncryptor<C> : BaseBoxEncryptor<C>

public object KeyPairGenerator {
    public inline fun <C> sync(): Id<SyncKeyPairGenerator<C>> = TODO()
    public inline fun <C> async(): Id<AsyncKeyPairGenerator<C>> = TODO()
}

public interface BaseKeyPairGenerator<K>
public interface SyncKeyPairGenerator<K> : BaseKeyPairGenerator<K>
public interface AsyncKeyPairGenerator<K> : BaseKeyPairGenerator<K>




























