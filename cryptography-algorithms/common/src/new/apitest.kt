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
    val s = Encryptor::Sync

    val r = func(String::class, BoxEncryptor::sync)
    val r2 = func(String::class, BoxEncryptor::async)

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

public object Encryptor {
    public inline fun sync(): Id<SyncEncryptor> = TODO()
    public inline fun async(): Id<AsyncEncryptor> = TODO()
}

public interface BaseEncryptor
public interface SyncEncryptor : BaseEncryptor
public interface AsyncEncryptor : BaseEncryptor

public object BoxEncryptor {
    public inline fun <C> sync(): Id<SyncBoxEncryptor<C>> = TODO()
    public inline fun <C> async(): Id<AsyncBoxEncryptor<C>> = TODO()
}

public interface BaseBoxEncryptor<C>

public interface SyncBoxEncryptor<C> : BaseBoxEncryptor<C>
public interface AsyncBoxEncryptor<C> : BaseBoxEncryptor<C>





























