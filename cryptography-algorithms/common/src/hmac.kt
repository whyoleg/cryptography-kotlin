package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.primitives.*
import dev.whyoleg.vio.*

//user: function (algorithm(hmac) -> builder -> primitive)
//provider: algorithm(hmac) -> builder -> parameters -> primitive

public interface Algorithm //implemented in library
public interface Builder //created internally, used by user
public interface Parameters //created internally user by provider
public interface Primitive //implemented by provider
public interface Key //implemented by provider

//secret key is always jsut a bytearray?

public interface Provider {

    //hash, random
    public fun create(
        algorithm: Algorithm,
        build: Builder.() -> Unit
    ): Primitive

    //generateKey - secret, public, private, pair
    public fun generateKey(
        algorithm: Algorithm,
        build: Builder.() -> Unit
    ): Primitive

    //decodeKey
    public fun importKey(
        algorithm: Algorithm,
        input: BufferView,
        build: Builder.() -> Unit
    ): Primitive

    //derive secret KEY from some input
    public fun deriveKey(
        algorithm: Algorithm
    ): Primitive
}

//ecdh - local private key + remote public key

//need hash for generation - can produce key or hmac
//need hash for decode - produce key
//need hash for import - produce hmac
//need nothing for encode
//need nothing for mac

//secret key, mac primitive, export, import, generate
public interface Hmac : SecretKey, KeyEncodePrimitive<SecretKeyFormat>, MacPrimitive {
    public interface Factory : KeyDecodePrimitive<SecretKeyFormat, Hmac>, KeyGeneratePrimitive<Hmac>

    public companion object {
        public inline fun parameters(block: HmacBuilder.() -> Unit): HmacParameters {
            TODO()
        }
    }
}

public sealed interface HmacParameters {
    public val hash: HashParameters

    public sealed interface Builder {
        public fun hash(hash: HashParameters)
    }

    public object Factory {
        public fun createBuilder(): HmacBuilder
        public fun build(builder: HmacBuilder): HmacParameters
    }
}

internal class HmacParametersImpl : HmacParameters, HmacBuilder {
    override var hash: HashParameters = Sha.SHA256

    override fun hash(hash: HashParameters) {
        this.hash = hash
    }
}

//public object Hmac


provider.import(Hmac) {

keySize(128.bits)
}

provider.generateKey(Hmac) {
    keySize(128.bits)
}

provider.decodeKey(Hmac, view) {
    hash(SHA1)
}
