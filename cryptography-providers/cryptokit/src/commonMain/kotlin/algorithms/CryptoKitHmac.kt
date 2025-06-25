/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitHmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        return when (digest) {
            MD5    -> HmacKeyDecoder(SwiftHashAlgorithmMd5, CC_MD5_DIGEST_LENGTH)
            SHA1   -> HmacKeyDecoder(SwiftHashAlgorithmSha1, CC_SHA1_DIGEST_LENGTH)
            SHA256 -> HmacKeyDecoder(SwiftHashAlgorithmSha256, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyDecoder(SwiftHashAlgorithmSha384, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyDecoder(SwiftHashAlgorithmSha512, CC_SHA512_DIGEST_LENGTH)
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        }
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        return when (digest) {
            MD5    -> HmacKeyGenerator(SwiftHashAlgorithmMd5, CC_MD5_BLOCK_BYTES, CC_MD5_DIGEST_LENGTH)
            SHA1   -> HmacKeyGenerator(SwiftHashAlgorithmSha1, CC_SHA1_BLOCK_BYTES, CC_SHA1_DIGEST_LENGTH)
            SHA256 -> HmacKeyGenerator(SwiftHashAlgorithmSha256, CC_SHA256_BLOCK_BYTES, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyGenerator(SwiftHashAlgorithmSha384, CC_SHA384_BLOCK_BYTES, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyGenerator(SwiftHashAlgorithmSha512, CC_SHA512_BLOCK_BYTES, CC_SHA512_DIGEST_LENGTH)
            else   -> throw IllegalStateException("Unsupported hash algorithm: $digest")
        }
    }
}

@OptIn(UnsafeNumber::class)
private class HmacKeyDecoder(
    private val algorithm: SwiftHashAlgorithm,
    private val digestSize: Int,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromByteArrayBlocking(format: HMAC.Key.Format, bytes: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> HmacKey(bytes.copyOf(), algorithm, digestSize)
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

@OptIn(UnsafeNumber::class)
private class HmacKeyGenerator(
    private val algorithm: SwiftHashAlgorithm,
    private val blockSize: Int,
    private val digestSize: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographySystem.getDefaultRandom().nextBytes(blockSize)
        return HmacKey(key, algorithm, digestSize)
    }
}

@OptIn(UnsafeNumber::class)
private class HmacKey(
    private val key: ByteArray,
    algorithm: SwiftHashAlgorithm,
    digestSize: Int,
) : HMAC.Key {
    private val signature = HmacSignature(key.toNSData(), algorithm, digestSize)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

@OptIn(UnsafeNumber::class)
private class HmacSignature(
    private val key: NSData,
    private val algorithm: SwiftHashAlgorithm,
    private val digestSize: Int,
) : SignatureGenerator, SignatureVerifier {
    private fun createFunction() = HmacFunction(
        key = key,
        algorithm = algorithm,
        digestSize = digestSize
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()
}

@OptIn(UnsafeNumber::class)
private class HmacFunction(
    private val key: NSData,
    private val algorithm: SwiftHashAlgorithm,
    private val digestSize: Int,
) : SignFunction, VerifyFunction {
    private var _function: SwiftHmacFunction? = SwiftHmacFunction(algorithm, key)
    private val function: SwiftHmacFunction
        get() = _function ?: error("Function is closed")

    @OptIn(UnsafeNumber::class)
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)

        source.useNSData(startIndex, endIndex, function::doUpdate)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + digestSize)

        return function.doFinal().getIntoByteArray(destination, destinationOffset).also {
            reset()
        }
    }

    override fun signToByteArray(): ByteArray {
        return function.doFinal().toByteArray().also {
            reset()
        }
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        checkBounds(signature.size, startIndex, endIndex)
        return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }

    override fun reset() {
        checkNotNull(_function) { "Function is closed" }
        _function = SwiftHmacFunction(algorithm, key)
    }

    override fun close() {
        _function = null
    }
}
