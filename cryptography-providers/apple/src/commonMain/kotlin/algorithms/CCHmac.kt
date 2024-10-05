/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCHmac : HMAC {
    override fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<HMAC.Key.Format, HMAC.Key> {
        return when (digest) {
            SHA1   -> HmacKeyDecoder(kCCHmacAlgSHA1, CC_SHA1_BLOCK_BYTES, CC_SHA1_DIGEST_LENGTH)
            SHA224 -> HmacKeyDecoder(kCCHmacAlgSHA224, CC_SHA224_BLOCK_BYTES, CC_SHA224_DIGEST_LENGTH)
            SHA256 -> HmacKeyDecoder(kCCHmacAlgSHA256, CC_SHA256_BLOCK_BYTES, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyDecoder(kCCHmacAlgSHA384, CC_SHA384_BLOCK_BYTES, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyDecoder(kCCHmacAlgSHA512, CC_SHA512_BLOCK_BYTES, CC_SHA512_DIGEST_LENGTH)
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
    }

    override fun keyGenerator(digest: CryptographyAlgorithmId<Digest>): KeyGenerator<HMAC.Key> {
        return when (digest) {
            SHA1   -> HmacKeyGenerator(kCCHmacAlgSHA1, CC_SHA1_BLOCK_BYTES, CC_SHA1_DIGEST_LENGTH)
            SHA224 -> HmacKeyGenerator(kCCHmacAlgSHA224, CC_SHA224_BLOCK_BYTES, CC_SHA224_DIGEST_LENGTH)
            SHA256 -> HmacKeyGenerator(kCCHmacAlgSHA256, CC_SHA256_BLOCK_BYTES, CC_SHA256_DIGEST_LENGTH)
            SHA384 -> HmacKeyGenerator(kCCHmacAlgSHA384, CC_SHA384_BLOCK_BYTES, CC_SHA384_DIGEST_LENGTH)
            SHA512 -> HmacKeyGenerator(kCCHmacAlgSHA512, CC_SHA512_BLOCK_BYTES, CC_SHA512_DIGEST_LENGTH)
            else   -> throw CryptographyException("Unsupported hash algorithm: $digest")
        }
    }
}

private class HmacKeyDecoder(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val keySizeBytes: Int,
    private val digestSize: Int,
) : KeyDecoder<HMAC.Key.Format, HMAC.Key> {
    override fun decodeFromByteArrayBlocking(format: HMAC.Key.Format, bytes: ByteArray): HMAC.Key = when (format) {
        HMAC.Key.Format.RAW -> {
            require(bytes.size == keySizeBytes) { "Invalid key size: ${bytes.size}, expected: $keySizeBytes" }
            wrapKey(hmacAlgorithm, bytes.copyOf(), digestSize)
        }
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacKeyGenerator(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val keySizeBytes: Int,
    private val digestSize: Int,
) : KeyGenerator<HMAC.Key> {
    override fun generateKeyBlocking(): HMAC.Key {
        val key = CryptographyRandom.nextBytes(keySizeBytes)
        return wrapKey(hmacAlgorithm, key, digestSize)
    }
}

private fun wrapKey(
    hmacAlgorithm: CCHmacAlgorithm,
    key: ByteArray,
    digestSize: Int,
): HMAC.Key = object : HMAC.Key {
    private val signature = HmacSignature(hmacAlgorithm, key, digestSize)
    override fun signatureGenerator(): SignatureGenerator = signature
    override fun signatureVerifier(): SignatureVerifier = signature

    override fun encodeToByteArrayBlocking(format: HMAC.Key.Format): ByteArray = when (format) {
        HMAC.Key.Format.RAW -> key.copyOf()
        HMAC.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class HmacSignature(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val key: ByteArray,
    private val digestSize: Int,
) : SignatureGenerator, SignatureVerifier {

    @OptIn(UnsafeNumber::class)
    private fun createFunction(): HmacFunction {
        val context = nativeHeap.alloc<CCHmacContext>().ptr
        // TODO: error handle?
        key.usePinned {
            CCHmacInit(context, hmacAlgorithm, it.safeAddressOf(0), key.size.convert())
        }
        return HmacFunction(digestSize, Resource(context, nativeHeap::free))
    }

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()
}

private class HmacFunction(
    private val digestSize: Int,
    private val context: Resource<CPointer<CCHmacContext>>,
) : SignFunction, VerifyFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {

    @OptIn(UnsafeNumber::class)
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)

        val context = context.access()
        source.usePinned {
            CCHmacUpdate(context, it.safeAddressOf(startIndex), (endIndex - startIndex).convert())
        }
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        checkBounds(destination.size, destinationOffset, destinationOffset + digestSize)

        val context = context.access()
        destination.usePinned {
            CCHmacFinal(context, it.safeAddressOf(destinationOffset))
        }
        close()
        return digestSize
    }

    override fun signToByteArray(): ByteArray {
        val output = ByteArray(digestSize)
        signIntoByteArray(output)
        return output
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        checkBounds(signature.size, startIndex, endIndex)
        return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }
}
