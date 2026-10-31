/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCHmac : BaseHmac<CCHmac.HmacDigest>() {
    class HmacDigest(val algorithm: CCHmacAlgorithm, val digestSize: Int, val blockSize: Int)

    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): HmacDigest = when (digest) {
        SHA1   -> HmacDigest(kCCHmacAlgSHA1, CC_SHA1_DIGEST_LENGTH, CC_SHA1_BLOCK_BYTES)
        SHA224 -> HmacDigest(kCCHmacAlgSHA224, CC_SHA224_DIGEST_LENGTH, CC_SHA224_BLOCK_BYTES)
        SHA256 -> HmacDigest(kCCHmacAlgSHA256, CC_SHA256_DIGEST_LENGTH, CC_SHA256_BLOCK_BYTES)
        SHA384 -> HmacDigest(kCCHmacAlgSHA384, CC_SHA384_DIGEST_LENGTH, CC_SHA384_BLOCK_BYTES)
        SHA512 -> HmacDigest(kCCHmacAlgSHA512, CC_SHA512_DIGEST_LENGTH, CC_SHA512_BLOCK_BYTES)
        else   -> unsupportedParameter("hash algorithm", digest.name)
    }

    override fun blockSize(digest: HmacDigest): Int = digest.blockSize

    override fun wrapKey(digest: CryptographyAlgorithmId<Digest>, resolvedDigest: HmacDigest, rawKey: ByteArray): HMAC.Key =
        HmacKey(digest, resolvedDigest, rawKey)

    private class HmacKey(
        digest: CryptographyAlgorithmId<Digest>,
        resolvedDigest: HmacDigest,
        key: ByteArray,
    ) : BaseKey(digest, key) {
        private val signature = HmacSignature(key, resolvedDigest.algorithm, resolvedDigest.digestSize)
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}

private class HmacSignature(
    private val key: ByteArray,
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val digestSize: Int,
) : SignatureGenerator, SignatureVerifier {
    private fun createFunction() = HmacFunction(
        hmacAlgorithm = hmacAlgorithm,
        key = key,
        digestSize = digestSize,
        context = NativeResource(nativeHeap.alloc<CCHmacContext>().ptr, nativeHeap::free)
    )

    override fun createSignFunction(): SignFunction = createFunction()
    override fun createVerifyFunction(): VerifyFunction = createFunction()
}

private class HmacFunction(
    private val hmacAlgorithm: CCHmacAlgorithm,
    private val key: ByteArray,
    private val digestSize: Int,
    private val context: NativeResource<CPointer<CCHmacContext>>,
) : SignFunction, VerifyFunction, AutoCloseable by context {
    init {
        reset()
    }

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
        reset()
        return digestSize
    }

    override fun signToByteArray(): ByteArray {
        val output = ByteArray(digestSize)
        val _ = signIntoByteArray(output)
        return output
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        checkBounds(signature.size, startIndex, endIndex)
        return signToByteArray().contentEquals(signature.copyOfRange(startIndex, endIndex))
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }

    @OptIn(UnsafeNumber::class)
    override fun reset() {
        val context = context.access()
        key.usePinned {
            CCHmacInit(context, hmacAlgorithm, it.safeAddressOf(0), key.size.convert())
        }
    }
}
