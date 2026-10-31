/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitHmac : BaseHmac<CryptoKitHmac.HmacDigest>() {
    class HmacDigest(val algorithm: DwcHashAlgorithm, val digestSize: Int, val blockSize: Int)

    override fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): HmacDigest = when (digest) {
        MD5    -> HmacDigest(DwcHashAlgorithmMd5, CC_MD5_DIGEST_LENGTH, CC_MD5_BLOCK_BYTES)
        SHA1   -> HmacDigest(DwcHashAlgorithmSha1, CC_SHA1_DIGEST_LENGTH, CC_SHA1_BLOCK_BYTES)
        SHA256 -> HmacDigest(DwcHashAlgorithmSha256, CC_SHA256_DIGEST_LENGTH, CC_SHA256_BLOCK_BYTES)
        SHA384 -> HmacDigest(DwcHashAlgorithmSha384, CC_SHA384_DIGEST_LENGTH, CC_SHA384_BLOCK_BYTES)
        SHA512 -> HmacDigest(DwcHashAlgorithmSha512, CC_SHA512_DIGEST_LENGTH, CC_SHA512_BLOCK_BYTES)
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
        private val signature = HmacSignature(key.toNSData(), resolvedDigest.algorithm, resolvedDigest.digestSize)
        override fun signatureGenerator(): SignatureGenerator = signature
        override fun signatureVerifier(): SignatureVerifier = signature
    }
}

@OptIn(UnsafeNumber::class)
private class HmacSignature(
    private val key: NSData,
    private val algorithm: DwcHashAlgorithm,
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
    private val algorithm: DwcHashAlgorithm,
    private val digestSize: Int,
) : SignFunction, VerifyFunction {
    private var _function: DwcHmacFunction? = DwcHmacFunction(algorithm, key)
    private val function: DwcHmacFunction
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
        _function = DwcHmacFunction(algorithm, key)
    }

    override fun close() {
        _function = null
    }
}
