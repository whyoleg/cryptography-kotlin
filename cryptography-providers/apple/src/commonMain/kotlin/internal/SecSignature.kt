/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal class SecSignatureVerifier(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = SecVerifyFunction(publicKey, algorithm)
}

internal class SecSignatureGenerator(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = SecSignFunction(privateKey, algorithm)
}

private class SecVerifyFunction(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : VerifyFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureNotClosed() {
        check(!isClosed) { "Already closed" }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)

        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        return verifyError(signature, startIndex, endIndex) == null
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        val error = verifyError(signature, startIndex, endIndex) ?: return
        error("Invalid signature: $error")
    }

    private fun verifyError(signature: ByteArray, startIndex: Int, endIndex: Int): String? = memScoped {
        ensureNotClosed()
        checkBounds(signature.size, startIndex, endIndex)
        val error = alloc<CFErrorRefVar>()
        accumulator.useNSData { data ->
            signature.useNSData { signature ->
                val result = SecKeyVerifySignature(
                    key = publicKey,
                    algorithm = algorithm,
                    signedData = data.retainBridgeAs<CFDataRef>(),
                    error = error.ptr,
                    signature = signature.retainBridgeAs<CFDataRef>()
                )
                when {
                    result -> null
                    else   -> error.value.releaseBridgeAs<NSError>()?.description ?: ""
                }
            }
        }
    }.also {
        close()
    }

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }
}

private class SecSignFunction(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureNotClosed() {
        check(!isClosed) { "Already closed" }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)

        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val signature = signToByteArray()
        checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
        signature.copyInto(destination, destinationOffset, destinationOffset)
        return signature.size
    }

    override fun signToByteArray(): ByteArray = memScoped {
        ensureNotClosed()
        val error = alloc<CFErrorRefVar>()
        accumulator.useNSData { data ->
            val signature = SecKeyCreateSignature(
                key = privateKey,
                algorithm = algorithm,
                dataToSign = data.retainBridgeAs<CFDataRef>(),
                error = error.ptr
            )?.releaseBridgeAs<NSData>()

            if (signature == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to generate signature: ${nsError?.description}")
            }

            signature.toByteArray()
        }
    }.also {
        close()
    }

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }
}
