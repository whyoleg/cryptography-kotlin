/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.operations.signature.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal class SecSignatureVerifier(
    private val publicKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureVerifier {
    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = memScoped {
        val error = alloc<CFErrorRefVar>()
        data.useNSData { data ->
            signature.useNSData { signature ->
                val result = SecKeyVerifySignature(
                    key = publicKey,
                    algorithm = algorithm,
                    signedData = data.retainBridgeAs<CFDataRef>(),
                    error = error.ptr,
                    signature = signature.retainBridgeAs<CFDataRef>()
                )
                if (!result) {
                    val nsError = error.value.releaseBridgeAs<NSError>()
                    error("Failed to verify signature: ${nsError?.description}")
                }
                result
            }
        }
    }
}

internal class SecSignatureGenerator(
    private val privateKey: SecKeyRef,
    private val algorithm: SecKeyAlgorithm?,
) : SignatureGenerator {
    override fun generateSignatureBlocking(data: ByteArray): ByteArray = memScoped {
        val error = alloc<CFErrorRefVar>()
        data.useNSData { data ->
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
    }
}
