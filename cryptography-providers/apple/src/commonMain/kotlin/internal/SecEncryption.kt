/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal fun secEncrypt(
    publicKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
    plaintextInput: ByteArray,
): ByteArray = memScoped {
    val error = alloc<CFErrorRefVar>()
    plaintextInput.useNSData { plaintext ->
        val ciphertext = SecKeyCreateEncryptedData(
            key = publicKey,
            algorithm = algorithm,
            plaintext = plaintext.retainBridgeAs<CFDataRef>(),
            error = error.ptr
        )?.releaseBridgeAs<NSData>()

        if (ciphertext == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to encrypt: ${nsError?.description}")
        }

        ciphertext.toByteArray()
    }
}

internal fun secDecrypt(
    privateKey: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
    ciphertextInput: ByteArray,
): ByteArray = memScoped {
    val error = alloc<CFErrorRefVar>()
    ciphertextInput.useNSData { ciphertext ->
        val plaintext = SecKeyCreateDecryptedData(
            key = privateKey,
            algorithm = algorithm,
            ciphertext = ciphertext.retainBridgeAs<CFDataRef>(),
            error = error.ptr
        )?.releaseBridgeAs<NSData>()

        if (plaintext == null) {
            val nsError = error.value.releaseBridgeAs<NSError>()
            error("Failed to decrypt: ${nsError?.description}")
        }

        plaintext.toByteArray()
    }
}
