/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

internal fun SecCipherFunction(
    key: SecKeyRef,
    algorithm: SecKeyAlgorithm?,
    finalizer: (SecKeyRef?, SecKeyAlgorithm?, CFDataRef?, error: CValuesRef<CFErrorRefVar>) -> CFDataRef?,
): CipherFunction = AccumulatingCipherFunction { input ->
    memScoped {
        val error = alloc<CFErrorRefVar>()
        input.useNSData { inputData ->
            val output = finalizer.invoke(
                key,
                algorithm,
                inputData.retainBridgeAs<CFDataRef>(),
                error.ptr
            )?.releaseBridgeAs<NSData>()

            if (output == null) {
                val nsError = error.value.releaseBridgeAs<NSError>()
                error("Failed to perform operation: ${nsError?.description}")
            }

            output.toByteArray()
        }
    }
}
