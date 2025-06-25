/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import kotlinx.cinterop.*
import platform.Foundation.*

internal typealias SwiftErrorPointer = CPointer<ObjCObjectVar<NSError?>>

@OptIn(BetaInteropApi::class)
internal fun <T : Any> swiftTry(
    block: (error: SwiftErrorPointer) -> T?,
): T = memScoped {
    val errorH = alloc<ObjCObjectVar<NSError?>>()
    when (val result = block(errorH.ptr)) {
        null -> error("Swift call failed: ${errorH.value?.localizedDescription ?: "unknown error"}")
        else -> result
    }
}


@OptIn(UnsafeNumber::class)
internal fun CryptographyAlgorithmId<Digest>.swiftHashAlgorithm(): SwiftHashAlgorithm = when (this) {
    MD5    -> SwiftHashAlgorithmMd5
    SHA1   -> SwiftHashAlgorithmSha1
    SHA256 -> SwiftHashAlgorithmSha256
    SHA384 -> SwiftHashAlgorithmSha384
    SHA512 -> SwiftHashAlgorithmSha512
    else   -> throw IllegalStateException("Unsupported hash algorithm: $this")
}

@OptIn(UnsafeNumber::class)
internal fun EC.Curve.swiftEcCurve(): SwiftEcCurve = when (this) {
    EC.Curve.P256 -> SwiftEcCurveP256
    EC.Curve.P384 -> SwiftEcCurveP384
    EC.Curve.P521 -> SwiftEcCurveP521
    else          -> error("Unsupported EC curve: $this")
}
