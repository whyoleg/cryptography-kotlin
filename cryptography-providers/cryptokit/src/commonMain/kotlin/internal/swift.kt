/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.internal

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import kotlinx.cinterop.*
import platform.Foundation.*

internal typealias DwcErrorPointer = CPointer<ObjCObjectVar<NSError?>>

@OptIn(BetaInteropApi::class)
internal fun <T : Any> swiftTry(
    block: (error: DwcErrorPointer) -> T?,
): T = memScoped {
    val errorH = alloc<ObjCObjectVar<NSError?>>()
    when (val result = block(errorH.ptr)) {
        null -> error("Dwc call failed: ${errorH.value?.localizedDescription ?: "unknown error"}")
        else -> result
    }
}

@OptIn(UnsafeNumber::class)
internal fun CryptographyAlgorithmId<Digest>?.swiftHashAlgorithm(): DwcHashAlgorithm = when (this) {
    MD5    -> DwcHashAlgorithmMd5
    SHA1   -> DwcHashAlgorithmSha1
    SHA256 -> DwcHashAlgorithmSha256
    SHA384 -> DwcHashAlgorithmSha384
    SHA512 -> DwcHashAlgorithmSha512
    null   -> throw IllegalStateException("Operation without digest is unsupported!")
    else   -> throw IllegalStateException("Unsupported hash algorithm: $this")
}

@OptIn(UnsafeNumber::class)
internal fun EC.Curve.swiftEcCurve(): DwcEcCurve = when (this) {
    EC.Curve.P256 -> DwcEcCurveP256
    EC.Curve.P384 -> DwcEcCurveP384
    EC.Curve.P521 -> DwcEcCurveP521
    else          -> error("Unsupported EC curve: $this")
}
