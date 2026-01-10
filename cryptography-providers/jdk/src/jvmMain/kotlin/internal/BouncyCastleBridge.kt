/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.internal

import org.bouncycastle.jce.*
import java.security.interfaces.*
import java.security.spec.*

// this is the only file, where it's allowed to use BouncyCastle classes

internal object BouncyCastleBridge {
    private val isAvailable = try {
        Class.forName("org.bouncycastle.jce.ECNamedCurveTable")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    fun derivePublicKey(
        privateKey: ECPrivateKey,
        curveName: String,
    ): ECPublicKeySpec? {
        if (!isAvailable) return null

        val bcSpec = ECNamedCurveTable.getParameterSpec(curveName)
        val bcPoint = bcSpec.g.multiply(privateKey.s).normalize()

        val point = ECPoint(
            bcPoint.affineXCoord.toBigInteger(),
            bcPoint.affineYCoord.toBigInteger()
        )
        return ECPublicKeySpec(point, privateKey.params)
    }

}
