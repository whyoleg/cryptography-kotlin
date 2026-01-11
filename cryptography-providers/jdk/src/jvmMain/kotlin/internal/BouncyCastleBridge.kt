/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.internal

import dev.whyoleg.cryptography.providers.jdk.*
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jcajce.provider.asymmetric.util.*
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

    fun deriveEdDSAPublicKeySpec(
        privateKey: JPrivateKey,
    ): KeySpec? {
        if (!isAvailable) return null

        return try {
            val bcKey = ECUtil.generatePrivateKeyParameter(privateKey)
            when (bcKey) {
                is Ed25519PrivateKeyParameters -> {
                    val spec = Class.forName("java.security.spec.EdECPublicKeySpec")
                    val paramSpec = Class.forName("java.security.spec.EdDSAParameterSpec")
                    val ed25519 = paramSpec.getField("Ed25519").get(null)
                    spec.getConstructor(paramSpec, ByteArray::class.java).newInstance(ed25519, bcKey.generatePublicKey().encoded) as KeySpec
                }
                is Ed448PrivateKeyParameters   -> {
                    val spec = Class.forName("java.security.spec.EdECPublicKeySpec")
                    val paramSpec = Class.forName("java.security.spec.EdDSAParameterSpec")
                    val ed448 = paramSpec.getField("Ed448").get(null)
                    spec.getConstructor(paramSpec, ByteArray::class.java).newInstance(ed448, bcKey.generatePublicKey().encoded) as KeySpec
                }
                else                           -> null
            }
        } catch (_: Throwable) {
            null
        }
    }

    fun deriveXDHPublicKeySpec(
        privateKey: JPrivateKey,
    ): KeySpec? {
        if (!isAvailable) return null

        return try {
            val bcKey = ECUtil.generatePrivateKeyParameter(privateKey)
            when (bcKey) {
                is X25519PrivateKeyParameters -> {
                    val spec = Class.forName("java.security.spec.XECPublicKeySpec")
                    val paramSpec = Class.forName("java.security.spec.NamedParameterSpec")
                    val x25519 = paramSpec.getField("X25519").get(null)
                    spec.getConstructor(paramSpec, ByteArray::class.java).newInstance(x25519, bcKey.generatePublicKey().encoded) as KeySpec
                }
                is X448PrivateKeyParameters   -> {
                    val spec = Class.forName("java.security.spec.XECPublicKeySpec")
                    val paramSpec = Class.forName("java.security.spec.NamedParameterSpec")
                    val x448 = paramSpec.getField("X448").get(null)
                    spec.getConstructor(paramSpec, ByteArray::class.java).newInstance(x448, bcKey.generatePublicKey().encoded) as KeySpec
                }
                else                          -> null
            }
        } catch (_: Throwable) {
            null
        }
    }
}
