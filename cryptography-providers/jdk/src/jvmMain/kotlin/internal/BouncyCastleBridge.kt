/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

    // TODO: BC APIs, don't check for BC classes
    // TODO: this require using jvmToolchain(21) and more implementation
//    fun deriveEdDSAPublicKey(privateKey: JPrivateKey): JPublicKey? {
//        if (!isAvailable) return null
//
//        // jdk 15 -> try/catch
//        privateKey as? EdECPrivateKey ?: return null
//
//        // BC class
//        if (privateKey is EdDSAPrivateKey) {
//            return privateKey.publicKey
//        }
//
//        // TODO: ed25519 vs ed448
//
//        val privateKeySeed = privateKey.bytes.getOrNull() ?: return null
//        val encodedPublicKey = Ed25519PrivateKeyParameters(privateKeySeed, 0)
//            .generatePublicKey()
//            .encoded
//
//        val pub = priv.generatePublicKey()
//
//        val publicKeyBytes = pub.getEncoded()
//
//        return try {
//            // BouncyCastle EdDSA private keys implement EdDSAPrivateKey interface
//            // which provides direct access to the public key
//            (privateKey as? EdDSAPrivateKey)?.publicKey
//        } catch (_: Throwable) {
//            null
//        }
//    }
//
//    fun deriveXDHPublicKey(privateKey: JPrivateKey, ): JPublicKey? {
//        if (!isAvailable) return null
//
//        return try {
//            // BouncyCastle XDH private keys implement XDHPrivateKey interface
//            // which provides direct access to the public key
//            (privateKey as? XDHPrivateKey)?.publicKey
//        } catch (_: Throwable) {
//            null
//        }
//    }
}
