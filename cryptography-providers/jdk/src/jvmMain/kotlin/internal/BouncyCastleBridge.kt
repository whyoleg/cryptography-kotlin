/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.internal

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.*
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jcajce.interfaces.*
import org.bouncycastle.jce.*
import java.security.interfaces.*
import java.security.spec.*
import kotlin.jvm.optionals.*

// this is the only file, where it's allowed to use BouncyCastle classes

// TODO: we should later have some kind of tests for this, to test all possible options...
internal object BouncyCastleBridge {
    private val isAvailable = try {
        Class.forName("org.bouncycastle.jce.ECNamedCurveTable")
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    fun deriveEcPublicKey(
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

    // returns either public key or raw bytes of public key
    fun deriveEdDsaPublicKey(
        privateKey: JPrivateKey,
        curve: EdDSA.Curve,
    ): Pair<JPublicKey?, ByteArray?>? {
        if (!isAvailable) return null

        // Try BC's EdDSAPrivateKey interface first (for BC-created keys)
        try {
            (privateKey as? EdDSAPrivateKey)?.publicKey?.let { return it to null }
        } catch (_: NoClassDefFoundError) {
        }

        // Fall back to low-level BC APIs with JDK key bytes
        // JDK 15+ EdECPrivateKey interface
        try {
            (privateKey as? EdECPrivateKey)?.bytes?.getOrNull()?.let { seed ->
                when (curve) {
                    EdDSA.Curve.Ed25519 -> Ed25519PrivateKeyParameters(seed).generatePublicKey().encoded
                    EdDSA.Curve.Ed448   -> Ed448PrivateKeyParameters(seed).generatePublicKey().encoded
                }?.let { return null to it }
            }
        } catch (_: NoClassDefFoundError) {
        }

        return null
    }

    // returns either public key or raw bytes of public key
    fun deriveXdhPublicKey(
        privateKey: JPrivateKey,
        curve: XDH.Curve,
    ): Pair<JPublicKey?, ByteArray?>? {
        if (!isAvailable) return null

        // Try BC's XDHPrivateKey interface first (for BC-created keys)
        try {
            (privateKey as? XDHPrivateKey)?.publicKey?.let { return it to null }
        } catch (_: NoClassDefFoundError) {
        }

        // Fall back to low-level BC APIs with JDK key bytes
        // JDK 11+ XECPrivateKey interface
        try {
            (privateKey as? XECPrivateKey)?.scalar?.getOrNull()?.let { scalar ->
                when (curve) {
                    XDH.Curve.X25519 -> X25519PrivateKeyParameters(scalar).generatePublicKey().encoded
                    XDH.Curve.X448   -> X448PrivateKeyParameters(scalar).generatePublicKey().encoded
                }?.let { return null to it }
            }
        } catch (_: NoClassDefFoundError) {
        }

        return null
    }
}
