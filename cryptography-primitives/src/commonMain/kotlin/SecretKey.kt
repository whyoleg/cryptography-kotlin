/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives

import kotlinx.io.bytestring.*

public interface SecretKey {
    public val encoded: ByteString
}

// keys or certificates
public interface PemEncodable {
    public fun encodeToPemString(): String
    public fun encodeToPemByteString(): ByteString
}

// PEM in SPKI format
public interface PublicKey : PemEncodable

// PEM in PKCS8 format
public interface PrivateKey : PemEncodable

public data class KeyPair<Pub : PublicKey, Pri : PrivateKey>(
    public val publicKey: Pub,
    public val privateKey: Pri,
)
