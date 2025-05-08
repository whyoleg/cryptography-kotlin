/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.bytestring.*

public interface SecretKeyFactory<P, K : SecretKey> {
    public fun generate(parameters: P): K
    public fun decode(bytes: ByteString): K
}

public interface PemDecodable<T> {
    public fun decodeFromPem(text: String): T
    public fun decodeFromPem(bytes: ByteString): T
}

public interface PublicKeyFactory<K : PublicKey> : PemDecodable<K>

public interface PrivateKeyFactory<K : PrivateKey> : PemDecodable<K>

public interface KeyPairFactory<P, Pub : PublicKey, Pri : PrivateKey> {
    public fun generateKeyPair(parameters: P): KeyPair<Pub, Pri>

    public fun decodePublicKeyFromPem(text: String): Pub
    public fun decodePrivateKeyFromPem(text: String): Pri
}
