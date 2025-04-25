/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.bytestring.*

public interface SecretKeyFactory<K : SecretKey> {
    public fun decode(bytes: ByteString): K
}

public interface PemDecodable<T> {
    public fun decodeFromPem(text: String): T
    public fun decodeFromPem(bytes: ByteString): T
}

public interface PublicKeyFactory<K : PublicKey> : PemDecodable<K>

public interface PrivateKeyFactory<K : PrivateKey> : PemDecodable<K>
