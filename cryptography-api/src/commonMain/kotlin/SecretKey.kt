/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import kotlinx.io.bytestring.*

public interface SecretKey {
    public val encoded: ByteString
}

public interface SecretKeyFactory<K : SecretKey, GP> : GeneratePrimitive<GP, K> {
    public fun decode(bytes: ByteString): K
}

public interface AsyncSecretKeyFactory<K : SecretKey, GP> : AsyncGeneratePrimitive<GP, K> {
    public suspend fun decode(bytes: ByteString): K
}
