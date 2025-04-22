/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.algorithms

import dev.whyoleg.cryptography.api.*

public interface AesKey : SecretKey, CryptographyComponent<AesKey> {
    public interface Tag<T> : CryptographyComponent.Tag<AesKey, T>
}

public interface AesKeyFactory : SecretKeyFactory<AesKey, AesKeyGenerationParameters> {
    public companion object Tag : CryptographyProvider.Tag<AesKeyFactory>
}

public class AesKeyGenerationParameters(public val size: Int) {
    public companion object {
        public val B256: AesKeyGenerationParameters = AesKeyGenerationParameters(256)
    }
}
