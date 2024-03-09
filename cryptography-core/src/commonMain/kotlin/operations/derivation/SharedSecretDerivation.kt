/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.derivation

import dev.whyoleg.cryptography.*

// TODO: decide on type parameter: should it be Key or just generic material?
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface SharedSecretDerivation<M> {
    public suspend fun deriveSharedSecret(material: M): ByteArray
}
