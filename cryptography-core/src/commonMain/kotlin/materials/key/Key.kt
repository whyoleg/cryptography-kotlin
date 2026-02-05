/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.*

@Deprecated(
    "Key marker interface is no longer needed. Algorithm keys now extend Encodable directly.",
    level = DeprecationLevel.ERROR,
)
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Key
