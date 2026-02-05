/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.operations.KeyGenerator as NewKeyGenerator

@Deprecated(
    "Moved to operations package",
    ReplaceWith("KeyGenerator<K>", "dev.whyoleg.cryptography.operations.KeyGenerator"),
    level = DeprecationLevel.ERROR,
)
public typealias KeyGenerator<K> = NewKeyGenerator<K>
