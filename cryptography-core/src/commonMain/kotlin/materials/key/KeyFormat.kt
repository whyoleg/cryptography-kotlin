/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.materials.*

@Deprecated(
    "Replaced by EncodingFormat",
    ReplaceWith("EncodingFormat", "dev.whyoleg.cryptography.materials.EncodingFormat"),
    level = DeprecationLevel.ERROR,
)
public typealias KeyFormat = EncodingFormat
