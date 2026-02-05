/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials.key

import dev.whyoleg.cryptography.materials.*

@Deprecated(
    "Replaced by Encodable. Algorithm keys should extend Encodable<Format> directly.",
    ReplaceWith("Encodable<KF>", "dev.whyoleg.cryptography.materials.Encodable"),
    level = DeprecationLevel.ERROR,
)
public typealias EncodableKey<KF> = Encodable<KF>
