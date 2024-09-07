/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

@Deprecated(
    "Moved to another package",
    ReplaceWith("AES", "dev.whyoleg.cryptography.algorithms.AES"),
    DeprecationLevel.ERROR
)
public typealias AES<K> = dev.whyoleg.cryptography.algorithms.AES<K>

@Deprecated(
    "Moved to another package",
    ReplaceWith("HMAC", "dev.whyoleg.cryptography.algorithms.HMAC"),
    DeprecationLevel.ERROR
)
public typealias HMAC = dev.whyoleg.cryptography.algorithms.HMAC
