/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

@Deprecated(
    "Moved to another package",
    ReplaceWith("EC", "dev.whyoleg.cryptography.algorithms.EC"),
    DeprecationLevel.ERROR
)
public typealias EC<PubK, PrivK, KP> = dev.whyoleg.cryptography.algorithms.EC<PubK, PrivK, KP>

@Deprecated(
    "Moved to another package",
    ReplaceWith("ECDSA", "dev.whyoleg.cryptography.algorithms.ECDSA"),
    DeprecationLevel.ERROR
)
public typealias ECDSA = dev.whyoleg.cryptography.algorithms.ECDSA

@Deprecated(
    "Moved to another package",
    ReplaceWith("RSA", "dev.whyoleg.cryptography.algorithms.RSA"),
    DeprecationLevel.ERROR
)
public typealias RSA<PubK, PrivK, KP> = dev.whyoleg.cryptography.algorithms.RSA<PubK, PrivK, KP>
