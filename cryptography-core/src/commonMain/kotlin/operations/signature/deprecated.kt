/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.signature

@Deprecated(
    "Moved to another package",
    ReplaceWith("SignatureGenerator", "dev.whyoleg.cryptography.operations.SignatureGenerator"),
    DeprecationLevel.ERROR
)
public typealias SignatureGenerator = dev.whyoleg.cryptography.operations.SignatureGenerator

@Deprecated(
    "Moved to another package",
    ReplaceWith("SignatureVerifier", "dev.whyoleg.cryptography.operations.SignatureVerifier"),
    DeprecationLevel.ERROR
)
public typealias SignatureVerifier = dev.whyoleg.cryptography.operations.SignatureVerifier
