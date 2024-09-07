/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.*

@Deprecated(
    "Moved to another package",
    ReplaceWith("Digest", "dev.whyoleg.cryptography.algorithms.Digest"),
    DeprecationLevel.ERROR
)
public typealias Digest = dev.whyoleg.cryptography.algorithms.Digest

@Deprecated(
    "Moved to another package",
    ReplaceWith("MD5", "dev.whyoleg.cryptography.algorithms.MD5"),
    DeprecationLevel.ERROR
)
@OptIn(DelicateCryptographyApi::class)
public typealias MD5 = dev.whyoleg.cryptography.algorithms.MD5

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA1", "dev.whyoleg.cryptography.algorithms.SHA1"),
    DeprecationLevel.ERROR
)
@OptIn(DelicateCryptographyApi::class)
public typealias SHA1 = dev.whyoleg.cryptography.algorithms.SHA1

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA224", "dev.whyoleg.cryptography.algorithms.SHA224"),
    DeprecationLevel.ERROR
)
public typealias SHA224 = dev.whyoleg.cryptography.algorithms.SHA224

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA256", "dev.whyoleg.cryptography.algorithms.SHA256"),
    DeprecationLevel.ERROR
)
public typealias SHA256 = dev.whyoleg.cryptography.algorithms.SHA256

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA384", "dev.whyoleg.cryptography.algorithms.SHA384"),
    DeprecationLevel.ERROR
)
public typealias SHA384 = dev.whyoleg.cryptography.algorithms.SHA384

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA512", "dev.whyoleg.cryptography.algorithms.SHA512"),
    DeprecationLevel.ERROR
)
public typealias SHA512 = dev.whyoleg.cryptography.algorithms.SHA512

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA3_224", "dev.whyoleg.cryptography.algorithms.SHA3_224"),
    DeprecationLevel.ERROR
)
public typealias SHA3_224 = dev.whyoleg.cryptography.algorithms.SHA3_224

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA3_256", "dev.whyoleg.cryptography.algorithms.SHA3_256"),
    DeprecationLevel.ERROR
)
public typealias SHA3_256 = dev.whyoleg.cryptography.algorithms.SHA3_256

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA3_384", "dev.whyoleg.cryptography.algorithms.SHA3_384"),
    DeprecationLevel.ERROR
)
public typealias SHA3_384 = dev.whyoleg.cryptography.algorithms.SHA3_384

@Deprecated(
    "Moved to another package",
    ReplaceWith("SHA3_512", "dev.whyoleg.cryptography.algorithms.SHA3_512"),
    DeprecationLevel.ERROR
)
public typealias SHA3_512 = dev.whyoleg.cryptography.algorithms.SHA3_512
