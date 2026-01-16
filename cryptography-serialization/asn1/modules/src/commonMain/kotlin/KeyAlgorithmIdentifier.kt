/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

@Deprecated(
    message = "KeyAlgorithmIdentifier is deprecated. Use AlgorithmIdentifier and concrete types " +
            "(RsaAlgorithmIdentifier, EcAlgorithmIdentifier, DhAlgorithmIdentifier) directly instead.",
    replaceWith = ReplaceWith("AlgorithmIdentifier", "dev.whyoleg.cryptography.serialization.asn1.modules.AlgorithmIdentifier"),
    level = DeprecationLevel.WARNING
)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

/**
 * Represents an unknown algorithm identifier encountered during decoding.
 */
@Suppress("DEPRECATION")
public class UnknownAlgorithmIdentifier(
    override val algorithm: ObjectIdentifier,
) : AlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}

@Deprecated(
    message = "Use UnknownAlgorithmIdentifier instead",
    replaceWith = ReplaceWith(
        "UnknownAlgorithmIdentifier",
        "dev.whyoleg.cryptography.serialization.asn1.modules.UnknownAlgorithmIdentifier"
    ),
    level = DeprecationLevel.ERROR
)
public typealias UnknownKeyAlgorithmIdentifier = UnknownAlgorithmIdentifier

