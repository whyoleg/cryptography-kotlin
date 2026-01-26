/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

@Deprecated(
    message = "KeyAlgorithmIdentifier is deprecated. Use AlgorithmIdentifier",
    replaceWith = ReplaceWith("AlgorithmIdentifier", "dev.whyoleg.cryptography.serialization.asn1.modules.AlgorithmIdentifier"),
    level = DeprecationLevel.ERROR
)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

@Deprecated(
    message = "Deprecated without replacement.",
    level = DeprecationLevel.ERROR
)
public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : AlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}
