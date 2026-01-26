/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

@Deprecated(
    message = "KeyAlgorithmIdentifier is deprecated. Use AlgorithmIdentifier",
    replaceWith = ReplaceWith("AlgorithmIdentifier", "dev.whyoleg.cryptography.serialization.asn1.modules.AlgorithmIdentifier"),
    level = DeprecationLevel.WARNING
)
public interface KeyAlgorithmIdentifier : AlgorithmIdentifier

@Deprecated(
    message = "UnknownKeyAlgorithmIdentifier is deprecated. Use SimpleAlgorithmIdentifier",
    replaceWith = ReplaceWith("SimpleAlgorithmIdentifier", "dev.whyoleg.cryptography.serialization.asn1.modules.SimpleAlgorithmIdentifier"),
    level = DeprecationLevel.ERROR
)
public class UnknownKeyAlgorithmIdentifier(override val algorithm: ObjectIdentifier) : AlgorithmIdentifier {
    override val parameters: Nothing? get() = null
}
