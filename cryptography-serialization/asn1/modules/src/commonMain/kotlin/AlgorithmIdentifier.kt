/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

public interface AlgorithmIdentifier {
    public val algorithm: ObjectIdentifier
    public val parameters: Any?
}

