/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

// OID: 1.3.101.110 (RFC 8410)
public val ObjectIdentifier.Companion.X25519: ObjectIdentifier get() = ObjectIdentifier("1.3.101.110")

// X25519 has no parameters (not even NULL, just absent)
public object X25519AlgorithmIdentifier : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.X25519
    override val parameters: Nothing? get() = null
}