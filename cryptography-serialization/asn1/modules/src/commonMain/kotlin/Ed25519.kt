/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*

// OID: 1.3.101.112 (RFC 8410)
public val ObjectIdentifier.Companion.Ed25519: ObjectIdentifier get() = ObjectIdentifier("1.3.101.112")

// ED25519 has no parameters (not even NULL, just absent)
public object Ed25519AlgorithmIdentifier : AlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.Ed25519
    override val parameters: Nothing? get() = null
}
