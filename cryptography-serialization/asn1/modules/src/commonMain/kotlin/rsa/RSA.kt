/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules.rsa

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*

public object RsaKeyAlgorithmIdentifier : KeyAlgorithmIdentifier {
    override val algorithm: ObjectIdentifier get() = ObjectIdentifier.RSA
    override val parameters: Nothing? get() = null
}

public val ObjectIdentifier.Companion.RSA: ObjectIdentifier get() = ObjectIdentifier("1.2.840.113549.1.1.1")
