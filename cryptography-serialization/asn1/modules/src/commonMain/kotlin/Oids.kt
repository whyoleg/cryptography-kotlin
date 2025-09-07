/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier

public val ObjectIdentifier.Companion.Ed25519: ObjectIdentifier get() = ObjectIdentifier("1.3.101.112")
public val ObjectIdentifier.Companion.Ed448: ObjectIdentifier get() = ObjectIdentifier("1.3.101.113")

public val ObjectIdentifier.Companion.X25519: ObjectIdentifier get() = ObjectIdentifier("1.3.101.110")
public val ObjectIdentifier.Companion.X448: ObjectIdentifier get() = ObjectIdentifier("1.3.101.111")

internal fun ObjectIdentifier.isRfc8410NoParams(): Boolean =
    this == ObjectIdentifier.Ed25519 ||
    this == ObjectIdentifier.Ed448 ||
    this == ObjectIdentifier.X25519 ||
    this == ObjectIdentifier.X448
