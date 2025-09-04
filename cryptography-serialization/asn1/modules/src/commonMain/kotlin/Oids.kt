/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier

public object EdwardsOids {
    public val Ed25519: ObjectIdentifier = ObjectIdentifier("1.3.101.112")
    public val Ed448: ObjectIdentifier = ObjectIdentifier("1.3.101.113")
}

public object MontgomeryOids {
    public val X25519: ObjectIdentifier = ObjectIdentifier("1.3.101.110")
    public val X448: ObjectIdentifier = ObjectIdentifier("1.3.101.111")
}

