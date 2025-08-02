/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// TODO: may be renamed it to just `JoseHeaders`?
public sealed interface JoseCompositeHeader {
    public val protected: JoseHeader
    public val unprotected: JoseHeader

    public val combined: JoseHeader
}

public sealed interface JoseCompositeHeaderBuilder : JoseCompositeHeader {
    override val protected: JoseHeaderBuilder
    override val unprotected: JoseHeaderBuilder
}
