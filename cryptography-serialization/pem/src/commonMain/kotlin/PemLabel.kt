/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlin.jvm.*

@JvmInline
public value class PemLabel(public val value: String) {
    public companion object {
        public val PublicKey: PemLabel = PemLabel("PUBLIC KEY")
        public val PrivateKey: PemLabel = PemLabel("PRIVATE KEY")
        public val RsaPublicKey: PemLabel = PemLabel("RSA PUBLIC KEY")
        public val RsaPrivateKey: PemLabel = PemLabel("RSA PRIVATE KEY")
        public val EcPrivateKey: PemLabel = PemLabel("EC PRIVATE KEY")
    }
}
