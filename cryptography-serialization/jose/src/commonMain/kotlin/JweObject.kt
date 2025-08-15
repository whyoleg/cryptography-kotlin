/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

public sealed interface JweObject : JoseObject {
    public val ciphertext: JweCiphertext

    public val sharedHeaders: JweHeaders // - shared header for recipients

    public val recipients: List<Recipient>

    public sealed interface Recipient {
        public val encryptedKey: ByteArray?
        public val header: JweHeader // unprotected header
    }

    public sealed interface Compact : JweObject, JoseObject.Compact {
        public val encryptedKey: ByteArray?

        override val header: JweHeader

        // has only protected part equals to `header`
        override val sharedHeaders: JweHeaders

        // single recipient = empty header
        override val recipients: List<Recipient>
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseJsonString(string: String): JweObject = TODO()
    }
}
