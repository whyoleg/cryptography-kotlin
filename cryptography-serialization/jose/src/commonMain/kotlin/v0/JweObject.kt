/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

// TODO: decide on how to support `direct encryption / previously exchanged key`
public sealed interface JweObject : JoseObject {
    public val authenticatedData: ByteArray?
    public val ciphertext: JweCiphertext

    // TODO: decide on shared and per-recipient header
    public val sharedHeader: JweCompositeHeader // - shared header for recipients

    public val recipients: List<Recipient>

    public sealed interface Recipient {
        public val encryptedKey: ByteArray
        public val header: JweHeader // unprotected header
    }

    public sealed interface Compact : JweObject, JoseObject.Compact {
        override val header: JweHeader
        public val encryptedKey: ByteArray

        // always null
        override val authenticatedData: ByteArray? get() = null

        // has only protected part equals to `header`
        override val sharedHeader: JweCompositeHeader

        // single recipient = empty header
        override val recipients: List<Recipient>
    }

    public companion object {
        public fun parseCompactString(string: String): Compact = TODO()
        public fun parseJsonString(string: String): JweObject = TODO()
    }
}
