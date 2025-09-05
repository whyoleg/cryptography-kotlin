/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

@OptIn(UnsafeNumber::class)
internal fun deriveSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
): ByteArray = memScoped {
    val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
    try {
        checkError(EVP_PKEY_derive_init(context))
        checkError(EVP_PKEY_derive_set_peer(context, publicKey))
        val secretSize = alloc<size_tVar>()
        checkError(EVP_PKEY_derive(context, null, secretSize.ptr))
        val secret = ByteArray(secretSize.value.toInt())
        checkError(EVP_PKEY_derive(context, secret.refToU(0), secretSize.ptr))
        secret
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}
