/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal fun deriveSharedSecret(
    publicKey: CPointer<EVP_PKEY>,
    privateKey: CPointer<EVP_PKEY>,
    createParams: MemScope.() -> CValuesRef<OSSL_PARAM>? = { null },
): ByteArray = with_PKEY_CTX(privateKey) { context ->
    checkError(EVP_PKEY_derive_init(context))
    createParams()?.let { checkError(EVP_PKEY_CTX_set_params(context, it)) }
    checkError(EVP_PKEY_derive_set_peer(context, publicKey))
    val secretSize = alloc<size_tVar>()
    checkError(EVP_PKEY_derive(context, null, secretSize.ptr))
    val secret = ByteArray(secretSize.value.toInt())
    checkError(EVP_PKEY_derive(context, secret.refToU(0), secretSize.ptr))
    secret.ensureSizeExactly(secretSize.value.toInt())
}
