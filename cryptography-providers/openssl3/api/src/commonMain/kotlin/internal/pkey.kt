/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal inline fun <T> with_PKEY_CTX(
    algorithm: String,
    block: MemScope.(context: CPointer<EVP_PKEY_CTX>) -> T,
): T = useContext(block) {
    EVP_PKEY_CTX_new_from_name(null, algorithm, null)
}

internal inline fun <T> with_PKEY_CTX(
    key: CPointer<EVP_PKEY>,
    block: MemScope.(context: CPointer<EVP_PKEY_CTX>) -> T,
): T = useContext(block) {
    EVP_PKEY_CTX_new_from_pkey(null, key, null)
}

internal inline fun <T> with_PKEY_CTX(
    algorithm: String?,
    key: CPointer<EVP_PKEY>?,
    block: MemScope.(context: CPointer<EVP_PKEY_CTX>) -> T,
): T = useContext(block) {
    when {
        algorithm != null -> EVP_PKEY_CTX_new_from_name(null, algorithm, null)
        else              -> EVP_PKEY_CTX_new_from_pkey(null, key, null)
    }
}

private inline fun <T> useContext(
    block: MemScope.(context: CPointer<EVP_PKEY_CTX>) -> T,
    createContext: () -> CPointer<EVP_PKEY_CTX>?,
): T = memScoped {
    val context = checkError(createContext())
    try {
        block(context)
    } finally {
        EVP_PKEY_CTX_free(context)
    }
}
