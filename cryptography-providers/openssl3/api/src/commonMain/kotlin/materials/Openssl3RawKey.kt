/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal fun decodeRawPublicKey(type: Int, bytes: ByteArray): CPointer<EVP_PKEY> = checkError(
    EVP_PKEY_new_raw_public_key(type, null, bytes.refToU(0), bytes.size.convert())
)

@OptIn(UnsafeNumber::class)
internal fun decodeRawPrivateKey(type: Int, bytes: ByteArray): CPointer<EVP_PKEY> = checkError(
    EVP_PKEY_new_raw_private_key(type, null, bytes.refToU(0), bytes.size.convert())
)

@OptIn(UnsafeNumber::class)
internal fun encodeRawPublicKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val lenVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_raw_public_key(key, null, lenVar.ptr))
    val result = ByteArray(lenVar.value.convert())
    checkError(EVP_PKEY_get_raw_public_key(key, result.refToU(0), lenVar.ptr))
    result.ensureSizeExactly(lenVar.value.toInt())
}

@OptIn(UnsafeNumber::class)
internal fun encodeRawPrivateKey(key: CPointer<EVP_PKEY>): ByteArray = memScoped {
    val lenVar = alloc<size_tVar>()
    checkError(EVP_PKEY_get_raw_private_key(key, null, lenVar.ptr))
    val result = ByteArray(lenVar.value.convert())
    checkError(EVP_PKEY_get_raw_private_key(key, result.refToU(0), lenVar.ptr))
    result.ensureSizeExactly(lenVar.value.toInt())
}
