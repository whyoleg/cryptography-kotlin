/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal abstract class Openssl3PrivateKeyDecoder<KF : KeyFormat, K : Key>(
    algorithm: String,
) : Openssl3KeyDecoder<KF, K>(algorithm) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    override fun inputStruct(format: KF): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyDecoder<KF : KeyFormat, K : Key>(
    algorithm: String,
) : Openssl3KeyDecoder<KF, K>(algorithm) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    override fun inputStruct(format: KF): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3KeyDecoder<KF : KeyFormat, K : Key>(
    private val algorithm: String,
) : KeyDecoder<KF, K> {
    protected abstract fun wrapKey(key: CPointer<EVP_PKEY>): K

    protected abstract fun selection(format: KF): Int
    protected abstract fun inputType(format: KF): String
    protected abstract fun inputStruct(format: KF): String

    override fun decodeFromByteArrayBlocking(format: KF, bytes: ByteArray): K = memScoped {
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        val context = checkError(
            OSSL_DECODER_CTX_new_for_pkey(
                pkey = pkeyVar.ptr,
                input_type = inputType(format).cstr.ptr,
                input_struct = inputStruct(format).cstr.ptr,
                keytype = algorithm.cstr.ptr,
                selection = selection(format),
                libctx = null,
                propquery = null
            )
        )
        @OptIn(UnsafeNumber::class)
        try {
            val pdataLenVar = alloc(bytes.size.convert<size_t>())
            val pdataVar = alloc<CPointerVar<UByteVar>> { value = allocArrayOf(bytes).reinterpret() }
            checkError(OSSL_DECODER_from_data(context, pdataVar.ptr, pdataLenVar.ptr))
            val pkey = checkError(pkeyVar.value)
            wrapKey(pkey)
        } finally {
            OSSL_DECODER_CTX_free(context)
        }
    }
}
