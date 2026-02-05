/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal abstract class Openssl3PrivateKeyDecoder<F : EncodingFormat, K>(
    algorithm: String,
) : Openssl3Decoder<F, K>(algorithm) {
    override fun selection(format: F): Int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    override fun inputStruct(format: F): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyDecoder<F : EncodingFormat, K>(
    algorithm: String,
) : Openssl3Decoder<F, K>(algorithm) {
    override fun selection(format: F): Int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    override fun inputStruct(format: F): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3ParametersDecoder<F : EncodingFormat, P>(
    algorithm: String,
) : Openssl3Decoder<F, P>(algorithm) {
    override fun selection(format: F): Int = EVP_PKEY_KEY_PARAMETERS
    override fun inputStruct(format: F): String? = null
}

internal abstract class Openssl3Decoder<F : EncodingFormat, K>(
    private val algorithm: String,
) : Decoder<F, K> {
    protected abstract fun wrapKey(key: CPointer<EVP_PKEY>): K

    protected abstract fun selection(format: F): Int
    protected abstract fun inputType(format: F): String
    protected abstract fun inputStruct(format: F): String?

    override fun decodeFromByteArrayBlocking(format: F, bytes: ByteArray): K = memScoped {
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        val context = checkError(
            OSSL_DECODER_CTX_new_for_pkey(
                pkey = pkeyVar.ptr,
                input_type = inputType(format).cstr.ptr,
                input_struct = inputStruct(format)?.cstr?.ptr,
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
