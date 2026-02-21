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
) : Openssl3Decoder<F, K>(algorithm, EVP_PKEY_KEYPAIR) {
    override fun inputStruct(format: F): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyDecoder<F : EncodingFormat, K>(
    algorithm: String,
) : Openssl3Decoder<F, K>(algorithm, EVP_PKEY_PUBLIC_KEY) {
    override fun inputStruct(format: F): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3ParametersDecoder<F : EncodingFormat, P>(
    algorithm: String,
) : Openssl3Decoder<F, P>(algorithm, EVP_PKEY_KEY_PARAMETERS) {
    override fun inputStruct(format: F): String? = null
}

internal abstract class Openssl3Decoder<F : EncodingFormat, K>(
    private val algorithm: String,
    private val selection: Int,
) : Decoder<F, K> {
    protected abstract fun wrapKey(key: CPointer<EVP_PKEY>): K

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
                selection = selection,
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

    // be careful when using it, as it requires ALL parameters to be present, otherwise some features will not work;
    // like in case of EC private key import without public key - the later will not be computed
    protected fun fromParameters(createParams: MemScope.() -> CValuesRef<OSSL_PARAM>?): CPointer<EVP_PKEY> = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_name(null, algorithm, null))
        try {
            checkError(EVP_PKEY_fromdata_init(context))
            val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
            checkError(
                EVP_PKEY_fromdata(
                    ctx = context,
                    ppkey = pkeyVar.ptr,
                    selection = selection,
                    param = createParams()
                )
            )
            checkError(pkeyVar.value)
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
