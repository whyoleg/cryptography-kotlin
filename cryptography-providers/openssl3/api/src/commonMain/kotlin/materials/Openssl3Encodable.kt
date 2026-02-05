/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal abstract class Openssl3PrivateKeyEncodable<F : EncodingFormat, PublicK>(
    key: CPointer<EVP_PKEY>,
    private var publicKey: PublicK?,
) : Openssl3Encodable<F>(key), PublicKeyAccessor<PublicK> {
    protected abstract fun wrapPublicKey(key: CPointer<EVP_PKEY>): PublicK

    final override fun getPublicKeyBlocking(): PublicK {
        if (publicKey == null) publicKey = wrapPublicKey(key.upRef())
        return publicKey!!
    }

    override fun selection(format: F): Int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    override fun outputStruct(format: F): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyEncodable<F : EncodingFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3Encodable<F>(key) {
    override fun selection(format: F): Int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    override fun outputStruct(format: F): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3ParametersEncodable<F : EncodingFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3Encodable<F>(key) {
    override fun selection(format: F): Int = EVP_PKEY_KEY_PARAMETERS
    override fun outputStruct(format: F): String? = null
}

internal abstract class Openssl3Encodable<F : EncodingFormat>(
    val key: CPointer<EVP_PKEY>,
) : Encodable<F> {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = key.cleaner()

    protected abstract fun selection(format: F): Int
    protected abstract fun outputType(format: F): String
    protected abstract fun outputStruct(format: F): String?

    override fun encodeToByteArrayBlocking(format: F): ByteArray = memScoped {
        val context = checkError(
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey = key,
                selection = selection(format),
                output_type = outputType(format).cstr.ptr,
                output_struct = outputStruct(format)?.cstr?.ptr,
                propquery = null
            )
        )
        @OptIn(UnsafeNumber::class)
        try {
            val pdataLenVar = alloc<size_tVar>()
            val pdataVar = alloc<CPointerVar<UByteVar>>()
            checkError(OSSL_ENCODER_to_data(context, pdataVar.ptr, pdataLenVar.ptr))
            pdataVar.value!!.readBytes(pdataLenVar.value.convert())
        } finally {
            OSSL_ENCODER_CTX_free(context)
        }
    }
}
