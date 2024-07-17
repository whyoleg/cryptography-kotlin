/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal abstract class Openssl3PrivateKeyEncodable<KF : KeyFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3KeyEncodable<KF>(key) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
    override fun outputStruct(format: KF): String = "PrivateKeyInfo"
}

internal abstract class Openssl3PublicKeyEncodable<KF : KeyFormat>(
    key: CPointer<EVP_PKEY>,
) : Openssl3KeyEncodable<KF>(key) {
    override fun selection(format: KF): Int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    override fun outputStruct(format: KF): String = "SubjectPublicKeyInfo"
}

internal abstract class Openssl3KeyEncodable<KF : KeyFormat>(
    val key: CPointer<EVP_PKEY>,
) : EncodableKey<KF> {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = key.cleaner()

    protected abstract fun selection(format: KF): Int
    protected abstract fun outputType(format: KF): String
    protected abstract fun outputStruct(format: KF): String

    override fun encodeToBlocking(format: KF): ByteArray = memScoped {
        val context = checkError(
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey = key,
                selection = selection(format),
                output_type = outputType(format).cstr.ptr,
                output_struct = outputStruct(format).cstr.ptr,
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
