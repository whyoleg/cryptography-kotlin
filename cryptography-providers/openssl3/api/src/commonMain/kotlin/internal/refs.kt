package dev.whyoleg.cryptography.openssl3.internal

import dev.whyoleg.cryptography.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.native.internal.*

@OptIn(ExperimentalStdlibApi::class)
internal fun CPointer<EVP_PKEY>.cleaner(): Cleaner = createCleaner(this, ::EVP_PKEY_free)

internal fun CPointer<EVP_PKEY>.upRef(): CPointer<EVP_PKEY> {
    checkError(EVP_PKEY_up_ref(this))
    return this
}
