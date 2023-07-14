/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

@ExperimentalNativeApi
internal fun CPointer<EVP_PKEY>.cleaner(): Cleaner = createCleaner(this, ::EVP_PKEY_free)

internal fun CPointer<EVP_PKEY>.upRef(): CPointer<EVP_PKEY> {
    checkError(EVP_PKEY_up_ref(this))
    return this
}
