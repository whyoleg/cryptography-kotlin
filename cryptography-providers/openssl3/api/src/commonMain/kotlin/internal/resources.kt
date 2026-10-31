/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

// keys own their `EVP_PKEY`, operations created from keys (and functions created from operations) share the same resource
internal typealias EvpPKey = NativeResource<CPointer<EVP_PKEY>>

internal fun EvpPKey(key: CPointer<EVP_PKEY>): EvpPKey = NativeResource(key, ::EVP_PKEY_free)

internal typealias EvpCipher = NativeResource<CPointer<EVP_CIPHER>>
