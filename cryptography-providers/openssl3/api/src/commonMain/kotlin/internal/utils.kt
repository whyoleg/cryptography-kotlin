/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.internal

import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal fun BN_num_bytes(bn: CPointer<BIGNUM>): Int = (checkError(BN_num_bits(bn)) + 7) / 8
