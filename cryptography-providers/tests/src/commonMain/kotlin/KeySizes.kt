/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*

val AesKeySizes = listOf(AES.Key.Size.B128, AES.Key.Size.B192, AES.Key.Size.B256)

val RsaKeySizes = listOf(2048.bits, 3072.bits, 4096.bits)
