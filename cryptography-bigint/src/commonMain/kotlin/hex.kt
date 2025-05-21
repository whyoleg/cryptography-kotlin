/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("BigIntKt")

package dev.whyoleg.cryptography.bigint

import kotlin.jvm.*

public fun BigInt.toHexString(format: HexFormat = HexFormat.Default): String = encodeToByteArray().toHexString(format)

public fun String.hexToBigInt(format: HexFormat = HexFormat.Default): BigInt = hexToByteArray(format).decodeToBigInt()
