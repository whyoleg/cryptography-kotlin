/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

@ExperimentalStdlibApi
public fun BigInt.toHexString(format: HexFormat = HexFormat.Default): String = encodeToByteArray().toHexString(format)

@ExperimentalStdlibApi
public fun String.hexToBigInt(format: HexFormat = HexFormat.Default): BigInt = hexToByteArray(format).decodeToBigInt()
