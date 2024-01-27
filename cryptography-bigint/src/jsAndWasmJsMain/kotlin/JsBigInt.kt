/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

internal expect interface JsBigInt {
    fun convertToString(): String
    fun convertToString(radix: Int): String
}

internal expect fun jsBigIntOrThrow(value: Int): JsBigInt
internal expect fun jsBigIntOrThrow(value: String): JsBigInt
internal expect fun jsBigIntOrNull(value: String): JsBigInt?

internal expect fun jsBigIntNegate(value: JsBigInt): JsBigInt

internal expect fun jsBigIntSign(value: JsBigInt): Int
internal expect fun jsBigIntCompareTo(a: JsBigInt, b: JsBigInt): Int
internal expect fun jsBigIntEquals(a: JsBigInt, b: JsBigInt): Boolean

internal expect fun jsBigIntAsInt(value: JsBigInt, bits: Int): JsBigInt
