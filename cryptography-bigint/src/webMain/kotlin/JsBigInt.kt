/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(ExperimentalWasmJsInterop::class)

package dev.whyoleg.cryptography.bigint

import kotlin.js.*

internal external interface JsBigInt : JsAny {
    @JsName("toString")
    fun convertToString(): String

    @JsName("toString")
    fun convertToString(radix: Int): String
}

@JsName("BigInt")
internal external fun jsBigInt(value: Int): JsBigInt

@JsName("BigInt")
internal external fun jsBigInt(value: String): JsBigInt

internal fun jsBigIntNegate(value: JsBigInt): JsBigInt = js("-value")

internal fun jsBigIntSign(value: JsBigInt): Int = js("value == 0 ? 0 : (value < 0 ? -1 : 1)")

internal fun jsBigIntCompareTo(a: JsBigInt, b: JsBigInt): Int = js("a < b ? -1 : a > b ? 1 : 0")

internal fun jsBigIntEquals(a: JsBigInt, b: JsBigInt): Boolean = js("a === b")

internal fun jsBigIntAsInt(value: JsBigInt, bits: Int): JsBigInt = js("BigInt.asIntN(bits, value)")
