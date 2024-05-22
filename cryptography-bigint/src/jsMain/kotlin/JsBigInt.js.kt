/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

internal actual external interface JsBigInt {
    @JsName("toString")
    actual fun convertToString(): String

    @JsName("toString")
    actual fun convertToString(radix: Int): String
}

@JsName("BigInt")
internal actual external fun jsBigInt(value: Int): JsBigInt

@JsName("BigInt")
internal actual external fun jsBigInt(value: String): JsBigInt

internal actual fun jsBigIntNegate(value: JsBigInt): JsBigInt = js("-value").unsafeCast<JsBigInt>()

internal actual fun jsBigIntSign(value: JsBigInt): Int {
    return js(
        code = """
        if (value == 0) return 0
        if (value > 0) return 1
        return -1
               """
    ).unsafeCast<Int>()
}

internal actual fun jsBigIntCompareTo(a: JsBigInt, b: JsBigInt): Int {
    return js(
        code = """
        if (a < b) return -1
        if (a > b) return 1
        return 0
               """
    ).unsafeCast<Int>()
}

internal actual fun jsBigIntEquals(a: JsBigInt, b: JsBigInt): Boolean =
    js("a === b").unsafeCast<Boolean>()

internal actual fun jsBigIntAsInt(value: JsBigInt, bits: Int): JsBigInt =
    js("BigInt.asIntN(bits, value)").unsafeCast<JsBigInt>()
