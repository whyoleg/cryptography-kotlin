/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

@Suppress("ACTUAL_CLASSIFIER_MUST_HAVE_THE_SAME_SUPERTYPES_AS_NON_FINAL_EXPECT_CLASSIFIER_WARNING")
internal actual external interface JsBigInt : JsAny {
    @JsName("toString")
    actual fun convertToString(): String

    @JsName("toString")
    actual fun convertToString(radix: Int): String
}

@JsName("BigInt")
internal actual external fun jsBigIntOrThrow(value: Int): JsBigInt

internal actual fun jsBigIntOrThrow(value: String): JsBigInt {
    return checkNotNull(jsBigIntOrNull(value)) { "Failed to parse BigInt from string" }
}

internal actual fun jsBigIntOrNull(value: String): JsBigInt? {
    js(
        code = """
        try {
            return BigInt(value);
        } catch (error) {
            return undefined;
        }
        
               """
    )
}

internal actual fun jsBigIntNegate(value: JsBigInt): JsBigInt = js("-value")

internal actual fun jsBigIntSign(value: JsBigInt): Int {
    js(
        code = """
        if (value == 0) return 0
        if (value > 0) return 1
        return -1
               """
    )
}

internal actual fun jsBigIntCompareTo(a: JsBigInt, b: JsBigInt): Int {
    js(
        code = """
        if (a < b) return -1
        if (a > b) return 1
        return 0
               """
    )
}

internal actual fun jsBigIntEquals(a: JsBigInt, b: JsBigInt): Boolean =
    js("a === b")

internal actual fun jsBigIntAsInt(value: JsBigInt, bits: Int): JsBigInt =
    js("BigInt.asIntN(bits, value)")
