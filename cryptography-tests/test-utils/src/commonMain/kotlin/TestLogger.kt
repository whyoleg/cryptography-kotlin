/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.test.utils

class TestLogger(
    tag: String?,
    val enabled: Boolean,
) {
    private val tag = when (tag) {
        null -> "[TEST]"
        else -> "[TEST|$tag]"
    }

    @PublishedApi
    internal fun print(message: String) {
        println("$tag $message")
    }

    inline fun log(message: () -> String) {
        if (enabled) print(message())
    }
}
