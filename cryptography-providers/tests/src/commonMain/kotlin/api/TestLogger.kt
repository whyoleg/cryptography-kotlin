/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

class TestLogger(
    private val enabled: Boolean,
    private val tag: String?,
) {

    fun child(tag: String): TestLogger = TestLogger(
        enabled = enabled,
        tag = when (this.tag) {
            null -> tag
            else -> "${this.tag}|$tag"
        }
    )

    fun print(message: String) {
        println(buildString {
            append("[TEST")
            if (tag != null) append("|").append(tag)
            append("] ")
            append(message)
        })
    }

    fun log(message: () -> String) {
        if (enabled) print(message())
    }
}
