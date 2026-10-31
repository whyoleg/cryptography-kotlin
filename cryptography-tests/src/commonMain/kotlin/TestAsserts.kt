/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import kotlinx.io.bytestring.*
import kotlin.test.*

fun assertBytesEquals(
    expected: ByteString,
    actual: ByteString,
    lazyMessage: () -> String,
) {
    if (expected == actual) return

    // should always fail, but with `hex` inputs
    assertEquals(
        expected = expected.toHexString(),
        actual = actual.toHexString(),
        lazyMessage = lazyMessage,
    )
}

fun assertBytesEquals(
    expected: ByteString,
    actual: ByteString,
) {
    if (expected == actual) return

    // should always fail, but with `hex` inputs
    assertEquals(
        expected = expected.toHexString(),
        actual = actual.toHexString(),
    )
}
