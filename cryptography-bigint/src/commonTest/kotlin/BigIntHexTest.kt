/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.random.*
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class BigIntHexTest {

    @Test
    fun testIntSize() {
        repeat(1000) {
            val number = Random.nextInt()
            val padChar = if (number >= 0) '0' else 'f'
            val padCharInv = if (number >= 0) 'f' else '0'
            assertEquals(number.toHexString(), number.toBigInt().toHexString().padStart(8, padChar))
            assertEquals((-number).toHexString(), (-number).toBigInt().toHexString().padStart(8, padCharInv))
        }
    }

    @Test
    fun testLongSize() {
        repeat(1000) {
            val number = Random.nextLong()
            val padChar = if (number >= 0) '0' else 'f'
            val padCharInv = if (number >= 0) 'f' else '0'
            assertEquals(number.toHexString(), number.toBigInt().toHexString().padStart(16, padChar))
            assertEquals((-number).toHexString(), (-number).toBigInt().toHexString().padStart(16, padCharInv))
        }
    }
}
