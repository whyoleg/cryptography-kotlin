/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.ContextSpecificTag.*
import kotlinx.serialization.*
import kotlin.test.*

@OptIn(ExperimentalStdlibApi::class)
class ContextSpecificEncodingTest {

    @Serializable
    class ImplicitPoint(
        @ContextSpecificTag(0, TagType.IMPLICIT)
        val x: Int? = null,
        @ContextSpecificTag(1, TagType.IMPLICIT)
        val y: Int? = null,
    )

    @Serializable
    class ExplicitPoint(
        @ContextSpecificTag(0, TagType.EXPLICIT)
        val x: Int? = null,
        @ContextSpecificTag(1, TagType.EXPLICIT)
        val y: Int? = null,
    )

    @Test
    fun testImplicitPointWithXOnly() {
        val bytes = Der.encodeToByteArray(ImplicitPoint(7, null))
        assertEquals("3003800107", bytes.toHexString())

        val point = Der.decodeFromByteArray<ImplicitPoint>(bytes)
        assertEquals(7, point.x)
        assertNull(point.y)
    }

    @Test
    fun testImplicitPointWithYOnly() {
        val bytes = Der.encodeToByteArray(ImplicitPoint(null, 8))
        assertEquals("3003810108", bytes.toHexString())

        val point = Der.decodeFromByteArray<ImplicitPoint>(bytes)
        assertNull(point.x)
        assertEquals(8, point.y)
    }

    @Test
    fun testImplicitPointWithXAndY() {
        val bytes = Der.encodeToByteArray(ImplicitPoint(7, 8))
        assertEquals("3006800107810108", bytes.toHexString())

        val point = Der.decodeFromByteArray<ImplicitPoint>(bytes)
        assertEquals(7, point.x)
        assertEquals(8, point.y)
    }

    @Test
    fun testExplicitPointWithXOnly() {
        val bytes = Der.encodeToByteArray(ExplicitPoint(7, null))
        assertEquals("3005a003020107", bytes.toHexString())

        val point = Der.decodeFromByteArray<ExplicitPoint>(bytes)
        assertEquals(7, point.x)
        assertNull(point.y)
    }

    @Test
    fun testExplicitPointWithYOnly() {
        val bytes = Der.encodeToByteArray(ExplicitPoint(null, 8))
        assertEquals("3005a103020108", bytes.toHexString())

        val point = Der.decodeFromByteArray<ExplicitPoint>(bytes)
        assertNull(point.x)
        assertEquals(8, point.y)
    }

    @Test
    fun testExplicitPointWithXAndY() {
        val bytes = Der.encodeToByteArray(ExplicitPoint(7, 8))
        assertEquals("300aa003020107a103020108", bytes.toHexString())

        val point = Der.decodeFromByteArray<ExplicitPoint>(bytes)
        assertEquals(7, point.x)
        assertEquals(8, point.y)
    }
}
