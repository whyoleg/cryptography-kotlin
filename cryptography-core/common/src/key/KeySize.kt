package dev.whyoleg.cryptography.key

import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class KeySize(public val value: BinarySize)

public fun KeySize.hasSizeOf(size: BinarySize): Boolean = value == size
