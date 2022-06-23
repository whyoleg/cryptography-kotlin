package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*
import kotlin.jvm.*

public open class CipherBox(public val ciphertext: BufferView)

@JvmInline
public value class AuthTag(public val value: BufferView)

@JvmInline
public value class AssociatedData(public val value: BufferView)

@JvmInline
public value class InitializationVector(public val value: BufferView)
