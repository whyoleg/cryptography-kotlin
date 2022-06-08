package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*
import kotlin.jvm.*

//TODO: decide on this inline classes

@JvmInline
public value class Ciphertext(public val value: BufferView)

public abstract class CipherBox(public val ciphertext: Ciphertext)

@JvmInline
public value class AuthTag(public val value: BufferView)

@JvmInline
public value class AssociatedData(public val value: BufferView)

@JvmInline
public value class InitializationVector(public val value: BufferView)