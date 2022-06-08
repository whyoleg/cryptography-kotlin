package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class DigestSize(public val value: BinarySize)

public interface HashParameters {
    public val digestSize: DigestSize
}
