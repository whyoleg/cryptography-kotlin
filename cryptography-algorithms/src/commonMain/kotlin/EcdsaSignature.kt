/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.primitives.*
import kotlinx.io.bytestring.*
import kotlin.jvm.*

public class EcdsaSignature {
    public val r: ByteString get() = TODO()
    public val s: ByteString get() = TODO()

    public fun encodeToRaw(): ByteString = TODO()
    public fun encodeToDer(): ByteString = TODO()

    public companion object {
        public fun decodeFromRaw(bytes: ByteString): EcdsaSignature = TODO()
        public fun decodeFromDer(bytes: ByteString): EcdsaSignature = TODO()
    }
}

public enum class EcdsaSignatureFormat { RAW, DER }

public class EcdsaParameters(
    public val format: EcdsaSignatureFormat,
)

@JvmInline
public value class EcCurve(public val name: String) {
    public companion object {
        public val P256: EcCurve = EcCurve("P256")
    }
}

public interface EcPublicKey : PublicKey, CryptographyComponent<EcPublicKey> {
    public interface Tag<I : Any, P : Any> : CryptographyComponent.Tag<EcPublicKey, I, P>

    public companion object
}

public interface EcPrivateKey : PrivateKey, CryptographyComponent<EcPrivateKey> {
    public interface Tag<I : Any, P : Any> : CryptographyComponent.Tag<EcPrivateKey, I, P>

    public companion object
}
