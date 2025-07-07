/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.materials

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Material

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialFormat {
    public val name: String
    override fun toString(): String
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EncodableMaterial<MF : MaterialFormat> : Material {
    public suspend fun encodeToByteArray(format: MF): ByteArray {
        return encodeToByteArrayBlocking(format)
    }

    public fun encodeToByteArrayBlocking(format: MF): ByteArray

    public suspend fun encodeToByteString(format: MF): ByteString {
        return encodeToByteArray(format).asByteString()
    }

    public fun encodeToByteStringBlocking(format: MF): ByteString {
        return encodeToByteArrayBlocking(format).asByteString()
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialDecoder<MF : MaterialFormat, M : Material> {
    public suspend fun decodeFromByteArray(format: MF, bytes: ByteArray): M {
        return decodeFromByteArrayBlocking(format, bytes)
    }

    public fun decodeFromByteArrayBlocking(format: MF, bytes: ByteArray): M

    public suspend fun decodeFromByteString(format: MF, byteString: ByteString): M {
        return decodeFromByteArray(format, byteString.asByteArray())
    }

    public fun decodeFromByteStringBlocking(format: MF, byteString: ByteString): M {
        return decodeFromByteArrayBlocking(format, byteString.asByteArray())
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface MaterialGenerator<M : Material> {
    public suspend fun generate(): M = generateBlocking()
    public fun generateBlocking(): M
}
