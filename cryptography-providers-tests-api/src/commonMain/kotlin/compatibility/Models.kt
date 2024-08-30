/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("ArrayInDataClass")

package dev.whyoleg.cryptography.providers.tests.api.compatibility

import kotlinx.serialization.*
import kotlin.jvm.*

interface TestParameters {
    @Serializable
    object Empty : TestParameters {
        override fun toString(): String = "EmptyParameters"
    }
}

interface TestData

@Serializable
@JvmInline
value class TestParametersId(val value: String) {
    override fun toString(): String = "P($value)"
}

@Serializable
@JvmInline
value class TestDataId(val value: String) {
    override fun toString(): String = "D($value)"
}

@Serializable
data class TestReference(
    val parametersId: TestParametersId,
    val dataId: TestDataId,
) {
    override fun toString(): String = "R(${parametersId.value} -> ${dataId.value})"
}

@Serializable
data class DigestData(val data: Base64ByteArray, val digest: Base64ByteArray) : TestData {
    override fun toString(): String = "DigestData(data.size=${data.size}, digest.size=${digest.size})"
}

@Serializable
data class KeyData(val formats: Map<String, ByteStringAsString>) : TestData

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData) : TestData

@Serializable
data class CipherData(
    val keyReference: TestReference,
    val plaintext: Base64ByteArray,
    val ciphertext: Base64ByteArray,
) : TestData {
    override fun toString(): String {
        return "CipherData(keyReference=$keyReference, plaintext.size=${plaintext.size}, ciphertext.size=${ciphertext.size})"
    }
}

@Serializable
data class AuthenticatedCipherData(
    val keyReference: TestReference,
    val associatedData: Base64ByteArray?,
    val plaintext: Base64ByteArray,
    val ciphertext: Base64ByteArray,
) : TestData {
    override fun toString(): String {
        return "AuthenticatedCipherData(keyReference=$keyReference, associatedData.size=${associatedData?.size}, plaintext.size=${plaintext.size}, ciphertext.size=${ciphertext.size})"
    }
}

@Serializable
data class SignatureData(
    val keyReference: TestReference,
    val data: ByteStringAsString,
    val signature: ByteStringAsString,
) : TestData

@Serializable
data class SharedSecretData(
    val keyReference: TestReference,
    val otherKeyReference: TestReference,
    val sharedSecret: ByteStringAsString,
) : TestData

@Serializable
data class DerivedSecretData(
    val input: ByteStringAsString,
    val secret: ByteStringAsString,
) : TestData
