/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("ArrayInDataClass")

package dev.whyoleg.cryptography.tests.compatibility.api

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


typealias SerializableBuffer = @Contextual ByteArray

@Serializable
data class DigestData(val data: SerializableBuffer, val digest: SerializableBuffer) : TestData {
    override fun toString(): String = "DigestData(data.size=${data.size}, digest.size=${digest.size})"
}

@Serializable
data class KeyData(val formats: Map<String, SerializableBuffer>) : TestData {
    override fun toString(): String = "KeyData(formats=${formats.mapValues { it.value.size }})"
}

inline fun KeyData(block: MutableMap<String, ByteArray>.() -> Unit): KeyData = KeyData(buildMap(block))

@Serializable
data class KeyPairData(val public: KeyData, val private: KeyData) : TestData

@Serializable
data class CipherData(
    val keyReference: TestReference,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
) : TestData {
    override fun toString(): String {
        return "CipherData(keyReference=$keyReference, plaintext.size=${plaintext.size}, ciphertext.size=${ciphertext.size})"
    }
}

@Serializable
data class AuthenticatedCipherData(
    val keyReference: TestReference,
    val associatedData: SerializableBuffer?,
    val plaintext: SerializableBuffer,
    val ciphertext: SerializableBuffer,
) : TestData {
    override fun toString(): String {
        return "AuthenticatedCipherData(keyReference=$keyReference, associatedData.size=${associatedData?.size}, plaintext.size=${plaintext.size}, ciphertext.size=${ciphertext.size})"
    }
}

@Serializable
data class SignatureData(
    val keyReference: TestReference,
    val data: SerializableBuffer,
    val signature: SerializableBuffer,
) : TestData {
    override fun toString(): String {
        return "SignatureData(keyReference=$keyReference, data.size=${data.size}, signature.size=${signature.size})"
    }
}
