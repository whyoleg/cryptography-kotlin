/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * JSON Web Algorithms (JWA) as defined in RFC 7518.
 */

/**
 * Digital Signature or MAC Algorithms for JWS (Section 3.1)
 */
@Serializable
@JvmInline
public value class JwsAlgorithm(public val value: String) {
    public companion object {
        /** HMAC using SHA-256 */
        public val HS256: JwsAlgorithm = JwsAlgorithm("HS256")
        /** HMAC using SHA-384 */
        public val HS384: JwsAlgorithm = JwsAlgorithm("HS384")
        /** HMAC using SHA-512 */
        public val HS512: JwsAlgorithm = JwsAlgorithm("HS512")
        /** RSASSA-PKCS1-v1_5 using SHA-256 */
        public val RS256: JwsAlgorithm = JwsAlgorithm("RS256")
        /** RSASSA-PKCS1-v1_5 using SHA-384 */
        public val RS384: JwsAlgorithm = JwsAlgorithm("RS384")
        /** RSASSA-PKCS1-v1_5 using SHA-512 */
        public val RS512: JwsAlgorithm = JwsAlgorithm("RS512")
        /** ECDSA using P-256 and SHA-256 */
        public val ES256: JwsAlgorithm = JwsAlgorithm("ES256")
        /** ECDSA using P-384 and SHA-384 */
        public val ES384: JwsAlgorithm = JwsAlgorithm("ES384")
        /** ECDSA using P-521 and SHA-512 */
        public val ES512: JwsAlgorithm = JwsAlgorithm("ES512")
        /** RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
        public val PS256: JwsAlgorithm = JwsAlgorithm("PS256")
        /** RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
        public val PS384: JwsAlgorithm = JwsAlgorithm("PS384")
        /** RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
        public val PS512: JwsAlgorithm = JwsAlgorithm("PS512")
        /** No digital signature or MAC performed */
        public val NONE: JwsAlgorithm = JwsAlgorithm("none")
    }
}

/**
 * Key Management Algorithms for JWE (Section 4.1)
 */
@Serializable
@JvmInline
public value class JweKeyManagementAlgorithm(public val value: String) {
    public companion object {
        /** RSAES-PKCS1-v1_5 */
        public val RSA1_5: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("RSA1_5")
        /** RSAES OAEP using default parameters */
        public val RSA_OAEP: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("RSA-OAEP")
        /** RSAES OAEP using SHA-256 and MGF1 with SHA-256 */
        public val RSA_OAEP_256: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("RSA-OAEP-256")
        /** AES Key Wrap with default initial value using 128-bit key */
        public val A128KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A128KW")
        /** AES Key Wrap with default initial value using 192-bit key */
        public val A192KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A192KW")
        /** AES Key Wrap with default initial value using 256-bit key */
        public val A256KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A256KW")
        /** Direct use of a shared symmetric key as the CEK */
        public val DIR: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("dir")
        /** Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF */
        public val ECDH_ES: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("ECDH-ES")
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 128-bit key */
        public val ECDH_ES_A128KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("ECDH-ES+A128KW")
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 192-bit key */
        public val ECDH_ES_A192KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("ECDH-ES+A192KW")
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 256-bit key */
        public val ECDH_ES_A256KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("ECDH-ES+A256KW")
        /** AES GCM key encryption with a 128-bit key */
        public val A128GCMKW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A128GCMKW")
        /** AES GCM key encryption with a 192-bit key */
        public val A192GCMKW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A192GCMKW")
        /** AES GCM key encryption with a 256-bit key */
        public val A256GCMKW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("A256GCMKW")
        /** PBES2 with HMAC SHA-256 and AES Key Wrap with 128-bit key */
        public val PBES2_HS256_A128KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("PBES2-HS256+A128KW")
        /** PBES2 with HMAC SHA-384 and AES Key Wrap with 192-bit key */
        public val PBES2_HS384_A192KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("PBES2-HS384+A192KW")
        /** PBES2 with HMAC SHA-512 and AES Key Wrap with 256-bit key */
        public val PBES2_HS512_A256KW: JweKeyManagementAlgorithm = JweKeyManagementAlgorithm("PBES2-HS512+A256KW")
    }
}

/**
 * Content Encryption Algorithms for JWE (Section 5.1)
 */
@Serializable
@JvmInline
public value class JweContentEncryptionAlgorithm(public val value: String) {
    public companion object {
        /** AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm */
        public val A128CBC_HS256: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A128CBC-HS256")
        /** AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm */
        public val A192CBC_HS384: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A192CBC-HS384")
        /** AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm */
        public val A256CBC_HS512: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A256CBC-HS512")
        /** AES GCM using 128-bit key */
        public val A128GCM: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A128GCM")
        /** AES GCM using 192-bit key */
        public val A192GCM: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A192GCM")
        /** AES GCM using 256-bit key */
        public val A256GCM: JweContentEncryptionAlgorithm = JweContentEncryptionAlgorithm("A256GCM")
    }
}