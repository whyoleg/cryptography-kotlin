/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.cryptography.jose

/**
 * JSON Web Algorithms (JWA) constants as defined in RFC 7518.
 * 
 * This object contains constants for cryptographic algorithms used in JOSE.
 */
public object JsonWebAlgorithms {
    // Digital Signature or MAC Algorithms for JWS (Section 3.1)
    public object Signature {
        /** HMAC using SHA-256 */
        public const val HS256: String = "HS256"
        /** HMAC using SHA-384 */
        public const val HS384: String = "HS384"
        /** HMAC using SHA-512 */
        public const val HS512: String = "HS512"
        /** RSASSA-PKCS1-v1_5 using SHA-256 */
        public const val RS256: String = "RS256"
        /** RSASSA-PKCS1-v1_5 using SHA-384 */
        public const val RS384: String = "RS384"
        /** RSASSA-PKCS1-v1_5 using SHA-512 */
        public const val RS512: String = "RS512"
        /** ECDSA using P-256 and SHA-256 */
        public const val ES256: String = "ES256"
        /** ECDSA using P-384 and SHA-384 */
        public const val ES384: String = "ES384"
        /** ECDSA using P-521 and SHA-512 */
        public const val ES512: String = "ES512"
        /** RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
        public const val PS256: String = "PS256"
        /** RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
        public const val PS384: String = "PS384"
        /** RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
        public const val PS512: String = "PS512"
        /** No digital signature or MAC performed */
        public const val NONE: String = "none"
    }
    
    // Key Management Algorithms for JWE (Section 4.1)
    public object KeyManagement {
        /** RSAES-PKCS1-v1_5 */
        public const val RSA1_5: String = "RSA1_5"
        /** RSAES OAEP using default parameters */
        public const val RSA_OAEP: String = "RSA-OAEP"
        /** RSAES OAEP using SHA-256 and MGF1 with SHA-256 */
        public const val RSA_OAEP_256: String = "RSA-OAEP-256"
        /** AES Key Wrap with default initial value using 128-bit key */
        public const val A128KW: String = "A128KW"
        /** AES Key Wrap with default initial value using 192-bit key */
        public const val A192KW: String = "A192KW"
        /** AES Key Wrap with default initial value using 256-bit key */
        public const val A256KW: String = "A256KW"
        /** Direct use of a shared symmetric key as the CEK */
        public const val DIR: String = "dir"
        /** Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF */
        public const val ECDH_ES: String = "ECDH-ES"
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 128-bit key */
        public const val ECDH_ES_A128KW: String = "ECDH-ES+A128KW"
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 192-bit key */
        public const val ECDH_ES_A192KW: String = "ECDH-ES+A192KW"
        /** ECDH Ephemeral Static key agreement using Concat KDF and CEK wrapped with AES Key Wrap using a 256-bit key */
        public const val ECDH_ES_A256KW: String = "ECDH-ES+A256KW"
        /** AES GCM key encryption with a 128-bit key */
        public const val A128GCMKW: String = "A128GCMKW"
        /** AES GCM key encryption with a 192-bit key */
        public const val A192GCMKW: String = "A192GCMKW"
        /** AES GCM key encryption with a 256-bit key */
        public const val A256GCMKW: String = "A256GCMKW"
        /** PBES2 with HMAC SHA-256 and AES Key Wrap with 128-bit key */
        public const val PBES2_HS256_A128KW: String = "PBES2-HS256+A128KW"
        /** PBES2 with HMAC SHA-384 and AES Key Wrap with 192-bit key */
        public const val PBES2_HS384_A192KW: String = "PBES2-HS384+A192KW"
        /** PBES2 with HMAC SHA-512 and AES Key Wrap with 256-bit key */
        public const val PBES2_HS512_A256KW: String = "PBES2-HS512+A256KW"
    }
    
    // Content Encryption Algorithms for JWE (Section 5.1)
    public object ContentEncryption {
        /** AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm */
        public const val A128CBC_HS256: String = "A128CBC-HS256"
        /** AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm */
        public const val A192CBC_HS384: String = "A192CBC-HS384"
        /** AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm */
        public const val A256CBC_HS512: String = "A256CBC-HS512"
        /** AES GCM using 128-bit key */
        public const val A128GCM: String = "A128GCM"
        /** AES GCM using 192-bit key */
        public const val A192GCM: String = "A192GCM"
        /** AES GCM using 256-bit key */
        public const val A256GCM: String = "A256GCM"
    }
}