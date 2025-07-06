/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * JSON Web Encryption (JWE) as defined in RFC 7516.
 * 
 * JWE represents encrypted content using JSON-based data structures.
 */

/**
 * JWE Header parameters as defined in RFC 7516 Section 4.1.
 */
@Serializable
public data class JweHeader(
    /** Algorithm used for key management */
    @SerialName("alg")
    val algorithm: JweKeyManagementAlgorithm,
    /** Content encryption algorithm */
    @SerialName("enc")
    val encryptionAlgorithm: JweContentEncryptionAlgorithm,
    /** JWE Type parameter */
    @SerialName("typ")
    val type: String? = null,
    /** Content Type parameter */
    @SerialName("cty")
    val contentType: String? = null,
    /** Key ID hint indicating which key was used to encrypt the JWE */
    @SerialName("kid")
    val keyId: String? = null,
    /** JSON Web Key parameter */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,
    /** X.509 URL parameter */
    @SerialName("x5u")
    val x509Url: String? = null,
    /** X.509 Certificate Chain parameter */
    @SerialName("x5c")
    val x509CertificateChain: List<String>? = null,
    /** X.509 Certificate SHA-1 Thumbprint parameter */
    @SerialName("x5t")
    val x509CertificateSha1Thumbprint: String? = null,
    /** X.509 Certificate SHA-256 Thumbprint parameter */
    @SerialName("x5t#S256")
    val x509CertificateSha256Thumbprint: String? = null,
    /** Critical parameter - identifies which extensions are critical */
    @SerialName("crit")
    val critical: List<String>? = null,
    /** Ephemeral Public Key parameter (for ECDH-ES key agreement) */
    @SerialName("epk")
    val ephemeralPublicKey: JsonWebKey? = null,
    /** Agreement PartyUInfo parameter (for ECDH-ES key agreement) */
    @SerialName("apu")
    val agreementPartyUInfo: String? = null,
    /** Agreement PartyVInfo parameter (for ECDH-ES key agreement) */
    @SerialName("apv")
    val agreementPartyVInfo: String? = null,
    /** Key Mgmt Alg Initialization Vector parameter (for AES GCM key encryption) */
    @SerialName("iv")
    val initializationVector: String? = null,
    /** Key Mgmt Alg Authentication Tag parameter (for AES GCM key encryption) */
    @SerialName("tag")
    val authenticationTag: String? = null,
    /** PBES2 Salt Input parameter (for PBES2 key encryption) */
    @SerialName("p2s")
    val pbes2SaltInput: String? = null,
    /** PBES2 Count parameter (for PBES2 key encryption) */
    @SerialName("p2c")
    val pbes2Count: Long? = null,
    /** Additional header parameters */
    val additionalParameters: Map<String, JsonElement> = emptyMap()
)

/**
 * JSON Web Encryption Compact Serialization format.
 * 
 * Represents a JWE in the Compact Serialization format:
 * BASE64URL(UTF8(JWE Protected Header)) || '.' ||
 * BASE64URL(JWE Encrypted Key) || '.' ||
 * BASE64URL(JWE Initialization Vector) || '.' ||
 * BASE64URL(JWE Ciphertext) || '.' ||
 * BASE64URL(JWE Authentication Tag)
 */
@Serializable
public data class JweCompact(
    val header: JweHeader,
    val encryptedKey: ByteArray,
    val initializationVector: ByteArray,
    val ciphertext: ByteArray,
    val authenticationTag: ByteArray
) {
    /**
     * Encodes the JWE as a compact serialization string.
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun encode(): String {
        val headerJson = Json.encodeToString(JweHeader.serializer(), header)
        val headerEncoded = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
        val encryptedKeyEncoded = Base64.UrlSafe.encode(encryptedKey).trimEnd('=')
        val ivEncoded = Base64.UrlSafe.encode(initializationVector).trimEnd('=')
        val ciphertextEncoded = Base64.UrlSafe.encode(ciphertext).trimEnd('=')
        val authTagEncoded = Base64.UrlSafe.encode(authenticationTag).trimEnd('=')
        
        return "$headerEncoded.$encryptedKeyEncoded.$ivEncoded.$ciphertextEncoded.$authTagEncoded"
    }
    
    /**
     * Returns the Additional Authenticated Data (AAD) for decryption.
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun getAdditionalAuthenticatedData(): ByteArray {
        val headerJson = Json.encodeToString(JweHeader.serializer(), header)
        val headerEncoded = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
        return headerEncoded.encodeToByteArray()
    }
    
    public companion object {
        /**
         * Decodes a JWE from its compact serialization string.
         */
        @OptIn(ExperimentalEncodingApi::class)
        public fun decode(jweString: String): JweCompact {
            val parts = jweString.split('.')
            require(parts.size == 5) { "Invalid JWE format: expected 5 parts separated by dots" }
            
            val headerJson = Base64.UrlSafe.decode(parts[0].padBase64()).decodeToString()
            val encryptedKey = Base64.UrlSafe.decode(parts[1].padBase64())
            val initializationVector = Base64.UrlSafe.decode(parts[2].padBase64())
            val ciphertext = Base64.UrlSafe.decode(parts[3].padBase64())
            val authenticationTag = Base64.UrlSafe.decode(parts[4].padBase64())
            
            val header = Json.decodeFromString(JweHeader.serializer(), headerJson)
            
            return JweCompact(header, encryptedKey, initializationVector, ciphertext, authenticationTag)
        }
        
        private fun String.padBase64(): String {
            val padding = (4 - length % 4) % 4
            return this + "=".repeat(padding)
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        
        other as JweCompact
        
        if (header != other.header) return false
        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authenticationTag.contentEquals(other.authenticationTag)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + encryptedKey.contentHashCode()
        result = 31 * result + initializationVector.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + authenticationTag.contentHashCode()
        return result
    }
}

/**
 * JWE Recipient for JSON Serialization format.
 */
@Serializable
public data class JweRecipient(
    /** Protected header parameters (base64url encoded) */
    @SerialName("header")
    val header: JweHeader? = null,
    /** The encrypted key value for this recipient */
    @SerialName("encrypted_key")
    val encryptedKey: String
)

/**
 * JSON Web Encryption JSON Serialization format.
 * 
 * Represents a JWE in the JSON Serialization format as defined in RFC 7516 Section 7.2.
 */
@Serializable
public data class JweJson(
    /** Protected header parameters (base64url encoded) */
    @SerialName("protected")
    val protectedHeader: String? = null,
    /** Unprotected header parameters */
    @SerialName("unprotected")
    val unprotectedHeader: JweHeader? = null,
    /** Array of recipient objects for General JSON Serialization */
    @SerialName("recipients")
    val recipients: List<JweRecipient>? = null,
    /** For Flattened JSON Serialization - recipient header */
    @SerialName("header")
    val header: JweHeader? = null,
    /** For Flattened JSON Serialization - encrypted key */
    @SerialName("encrypted_key")
    val encryptedKey: String? = null,
    /** The initialization vector */
    @SerialName("iv")
    val initializationVector: String,
    /** The ciphertext */
    @SerialName("ciphertext")
    val ciphertext: String,
    /** The authentication tag */
    @SerialName("tag")
    val authenticationTag: String
) {
    /**
     * Converts this JSON serialization to compact serialization if it contains exactly one recipient.
     */
    @OptIn(ExperimentalEncodingApi::class)
    public fun toCompact(): JweCompact? {
        // Handle Flattened JSON Serialization
        if (recipients == null && encryptedKey != null && protectedHeader != null) {
            val headerJson = Base64.UrlSafe.decode(protectedHeader.padBase64()).decodeToString()
            val header = Json.decodeFromString(JweHeader.serializer(), headerJson)
            val encryptedKeyBytes = Base64.UrlSafe.decode(encryptedKey.padBase64())
            val ivBytes = Base64.UrlSafe.decode(initializationVector.padBase64())
            val ciphertextBytes = Base64.UrlSafe.decode(ciphertext.padBase64())
            val authTagBytes = Base64.UrlSafe.decode(authenticationTag.padBase64())
            
            return JweCompact(header, encryptedKeyBytes, ivBytes, ciphertextBytes, authTagBytes)
        }
        
        // Handle General JSON Serialization with single recipient
        if (recipients?.size == 1 && protectedHeader != null) {
            val recipient = recipients.first()
            val headerJson = Base64.UrlSafe.decode(protectedHeader.padBase64()).decodeToString()
            val header = Json.decodeFromString(JweHeader.serializer(), headerJson)
            val encryptedKeyBytes = Base64.UrlSafe.decode(recipient.encryptedKey.padBase64())
            val ivBytes = Base64.UrlSafe.decode(initializationVector.padBase64())
            val ciphertextBytes = Base64.UrlSafe.decode(ciphertext.padBase64())
            val authTagBytes = Base64.UrlSafe.decode(authenticationTag.padBase64())
            
            return JweCompact(header, encryptedKeyBytes, ivBytes, ciphertextBytes, authTagBytes)
        }
        
        return null
    }
    
    /**
     * Checks if this is a flattened JSON serialization.
     */
    public val isFlattened: Boolean
        get() = recipients == null && encryptedKey != null
    
    /**
     * Checks if this is a general JSON serialization.
     */
    public val isGeneral: Boolean
        get() = recipients != null
    
    public companion object {
        /**
         * Creates a flattened JSON serialization from a compact JWE.
         */
        @OptIn(ExperimentalEncodingApi::class)
        public fun fromCompact(compact: JweCompact): JweJson {
            val headerJson = Json.encodeToString(JweHeader.serializer(), compact.header)
            val protectedHeader = Base64.UrlSafe.encode(headerJson.encodeToByteArray()).trimEnd('=')
            val encryptedKey = Base64.UrlSafe.encode(compact.encryptedKey).trimEnd('=')
            val iv = Base64.UrlSafe.encode(compact.initializationVector).trimEnd('=')
            val ciphertext = Base64.UrlSafe.encode(compact.ciphertext).trimEnd('=')
            val authTag = Base64.UrlSafe.encode(compact.authenticationTag).trimEnd('=')
            
            return JweJson(
                protectedHeader = protectedHeader,
                encryptedKey = encryptedKey,
                initializationVector = iv,
                ciphertext = ciphertext,
                authenticationTag = authTag
            )
        }
        
        private fun String.padBase64(): String {
            val padding = (4 - length % 4) % 4
            return this + "=".repeat(padding)
        }
    }
}