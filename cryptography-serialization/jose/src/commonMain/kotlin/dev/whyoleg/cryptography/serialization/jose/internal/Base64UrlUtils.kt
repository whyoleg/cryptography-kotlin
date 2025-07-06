/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.internal

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Internal utilities for Base64 URL-safe encoding/decoding used across JOSE implementations.
 */
@OptIn(ExperimentalEncodingApi::class)
internal object Base64UrlUtils {
    
    /**
     * Encodes byte array to Base64 URL-safe string without padding.
     */
    fun encode(data: ByteArray): String = Base64.UrlSafe.encode(data).trimEnd('=')
    
    /**
     * Encodes string to Base64 URL-safe string without padding.
     */
    fun encode(data: String): String = encode(data.encodeToByteArray())
    
    /**
     * Decodes Base64 URL-safe string to byte array, adding padding if needed.
     */
    fun decode(encoded: String): ByteArray = Base64.UrlSafe.decode(encoded.padBase64())
    
    /**
     * Decodes Base64 URL-safe string to string, adding padding if needed.
     */
    fun decodeToString(encoded: String): String = decode(encoded).decodeToString()
    
    /**
     * Adds Base64 padding to a string if needed.
     */
    private fun String.padBase64(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}