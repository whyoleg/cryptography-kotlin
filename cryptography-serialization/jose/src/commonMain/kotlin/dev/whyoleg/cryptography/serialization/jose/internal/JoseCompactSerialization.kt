/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.internal

import kotlinx.serialization.json.Json

/**
 * Common interface for JOSE compact serialization formats.
 */
internal interface JoseCompactSerialization {
    
    /**
     * Encodes this object as a compact serialization string.
     */
    fun encode(): String
    
    /**
     * Gets the header as a JSON string for encoding.
     */
    fun getHeaderJson(): String
}

/**
 * Common utilities for JOSE compact serialization.
 */
internal object JoseCompactUtils {
    
    /**
     * Creates a compact serialization string from the given parts.
     */
    fun createCompactString(vararg parts: String): String = parts.joinToString(".")
    
    /**
     * Parses a compact serialization string into its parts.
     */
    fun parseCompactString(compact: String, expectedParts: Int): List<String> {
        val parts = compact.split('.')
        require(parts.size == expectedParts) { 
            "Invalid compact format: expected $expectedParts parts separated by dots, got ${parts.size}" 
        }
        return parts
    }
}