/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.Serializable

/**
 * Represents a raw ASN.1 element (tag + length + value) captured as-is.
 * Useful for preserving unknown parameters for round-trip encoding.
 */
@Serializable
public class Asn1Any(public val bytes: ByteArray)

