/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.Serializable

/**
 * Represents a raw ASN.1 element captured as-is.
 *
 * Notes:
 * - [bytes] contains the full TLV (Tag + Length + Value), not only the value bytes.
 * - Useful for preserving unknown parameters for exact round‑trip encoding.
 */
@Serializable
public class Asn1Any(public val bytes: ByteArray)
