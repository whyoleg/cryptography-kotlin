/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

/**
 * Marks APIs intended for cryptography provider implementations.
 *
 * These APIs are not meant for general library users and are subject to change.
 */
@RequiresOptIn(
    message = "API of everything what is implemented in providers is experimental for now and subject to change (if possible in backward-compatible way)",
    level = RequiresOptIn.Level.ERROR
)
public annotation class CryptographyProviderApi
