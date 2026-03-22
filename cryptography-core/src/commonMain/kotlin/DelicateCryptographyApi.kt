/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

/**
 * Marks APIs that require careful consideration before use.
 *
 * Applied to cryptographically weak algorithms (e.g., MD5, SHA-1),
 * unsafe modes (e.g., ECB, raw RSA), and operations requiring manual management
 * of security-critical parameters (e.g., explicit IV handling).
 */
@RequiresOptIn(
    message = "API marked with this annotation should be used only when you know what you are doing. Avoid usage of such declarations as much as possible. They are provided mostly for backward compatibility with older services that require them.",
    level = RequiresOptIn.Level.ERROR
)
@MustBeDocumented
public annotation class DelicateCryptographyApi
