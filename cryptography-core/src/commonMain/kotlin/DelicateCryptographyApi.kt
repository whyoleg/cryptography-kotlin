/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@RequiresOptIn(
    message = "API marked with this annotation should be used only when you know what you are doing. Avoid usage of such declarations as much as possible. They are provided mostly for backward compatibility with older services that require them.",
    level = RequiresOptIn.Level.ERROR
)
public annotation class DelicateCryptographyApi
