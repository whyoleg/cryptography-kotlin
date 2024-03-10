/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = """
              This is an API which should be used only for providing support for additional cryptography implementations.
              This API is subject to change, if possible in backward-compatible way.
              """
)
public annotation class CryptographyProviderApi
