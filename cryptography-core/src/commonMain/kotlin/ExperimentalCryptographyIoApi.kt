/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

@RequiresOptIn(
    level = RequiresOptIn.Level.WARNING,
    message = """
              This is an experimental API for integration with kotlinx-io.
              There are 2 reasons for this:
              1. kotlinx-io is not stable yet, so some changes to API and behavior are possible
              2. API itself is not stable yet, and will evolve based on feedback
              """
)
public annotation class ExperimentalCryptographyIoApi
