/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

import android.os.*

internal actual val currentTestPlatform: TestPlatform = TestPlatform.Android(
    apiLevel = Build.VERSION.SDK_INT
)
