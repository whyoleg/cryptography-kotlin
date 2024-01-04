/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import kotlinx.browser.*

internal actual val currentTestPlatform: TestPlatform = run {
    when (js("typeof process !== 'undefined' && process.versions != null && process.versions.node != null").unsafeCast<Boolean>()) {
        true  -> TestPlatform.NodeJS(
            version = js("process.version").unsafeCast<String?>() ?: "",
            os = js("process.platform").unsafeCast<String?>() ?: "",
            arch = js("process.arch").unsafeCast<String?>() ?: ""
        )
        // https://developer.mozilla.org/en-US/docs/Web/API/NavigatorUAData
        // https://developer.mozilla.org/en-US/docs/Web/API/Navigator/platform
        false -> TestPlatform.Browser(
            brand = js("navigator.userAgentData ? navigator.userAgentData.brand : ''").unsafeCast<String?>() ?: "",
            platform = js("navigator.userAgentData ? navigator.userAgentData.platform : navigator.platform").unsafeCast<String?>() ?: "",
            userAgent = window.navigator.userAgent
        )
    }
}
