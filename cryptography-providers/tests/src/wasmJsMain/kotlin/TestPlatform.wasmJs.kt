/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

internal actual val currentTestPlatform: TestPlatform = jsPlatform().run {
    when {
        isNode -> TestPlatform.WasmJs.NodeJS(
            version = nodeVersion ?: "",
            os = nodeOs ?: "",
            arch = nodeArch ?: "",
        )
        else   -> TestPlatform.WasmJs.Browser(
            brand = browserBrand ?: "",
            platform = browserPlatform ?: "",
            userAgent = browserUserAgent ?: "",
        )
    }
}

// https://developer.mozilla.org/en-US/docs/Web/API/NavigatorUAData
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator/platform
//language=JavaScript
private fun jsPlatform(): JsPlatform {
    js(
        code = """

        var isNodeJs = typeof process !== 'undefined' && process.versions != null && process.versions.node != null

        if (isNodeJs) {
            return {
                isNode: true,
                nodeVersion: process.version,
                nodeOs: process.platform,
                nodeArch: process.arch
            };
        } else {
            return {
                isNode: false,
                browserBrand: navigator.userAgentData ? navigator.userAgentData.brand : '',
                browserPlatform: navigator.userAgentData ? navigator.userAgentData.platform : navigator.platform,
                browserUserAgent: window.navigator.userAgent
            };
        }
        
               """
    )
}

private external interface JsPlatform : JsAny {
    val isNode: Boolean

    // nodeJs
    val nodeVersion: String?
    val nodeOs: String?
    val nodeArch: String?

    // browser
    val browserBrand: String?
    val browserPlatform: String?
    val browserUserAgent: String?
}
