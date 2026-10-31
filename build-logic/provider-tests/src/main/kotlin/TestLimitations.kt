/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import kotlinx.serialization.*
import kotlinx.serialization.json.*
import org.gradle.api.*
import java.io.File

// Limitations of providers observed in test reports: environment (`provider/platform`) -> suite id -> limitations
class TestLimitations internal constructor(
    val environments: Map<String, Map<String, SuiteLimitations>>,
) {
    // environments of a provider, f.e. `jdk.default`
    fun environments(provider: String): List<String> = environments.keys.filter { it.substringBefore('/') == provider }
}

class SuiteLimitations internal constructor() {
    // the suite is not supported: nothing was validated, descriptions of failed operations
    val unsupported: MutableSet<String> = mutableSetOf()

    // the suite is supported, but some operations are limited
    val limitations: MutableSet<Limitation> = mutableSetOf()

    data class Limitation(val kind: String, val description: String)
}

// region storage

// latest runs for each (exact environment, suite), so that partial local runs don't lose results of other suites
internal fun Map<String, TestRun>.toTestLimitations(): TestLimitations {
    val latest = mutableMapOf<Pair<TestEnvironment, String>, List<TestExecutionReport>>()
    values.forEach { run ->
        run.suites.forEach { (suiteId, reports) -> latest[run.environment to suiteId] = reports }
    }
    val environments = mutableMapOf<String, MutableMap<String, SuiteLimitations>>()
    latest.forEach { (key, reports) ->
        val (environment, suiteId) = key
        val suite = environments.getOrPut(environment.label(), ::mutableMapOf).getOrPut(suiteId, ::SuiteLimitations)
        val limitations = reports.flatMap { it.limitations.values.flatten() }
        val failures = limitations.filter { it.kind == "Fails" }
        when {
            // f.e. the algorithm is not supported, or all operations of the suite fail
            reports.all { it.validated == 0 } && failures.isNotEmpty()
                 -> failures.mapTo(suite.unsupported) { it.description }
            else -> limitations.mapTo(suite.limitations) { SuiteLimitations.Limitation(it.kind, it.description) }
        }
    }
    return TestLimitations(environments)
}

// `provider/platform`, version-insensitive except what limitations depend on
private fun TestEnvironment.label(): String {
    val providerLabel = when (provider.type) {
        "openssl3" -> when {
            provider.version.orEmpty().startsWith("3.0") -> "openssl3-3.0"
            else                                         -> "openssl3-3.x"
        }
        else       -> provider.type
    }
    val platformLabel = when (platform.type) {
        "jdk"                           -> "jdk-${platform.major}"
        "android"                       -> "android"
        "native"                        -> "native-${platform.os.orEmpty().lowercase()}"
        "js.nodejs", "wasm.js.nodejs"   -> "nodejs"
        "js.browser", "wasm.js.browser" -> "browser-${browserBrand(platform.userAgent.orEmpty())}"
        else                            -> throw GradleException("Unsupported test platform: ${platform.type}")
    }
    return "$providerLabel/$platformLabel"
}

// `brand` is not available in all browsers
private fun browserBrand(userAgent: String): String = when {
    "Firefox/" in userAgent -> "firefox"
    "Chrome/" in userAgent  -> "chrome"
    "Safari/" in userAgent  -> "safari"
    else                    -> throw GradleException("Unsupported browser: $userAgent")
}

// endregion

// region snapshot

// Committed snapshot format (suite-first, everything is only where needed):
// {
//   "environments": ["jdk.default/jdk-8", "webcrypto/browser-safari", ...],
//   "suites": {
//     "AES-CCM": {
//       "untested": [environments],
//       "unsupported": [{ "description", "environments"? }],
//       "limitations": [{ "kind", "description", "environments"? }]
//     }
//   }
// }
// environments in entries: a bare provider (f.e. `jdk.default`) means all environments of this provider; absent means all environments
@Serializable
private class Snapshot(
    val environments: List<String>,
    val suites: Map<String, Suite>,
) {
    @Serializable
    class Suite(
        val untested: List<String>? = null,
        val unsupported: List<Entry>? = null,
        val limitations: List<Entry>? = null,
    )

    @Serializable
    class Entry(
        val kind: String? = null,
        val description: String,
        val environments: List<String>? = null,
    )
}

@OptIn(ExperimentalSerializationApi::class)
private val json = Json {
    prettyPrint = true
    // the same as IDEs use for JSON by default, so that reformatting doesn't change the file
    prettyPrintIndent = "  "
    explicitNulls = false
}

fun readTestLimitations(file: File): TestLimitations {
    val snapshot = json.decodeFromString<Snapshot>(file.readText())

    // reverse of `compress` in `writeTestLimitations`
    fun expand(environments: List<String>?): List<String> = when (environments) {
        null -> snapshot.environments
        else -> environments.flatMap { pattern ->
            when {
                '/' in pattern -> listOf(pattern)
                else           -> snapshot.environments.filter { it.substringBefore('/') == pattern }
            }
        }
    }

    val environments = snapshot.environments.associateWith { mutableMapOf<String, SuiteLimitations>() }
    snapshot.suites.forEach { (suiteId, suite) ->
        val untested = expand(suite.untested.orEmpty()).toSet()
        snapshot.environments.filter { it !in untested }.forEach { environments.getValue(it)[suiteId] = SuiteLimitations() }
        suite.unsupported.orEmpty().forEach { entry ->
            expand(entry.environments).forEach { environments.getValue(it).getValue(suiteId).unsupported.add(entry.description) }
        }
        suite.limitations.orEmpty().forEach { entry ->
            val limitation = SuiteLimitations.Limitation(entry.kind!!, entry.description)
            expand(entry.environments).forEach { environments.getValue(it).getValue(suiteId).limitations.add(limitation) }
        }
    }
    return TestLimitations(environments)
}

internal fun writeTestLimitations(file: File, limitations: TestLimitations) {
    val environments = limitations.environments.keys.sorted()

    // all environments -> absent, all environments of a provider -> provider
    fun compress(subset: Set<String>): List<String>? {
        if (subset.size == environments.size) return null
        return environments.groupBy { it.substringBefore('/') }.flatMap { (provider, providerEnvironments) ->
            when {
                subset.containsAll(providerEnvironments) -> listOf(provider)
                else                                     -> providerEnvironments.filter { it in subset }
            }
        }
    }

    fun <T> entries(
        suiteId: String,
        select: (SuiteLimitations) -> Set<T>,
        entry: (T, List<String>?) -> Snapshot.Entry,
    ): List<Snapshot.Entry>? {
        val byValue = mutableMapOf<T, MutableSet<String>>()
        environments.forEach { environment ->
            limitations.environments.getValue(environment)[suiteId]?.let(select)?.forEach {
                byValue.getOrPut(it, ::mutableSetOf).add(environment)
            }
        }
        return byValue.map { (value, valueEnvironments) -> entry(value, compress(valueEnvironments)) }
            .sortedWith(compareBy({ it.kind }, { it.description }))
            .takeIf { it.isNotEmpty() }
    }

    val suiteIds = limitations.environments.values.flatMapTo(sortedSetOf()) { it.keys }
    val snapshot = Snapshot(
        environments = environments,
        suites = suiteIds.associateWith { suiteId ->
            Snapshot.Suite(
                untested = compress(environments.filterTo(mutableSetOf()) { suiteId !in limitations.environments.getValue(it) })
                    ?.takeIf { it.isNotEmpty() },
                unsupported = entries(suiteId, SuiteLimitations::unsupported) { description, environments ->
                    Snapshot.Entry(description = description, environments = environments)
                },
                limitations = entries(suiteId, SuiteLimitations::limitations) { limitation, environments ->
                    Snapshot.Entry(limitation.kind, limitation.description, environments)
                },
            )
        },
    )
    file.writeText(json.encodeToString(snapshot) + "\n")
}

// endregion
