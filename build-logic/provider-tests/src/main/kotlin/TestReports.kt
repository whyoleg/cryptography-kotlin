/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import ckbuild.teststorage.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*

// Reports of `cryptography-tests` in the test storage:
// * `[run-id].json` - `TestEnvironment`
// * `[run-id]/[suite-id]/[test-id].json` - `TestExecutionReport`
// * `[run-id]/[suite-id].restore/report.json` - restoration report, not used here
// The models are minimal copies of the classes in `cryptography-tests` and `cryptography-testhost`

internal class TestRun(
    val environment: TestEnvironment,
    // suite id -> reports of tests
    val suites: Map<String, List<TestExecutionReport>>,
)

// see `TestEnvironment` in `cryptography-tests`
@Serializable
internal data class TestEnvironment(
    // see `TestPlatform` in `cryptography-testhost`
    val platform: Descriptor,
    // see `TestProvider` in `cryptography-tests`
    val provider: Descriptor,
) {
    // only properties used for labels, see `environmentLabel`
    @Serializable
    data class Descriptor(
        val type: String,
        val version: String? = null,
        val major: Int? = null,
        val os: String? = null,
        val userAgent: String? = null,
    )
}

// see `TestExecutionReport` in `cryptography-tests`
@Serializable
internal class TestExecutionReport(
    val validated: Int,
    val limitations: Map<String, List<TestExecutionLimitation>>,
)

@Serializable
internal class TestExecutionLimitation(
    val operation: String,
    val kind: String,
    val description: String,
)

private val json = Json { ignoreUnknownKeys = true }

// sorted by run id (UUID v7), so from the oldest to the newest
internal fun TestStorage.readTestRuns(): Map<String, TestRun> = list(emptyList())
    .filter { it.endsWith(".json") }
    .sorted()
    .associate { runFile ->
        val runId = runFile.removeSuffix(".json")
        val suites = directories(listOf(runId)).filterNot { it.endsWith(".restore") }.associateWith { suiteId ->
            list(listOf(runId, suiteId)).filter { it.endsWith(".json") }.map { reportFile ->
                json.decodeFromString<TestExecutionReport>(get(listOf(runId, suiteId, reportFile)))
            }
        }
        runId to TestRun(json.decodeFromString(get(listOf(runFile))), suites)
    }
