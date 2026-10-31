/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.testhost.*
import kotlinx.coroutines.test.*
import kotlin.time.Duration.Companion.minutes

// Storage layout:
// [run-id].json                       -> TestEnvironment
// [run-id]/[suite-id]/[test-id].json  -> TestExecutionReport
// [run-id]/[suite-id]/[test-id]/...   -> test nodes (see `TestStorage`)

// generates, validates and stores test data
internal fun runGenerationTest(
    provider: CryptographyProvider,
    // f.e. algorithm name
    suiteId: String,
    testId: String,
    store: Boolean,
    block: suspend context(TestGenerationContext) () -> Unit,
): TestResult = runTest(timeout = 10.minutes) {
    val environment = TestEnvironment(provider)
    val runId = currentRunId(provider)
    val client = if (store) TestStorageClient.default() else TestStorageClient.noop()
    val root = TestStorage(client, emptyList())
    root.save(runId, environment, TestEnvironment.serializer())
    val storage = root.child(runId).child(suiteId)
    val report = TestReportBuilder()
    val context = TestGenerationContext(TestNode(storage.child(testId), testId, TestLimitationScope(environment), report))
    try {
        val _ = runNode(context.node) { context(context) { block() } }
    } finally {
        storage.save(testId, report.build(), TestExecutionReport.serializer())
    }
    println(report.build().summary("$suiteId/$testId"))
    report.checkNotSkipped(testId, TestReportBuilder().mark())
}

// validates all data stored by other runs (other providers, platforms, or previous runs of the same provider)
internal fun runRestorationTest(
    provider: CryptographyProvider,
    // f.e. algorithm name
    suiteId: String,
    block: suspend context(TestRestorationContext) () -> Unit,
): TestResult = runTest(timeout = 10.minutes) {
    val scope = TestLimitationScope(TestEnvironment(provider))
    val runId = currentRunId(provider)
    val root = TestStorage(TestStorageClient.default(), emptyList())
    val report = TestReportBuilder()
    val restored = mutableListOf<String>()
    try {
        root.ids().filter { it != runId }.forEach { otherRunId ->
            val storage = root.child(otherRunId).child(suiteId)
            storage.ids().forEach { testId ->
                val path = "$otherRunId/$testId"
                val mark = report.mark()
                val context = TestRestorationContext(TestNode(storage.child(testId), path, scope, report))
                val _ = runNode(context.node) { context(context) { block() } }
                report.checkNotSkipped(path, mark)
                restored += path
            }
        }
    } finally {
        // the report is stored per run, to not mix it with generated ones
        root.child(runId).child("$suiteId.restore").save("report", report.build(), TestExecutionReport.serializer())
    }
    println(report.build().summary("$suiteId/restore (${restored.size} test(s))"))
}
