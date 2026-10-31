/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.testhost.*
import kotlinx.serialization.*

// shared by all test DSLs (limitations, validators, data generation), so that receivers of outer DSL blocks are not accessible implicitly
@DslMarker
annotation class TestDsl

// operation which could be limited by a provider; `toString` is used for reporting, so should be readable
interface TestOperation

// declared up front for (provider, platform, operation), see `TestOperationLimitation`
class TestLimitation(
    val kind: Kind,
    // also shown in the provider support tables in docs, so should be user-facing and self-contained,
    // f.e. "X448 is not supported in browsers" instead of "X448 is not supported"
    val description: String,
) {
    enum class Kind {
        // operation is executed and must fail; success means the limitation is stale
        Fails,

        // operation must fail by contract (f.e. invalid input), but provider accepts it; failure means the limitation is stale
        Lenient,

        // operation is not executed at all, f.e. because it's too slow.
        // Should be used very rarely: unlike other limitations, skips are not verified, so prefer `Fails`
        Skipped,
    }
}

// receiver of all limitations: describes what the current provider on the current platform can't do
@TestDsl
class TestLimitationScope internal constructor(environment: TestEnvironment) {
    val provider: TestProvider = environment.provider
    val platform: TestPlatform = environment.platform

    fun fails(description: String): TestLimitation = TestLimitation(TestLimitation.Kind.Fails, description)
    fun lenient(description: String): TestLimitation = TestLimitation(TestLimitation.Kind.Lenient, description)
    fun skip(reason: String): TestLimitation = TestLimitation(TestLimitation.Kind.Skipped, reason)
}

// Limitation of operations of type `O`, declared by the validator (or codec) which executes them,
// f.e. `SignatureTestOperation` for signature validators or parameters for group validators.
// `null` means that the validator doesn't declare a limitation for the operation.
typealias TestOperationLimitation<O> = TestLimitationScope.(operation: O) -> TestLimitation?

// recorded results of a test: `[test-id].json`

@Serializable
class TestExecutionReport(
    // number of validated data nodes, not skipped because of limitations
    val validated: Int,
    // key: path of the test node
    val limitations: Map<String, List<TestExecutionLimitation>>,
)

@Serializable
data class TestExecutionLimitation(
    val operation: String,
    val kind: TestLimitation.Kind,
    val description: String,
)

internal class TestReportBuilder {
    var validated: Int = 0
    private val limitations = mutableMapOf<String, MutableList<TestExecutionLimitation>>()
    private var verified = 0
    private var skipped = 0

    fun limited(path: String, operation: TestOperation, limitation: TestLimitation) {
        when (limitation.kind) {
            TestLimitation.Kind.Skipped -> skipped++
            else                        -> verified++
        }
        limitations.getOrPut(path, ::mutableListOf).add(
            TestExecutionLimitation(operation.toString(), limitation.kind, limitation.description)
        )
    }

    // Guards against too broad skips: fails if the test was skipped as a whole,
    // i.e. nothing was validated or verified via limitations since `mark`,
    // unless the test was explicitly skipped at its root (`name`), f.e. the algorithm is skipped
    fun checkNotSkipped(name: String, mark: Mark) {
        if (validated > mark.validated || verified > mark.verified || skipped == mark.skipped) return
        if (limitations[name].orEmpty().any { it.kind == TestLimitation.Kind.Skipped }) return
        throw AssertionError("[$name] the test was skipped as a whole, nothing was validated; check skips:\n" + build().summary(name))
    }

    fun mark(): Mark = Mark(validated, verified, skipped)

    class Mark(val validated: Int, val verified: Int, val skipped: Int)

    fun build(): TestExecutionReport = TestExecutionReport(validated, limitations)
}

// f.e.:
// [ECDSA/random] validated 312 data node(s)
//   Fails   x24: secp256k1 is not supported
//   Skipped x2: DH parameter generation is very slow
internal fun TestExecutionReport.summary(name: String): String = buildString {
    append("[$name] validated $validated data node(s)")
    limitations.flatMap { (path, list) -> list.map { "${it.kind}" to it.description to path } }
        .groupBy({ it.first }, { it.second })
        .forEach { (kindAndDescription, paths) ->
            val (kind, description) = kindAndDescription
            append("\n  ${kind.padEnd(7)} x${paths.distinct().size}: $description")
        }
}
