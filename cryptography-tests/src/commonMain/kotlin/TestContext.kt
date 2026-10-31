/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.testhost.*
import kotlinx.coroutines.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlin.test.*

sealed class TestValidationContext {
    internal abstract val node: TestNode

    // f.e. `rfc8032/Ed25519/TestCase1/0/0`
    val path: String get() = node.path
}

class TestGenerationContext internal constructor(
    override val node: TestNode,
) : TestValidationContext() {
    private val usedIds = mutableSetOf<String>()
    private var nextId = 0

    fun generateChildId(): String {
        while (true) {
            val id = (nextId++).toString()
            if (id !in usedIds) return id
        }
    }

    internal fun reserveChildId(id: String) {
        check(usedIds.add(id)) { "Duplicate test id '$id' at '$path'" }
    }
}

class TestRestorationContext internal constructor(
    override val node: TestNode,
) : TestValidationContext()

// Executes provider operation `block`:
// * not limited -> must succeed
// * limited with `Fails` -> must fail, the limitation is recorded and the current test node is skipped
// * limited with `Skipped` -> not executed, the limitation is recorded and the current test node is skipped
// `limitation` is declared by the validator executing the operation
context(context: TestValidationContext)
suspend fun <O : TestOperation, T> operation(
    operation: O,
    limitation: TestOperationLimitation<O>? = null,
    block: suspend () -> T,
): T = when (val result = runOperation(operation, limitation, block)) {
    is OperationResult.Success -> result.value
    OperationResult.Limited    -> throw TestSkippedException("'$operation' is limited")
}

// Same as `operation` but returns `null` instead of skipping the current test node.
// Useful when the operation is optional for the rest of validation, f.e. decoding from a specific format.
context(context: TestValidationContext)
suspend fun <O : TestOperation, T : Any> operationOrNull(
    operation: O,
    limitation: TestOperationLimitation<O>? = null,
    block: suspend () -> T,
): T? = when (val result = runOperation(operation, limitation, block)) {
    is OperationResult.Success -> result.value
    OperationResult.Limited    -> null
}

// Skips the current test node, f.e. when there is nothing to validate because all inputs are limited
context(context: TestValidationContext)
fun skipNode(reason: String): Nothing = throw TestSkippedException("[${context.path}] $reason")

// Executes `block` which must fail by contract (f.e. invalid signature, tampered ciphertext, malformed key):
// * not limited -> must fail
// * limited with `Lenient` -> must succeed, the limitation is recorded
// * limited with `Fails` -> must fail, the limitation is recorded
// * limited with `Skipped` -> not executed, the limitation is recorded
// `block` should contain only provider calls: assertion errors inside it are treated as failures.
context(context: TestValidationContext)
suspend fun <O : TestOperation> expectFailure(
    operation: O,
    limitation: TestOperationLimitation<O>? = null,
    block: suspend () -> Unit,
) {
    val limitation = context.limitation(operation, limitation)
    if (limitation?.kind == TestLimitation.Kind.Skipped) return context.node.limited(operation, limitation)

    val result = runCatchingOperation(block)
    when (limitation?.kind) {
        TestLimitation.Kind.Lenient -> if (result.isFailure) context.failStale(operation, limitation, result.exceptionOrNull())
        TestLimitation.Kind.Fails,
        TestLimitation.Kind.Skipped,
        null,
                                    -> if (result.isSuccess) fail("[${context.path}] '$operation' was expected to fail, but succeeded")
    }
    if (limitation != null) context.node.limited(operation, limitation)
}

// Same as `expectFailure`, but for operations which report failure by returning `false` instead of throwing (f.e. `tryVerify`).
// `block` must not throw.
context(context: TestValidationContext)
suspend fun <O : TestOperation> expectFalse(
    operation: O,
    limitation: TestOperationLimitation<O>? = null,
    block: suspend () -> Boolean,
) {
    val limitation = context.limitation(operation, limitation)
    if (limitation?.kind == TestLimitation.Kind.Skipped) return context.node.limited(operation, limitation)

    val result = runCatchingOperation(block).getOrElse {
        throw AssertionError("[${context.path}] '$operation' must return `false` instead of throwing", it)
    }
    when (limitation?.kind) {
        TestLimitation.Kind.Lenient -> if (!result) context.failStale(operation, limitation, null)
        TestLimitation.Kind.Fails,
        TestLimitation.Kind.Skipped,
        null,
                                    -> if (result) fail("[${context.path}] '$operation' was expected to return `false`, but returned `true`")
    }
    if (limitation != null) context.node.limited(operation, limitation)
}

// impl

internal class TestSkippedException(message: String) : RuntimeException(message)

// generation of a node skipped explicitly, see `generateNode`
private data class GenerateTestNode(val id: String) : TestOperation

// attached as suppressed exception to failures to know where they happened
class TestNodeException(path: String) : Throwable(path)

internal sealed interface OperationResult<out T> {
    class Success<T>(val value: T) : OperationResult<T>
    object Limited : OperationResult<Nothing>
}

private fun <O : TestOperation> TestValidationContext.limitation(operation: O, limitation: TestOperationLimitation<O>?): TestLimitation? =
    limitation?.invoke(node.scope, operation)

context(context: TestValidationContext)
private suspend fun <O : TestOperation, T> runOperation(
    operation: O,
    limitation: TestOperationLimitation<O>?,
    block: suspend () -> T,
): OperationResult<T> {
    val limitation = context.limitation(operation, limitation)
    when (limitation?.kind) {
        TestLimitation.Kind.Fails   -> {
            val result = runCatchingOperation(block)
            if (result.isSuccess) context.failStale(operation, limitation, null)
            context.node.limited(operation, limitation)
            return OperationResult.Limited
        }
        TestLimitation.Kind.Skipped -> {
            context.node.limited(operation, limitation)
            return OperationResult.Limited
        }
        TestLimitation.Kind.Lenient -> error(
            "[${context.path}] '$operation' is limited with `Lenient` (${limitation.description}), " +
                    "which is applicable only for operations which must fail (`expectFailure`, `expectFalse`)"
        )
        null                        -> {
            val result = runCatchingOperation(block)
            return OperationResult.Success(result.getOrElse {
                throw AssertionError("[${context.path}] '$operation' failed", it)
            })
        }
    }
}

private fun TestValidationContext.failStale(operation: TestOperation, limitation: TestLimitation, cause: Throwable?): Nothing {
    throw AssertionError(
        "[$path] '$operation' is declared as limited (${limitation.kind}: ${limitation.description}), " +
                "but it behaves correctly; the limitation is stale and should be removed or moved to the operation which actually fails",
        cause
    )
}

private suspend fun <T> runCatchingOperation(block: suspend () -> T): Result<T> = try {
    Result.success(block())
} catch (cause: CancellationException) {
    throw cause
} catch (cause: TestSkippedException) {
    throw cause
} catch (cause: Throwable) {
    Result.failure(cause)
}

internal class TestNode(
    val storage: TestStorage,
    val path: String,
    val scope: TestLimitationScope,
    val report: TestReportBuilder,
) {
    fun child(id: String): TestNode = TestNode(storage.child(id), "$path/$id", scope, report)

    fun limited(operation: TestOperation, limitation: TestLimitation): Unit = report.limited(path, operation, limitation)
}

// returns `false` if the node was skipped
internal suspend fun runNode(node: TestNode, block: suspend () -> Unit): Boolean {
    try {
        block()
        return true
    } catch (cause: CancellationException) {
        throw cause
    } catch (_: TestSkippedException) {
        return false
    } catch (cause: Throwable) {
        if (cause.suppressedExceptions.none { it is TestNodeException }) {
            cause.addSuppressed(TestNodeException(node.path))
        }
        throw cause
    }
}

// generated nodes are validated first and stored only if validation succeeded (or was skipped because of limitations)
context(context: TestGenerationContext)
internal suspend fun <T> generateNode(
    id: String,
    value: T,
    serializer: KSerializer<T>,
    // `true` for data nodes, which are counted as validated
    isData: Boolean,
    // if not `null`, the node is neither validated nor stored, only the skip is recorded
    skip: String?,
    block: suspend context(TestGenerationContext) (T) -> Unit,
) {
    context.reserveChildId(id)
    val child = TestGenerationContext(context.node.child(id))
    if (skip != null) return child.node.limited(GenerateTestNode(id), TestLimitation(TestLimitation.Kind.Skipped, skip))
    val validated = runNode(child.node) { context(child) { block(value) } }
    if (validated && isData) child.node.report.validated++
    context.node.storage.save(id, value, serializer)
}

context(context: TestRestorationContext)
internal suspend fun <T> restoreNodes(
    serializer: KSerializer<T>,
    // `true` for data nodes, which are counted as validated
    isData: Boolean,
    block: suspend context(TestRestorationContext) (T) -> Unit,
) {
    context.node.storage.ids().forEach { id ->
        val value = context.node.storage.get(id, serializer)
        val child = TestRestorationContext(context.node.child(id))
        val validated = runNode(child.node) { context(child) { block(value) } }
        if (validated && isData) child.node.report.validated++
    }
}

// layout: `[path]/[id].json` contains the node value, `[path]/[id]/` contains children of the node
internal class TestStorage(
    private val client: TestStorageClient,
    private val path: List<String>,
) {
    fun child(id: String): TestStorage = TestStorage(client, path + id)

    suspend fun <T> save(id: String, value: T, serializer: KSerializer<T>) {
        client.save(filePath(id), json.encodeToString(serializer, value))
    }

    suspend fun <T> get(id: String, serializer: KSerializer<T>): T {
        return json.decodeFromString(serializer, client.get(filePath(id)))
    }

    suspend fun ids(): List<String> = client.list(path.toTypedArray()).mapNotNull {
        it.takeIf { it.endsWith(EXTENSION) }?.removeSuffix(EXTENSION)
    }.sorted()

    private fun filePath(id: String): TestStorageClient.Path = (path + "$id$EXTENSION").toTypedArray()

    private companion object {
        const val EXTENSION = ".json"
        val json = Json {
            prettyPrint = true
            encodeDefaults = false
        }
    }
}
