/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import kotlinx.serialization.*

// Wycheproof-style expected result of the stored test data
@Serializable
enum class ExpectedResult {
    // must be accepted by all providers
    Valid,

    // must be rejected by all providers
    Invalid,

    // could be accepted or rejected (f.e. non-canonical encodings)
    Acceptable
}

// Validators form a tree: groups (parameters -> child validator) and data (leafs).
// Validators must be self-sufficient: all checks are done inside of them,
// as during restoration, only the stored values are available.
@TestDsl
sealed class TestInputValidator {
    context(context: TestRestorationContext)
    internal abstract suspend fun restore()
}

abstract class TestDataValidator<D>(
    private val serializer: KSerializer<D>,
) : TestInputValidator() {
    context(context: TestValidationContext)
    protected abstract suspend fun validate(data: D)

    // `skip` - see `group`
    context(context: TestGenerationContext)
    suspend fun generate(id: String, data: D, skip: String? = null): Unit =
        generateNode(id, data, serializer, isData = true, skip = skip) { validate(it) }

    context(context: TestRestorationContext)
    final override suspend fun restore(): Unit = restoreNodes(serializer, isData = true) { validate(it) }
}

// Parameters of a group node (f.e. curve, digest, key size):
// * `id` is used as the id of the node, if `null` it's generated
// * creation of the child validator is the operation, so limitations could be declared for parameters directly:
//   in this case, provider calls in `createValidator` (f.e. getting a cipher for a specific padding) must fail
// * limitations of operations inside the group are declared by validators and codecs executing them, see `TestOperationLimitation`
interface TestParameters : TestOperation {
    val id: String? get() = null
}

abstract class TestGroupValidator<P, V : TestInputValidator>(
    private val serializer: KSerializer<P>,
) : TestInputValidator() {
    context(context: TestValidationContext)
    protected abstract suspend fun createValidator(parameters: P): V

    // limitation of the group creation (`createValidator`), applicable only for `TestParameters`
    protected open fun parametersLimitation(scope: TestLimitationScope, parameters: P): TestLimitation? = null

    // `skip` - see `group`
    context(context: TestGenerationContext)
    suspend fun generate(
        id: String,
        parameters: P,
        skip: String? = null,
        block: suspend context(TestGenerationContext) V.() -> Unit,
    ): Unit = generateNode(id, parameters, serializer, isData = false, skip = skip) { checkedValidator(it).block() }

    context(context: TestRestorationContext)
    final override suspend fun restore(): Unit = restoreNodes(serializer, isData = false) { checkedValidator(it).restore() }

    context(context: TestValidationContext)
    private suspend fun checkedValidator(parameters: P): V {
        return when (parameters) {
            is TestParameters -> operation(parameters, { this@TestGroupValidator.parametersLimitation(this, parameters) }) {
                createValidator(parameters)
            }
            else              -> createValidator(parameters)
        }
    }
}

// Receiver of the validators DSL: describes the shape of the test data tree and checks of every node.
// Validators are created lazily (during generation or restoration of the node),
// so provider calls inside are executed as a part of the group creation.
@TestDsl
object TestValidatorScope

// [parameters] -> V, `limitation` is the limitation of the group creation (provider calls in `validator`)
inline fun <reified P : TestParameters, V : TestInputValidator> TestValidatorScope.group(
    noinline limitation: TestOperationLimitation<P>? = null,
    noinline validator: TestValidatorScope.(parameters: P) -> V,
): TestGroupValidator<P, V> = group(serializer<P>(), limitation, validator)

fun <P : TestParameters, V : TestInputValidator> TestValidatorScope.group(
    serializer: KSerializer<P>,
    limitation: TestOperationLimitation<P>?,
    validator: TestValidatorScope.(parameters: P) -> V,
): TestGroupValidator<P, V> = object : TestGroupValidator<P, V>(serializer) {
    context(context: TestValidationContext)
    override suspend fun createValidator(parameters: P): V = TestValidatorScope.validator(parameters)

    override fun parametersLimitation(scope: TestLimitationScope, parameters: P): TestLimitation? = limitation?.invoke(scope, parameters)
}

// `id` is taken from `TestParameters` or generated;
// `skip` - the reason why the group is neither generated nor stored (f.e. too slow), recorded as `Skipped` limitation:
// test data stays in code, so it could be run locally by removing `skip`
context(context: TestGenerationContext)
suspend fun <P, V : TestInputValidator> TestGroupValidator<P, V>.group(
    parameters: P,
    id: String = (parameters as? TestParameters)?.id ?: context.generateChildId(),
    skip: String? = null,
    block: suspend context(TestGenerationContext) V.() -> Unit,
): Unit = generate(id, parameters, skip, block)

context(context: TestGenerationContext)
suspend fun <V : TestInputValidator> TestGroupValidator<Unit, V>.group(
    id: String = context.generateChildId(),
    block: suspend context(TestGenerationContext) V.() -> Unit,
): Unit = group(Unit, id, block = block)
