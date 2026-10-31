/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.teststorage

import com.android.build.gradle.internal.tasks.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.provider.Provider
import org.gradle.api.services.*
import org.gradle.build.event.*
import org.gradle.kotlin.dsl.*
import org.gradle.tooling.events.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import javax.inject.*

abstract class TestStoragePlugin : Plugin<Project> {
    @get:Inject
    abstract val buildEvents: BuildEventsListenerRegistry

    // see `FileSystemTestStorageClient` for the usage of it
    @Suppress("PrivatePropertyName")
    private val CK_FILESYSTEM_ROOT_PATH = "CK_FILESYSTEM_ROOT_PATH"

    override fun apply(target: Project): Unit = with(target) {
        val storageDirectory = testStorageDirectory()
        val storageProvider = testStorageService()
        // to keep generated test data if the build failed
        buildEvents.onTaskCompletion(storageProvider)
        val keepTestData = testStorageKeepTestData()

        fun Task.useTestStorage(startServer: Boolean) {
            doFirst {
                // call `get` to initialize the service to perform cleanup afterward
                val storage = storageProvider.get()
                if (startServer) storage.startServer()
            }
            usesService(storageProvider)
            // so that tests are rerun to keep the data, when it was deleted after the previous run
            inputs.property("ckbuild.teststorage.keep", keepTestData)
        }

        // android/js targets setup -> HTTP storage
        tasks.matching {
            when (it) {
                // we can't use `withType` because `AndroidTestTask` doesn't extends `Task`
                is AndroidTestTask -> true
                // overall, on nodejs we can use FS, but kotlinx-io is not compatible with ES modules yet
                // also handles wasm tests - TODO
                is KotlinJsTest    -> true
                else               -> false
            }
        }.configureEach {
            it.useTestStorage(startServer = true)
        }

        // native/jvm targets setup -> FS storage
        tasks.withType<KotlinNativeTest>().configureEach {
            it.useTestStorage(startServer = false)

            it.environment(CK_FILESYSTEM_ROOT_PATH, storageDirectory.get().asFile.absolutePath)
            // for apple simulators
            it.environment("SIMCTL_CHILD_$CK_FILESYSTEM_ROOT_PATH", storageDirectory.get().asFile.absolutePath)
        }
        tasks.withType<KotlinJvmTest>().configureEach {
            it.useTestStorage(startServer = false)

            it.environment(CK_FILESYSTEM_ROOT_PATH, storageDirectory.get().asFile.absolutePath)
        }
    }
}

// shared by all projects, so that tests and build logic use the same test storage
fun Project.testStorageService(): Provider<TestStorageService> = gradle.sharedServices.registerIfAbsent(
    "ckbuild-test-storage-service",
    TestStorageService::class.java
) {
    it.parameters {
        it.keepTestData.set(testStorageKeepTestData())
        it.storageDirectory.set(testStorageDirectory())
    }
}

private fun Project.testStorageKeepTestData(): Provider<Boolean> =
    providers.gradleProperty("ckbuild.teststorage.keep").map(String::toBoolean).orElse(false)

private fun Project.testStorageDirectory(): Provider<Directory> = rootProject.layout.buildDirectory.dir("test-storage")

// Test data generated during the build is deleted after the build if nothing failed, unless `ckbuild.teststorage.keep=true`:
// layout: `[run].json` - environment, `[run]/[suite]/[test].json` - reports, `[run]/[suite]/[test]/` - test data;
// environments and reports are kept, as they are small and used to update limitations, see `UpdateTestLimitationsTask`
abstract class TestStorageService : BuildService<TestStorageService.Parameters>, OperationCompletionListener, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val keepTestData: Property<Boolean>
        val storageDirectory: DirectoryProperty
    }

    val storage: TestStorage by lazy { TestStorage(parameters.storageDirectory.get().asFile.toPath()) }

    // runs created before the build, which are never deleted; the service is created before any test task is executed
    private val previousRuns = storage.list(emptyList()).toSet()

    @Volatile
    private var failed = false

    override fun onFinish(event: FinishEvent) {
        if (event.result is FailureResult) failed = true
    }

    private val server = lazy { startServer(storage) }

    fun startServer() {
        server.value // initialize server
    }

    override fun close() {
        if (server.isInitialized()) {
            server.value.close()
        }
        if (failed || parameters.keepTestData.get()) return
        storage.list(emptyList()).filter { it !in previousRuns }.forEach { runFile ->
            val runId = runFile.removeSuffix(".json")
            storage.directories(listOf(runId)).forEach { suiteId ->
                storage.directories(listOf(runId, suiteId)).forEach { testId ->
                    storage.delete(listOf(runId, suiteId, testId))
                }
            }
        }
    }
}
