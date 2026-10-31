/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import ckbuild.teststorage.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

// Aggregates limitations from test reports of providers into a committed snapshot, so that changes in limitations are visible in diffs.
// Only suites of environments present in the test storage are replaced, so it works with partial local runs
abstract class UpdateTestLimitationsTask : DefaultTask() {

    @get:Internal
    abstract val testStorage: Property<TestStorageService>

    @get:Internal
    abstract val limitationsFile: RegularFileProperty

    // all environments of the snapshot must be present in the test storage, f.e. on CI
    @get:Internal
    abstract val strict: Property<Boolean>

    @TaskAction
    fun update() {
        val file = limitationsFile.get().asFile
        val current = if (file.exists()) readTestLimitations(file).environments else emptyMap()
        val updated = testStorage.get().storage.readTestRuns().toTestLimitations().environments
        if (updated.isEmpty()) throw GradleException("No test reports found in the test storage")

        if (strict.get()) {
            val missing = current.keys - updated.keys
            if (missing.isNotEmpty()) throw GradleException("Environments are missing in the test storage: $missing")
            writeTestLimitations(file, TestLimitations(updated))
        } else {
            // removed or renamed suites are not dropped here, but they are dropped in strict mode on CI
            val merged = (current.keys + updated.keys).associateWith { current[it].orEmpty() + updated[it].orEmpty() }
            writeTestLimitations(file, TestLimitations(merged))
        }
        logger.lifecycle("Updated ${file.name} with environments: ${updated.keys.sorted()}")
    }
}
