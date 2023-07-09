/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import dev.whyoleg.cryptography.testtool.server.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.services.*

abstract class TesttoolServerService : BuildService<TesttoolServerService.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val instanceId: Property<String>
        val storage: DirectoryProperty
    }

    private val server = startTesttoolServer(
        instanceId = parameters.instanceId.get(),
        storagePath = parameters.storage.get().asFile.toPath()
    )

    override fun close(): Unit = server.close()
}
