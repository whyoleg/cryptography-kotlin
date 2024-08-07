/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.plugin

import dev.whyoleg.cryptography.testtool.server.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.services.*
import java.util.*

abstract class TesttoolServerService : BuildService<TesttoolServerService.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val instanceId: Property<String>
        val storage: DirectoryProperty
    }

    // use random prefix to easy local dev
    private val server = startTesttoolServer(
        instanceId = "${parameters.instanceId.get()}-${UUID.randomUUID()}",
        storagePath = parameters.storage.get().asFile.toPath()
    )

    override fun close(): Unit = server.close()
}
