/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.server

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.routing.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.services.*

abstract class TesttoolServer : BuildService<TesttoolServer.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val instanceId: Property<String>
        val storage: DirectoryProperty
    }

    private val server: ApplicationEngine

    init {
        println("TesttoolServer: starting...")
        val instanceId = parameters.instanceId.get()
        val storagePath = parameters.storage.get().asFile.toPath()
        server = embeddedServer(Netty, port = 9000) {
            //TODO: redirect logback to file
            install(CallLogging) {
                disableDefaultColors()
            }
            install(CORS) { anyHost() }
            routing {
                compatibility(instanceId, storagePath.resolve("compatibility"))
            }
        }.start()
        println("TesttoolServer: started")
    }

    override fun close() {
        println("TesttoolServer: stopping...")
        server.stop()
        println("TesttoolServer: stopped")
    }
}
