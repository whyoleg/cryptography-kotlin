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
import java.io.*
import java.nio.file.*

fun startTesttoolServer(
    instanceId: String,
    storagePath: Path,
): Closeable {
    println("TesttoolServer: starting...")
    val server = embeddedServer(Netty, 9000) {
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

    return Closeable {
        println("TesttoolServer: stopping...")
        server.stop()
        println("TesttoolServer: stopped")
    }
}
