/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.teststorage

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.*
import io.ktor.server.engine.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import io.ktor.utils.io.jvm.javaio.*
import kotlin.io.path.*

// HTTP access to the test storage for platforms without file system access (android, js, wasm)
internal fun startServer(storage: TestStorage): AutoCloseable {
    fun resolve(path: String) = storage.resolve(path.split('/'))

    println("TestServer: starting...")
    val server = embeddedServer(CIO, 9000) {
        // for browser to work correctly
        install(CORS) { anyHost() }
        routing {
            post("save") {
                val path: String by call.parameters

                resolve(path).createParentDirectories().outputStream().use {
                    call.receiveChannel().copyTo(it)
                }

                call.response.status(HttpStatusCode.OK)
            }
            get("get") {
                val path: String by call.parameters

                call.respondPath(resolve(path))
            }
            get("list") {
                val path: String by call.parameters

                call.respondText(storage.list(path.split('/')).joinToString("\n"))
            }
        }
    }.start()
    println("TestServer: started")
    return AutoCloseable {
        println("TestServer: stopping...")
        server.stop()
        println("TestServer: stopped")
    }
}
