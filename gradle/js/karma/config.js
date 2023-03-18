/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

config.client = config.client || {}
config.client.mocha = config.client.mocha || {}
config.client.mocha.timeout = '1800s'
config.browserNoActivityTimeout = 1800000
config.browserDisconnectTimeout = 1800000
