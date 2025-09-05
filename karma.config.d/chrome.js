/*
 * Enable experimental WebCrypto features (EdDSA/XDH) in headless Chrome.
 */

config.customLaunchers = config.customLaunchers || {}
config.customLaunchers.ChromeHeadlessExperimental = {
  base: 'ChromeHeadless',
  flags: ['--enable-experimental-web-platform-features']
}

// Prefer our custom launcher for tests
config.browsers = ['ChromeHeadlessExperimental']

