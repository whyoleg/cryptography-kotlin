// Web Test Runner configuration for Kotlin/JS mocha tests via Playwright
import { playwrightLauncher } from '@web/test-runner-playwright';
import { defaultReporter } from '@web/test-runner';

// Headless by default; enable headful via HEADFUL=1
const headless = process.env.HEADFUL === '1' ? false : true;
// Default to Chrome for Testing (installed via installBrowsers) for consistent Ed25519/X25519 support.
const channel = 'chrome';
// Generous defaults; no need to tweak per run.
const testsFinishTimeout = 6000000; // 100 minutes (aligns with mocha timeout)
const testsStartTimeout = 120000;   // 2 minutes
const browserStartTimeout = 60000;  // 1 minute

const envFiles = process.env.WTR_FILES && process.env.WTR_FILES.trim();
const selectedFiles = envFiles ? envFiles.split(/\s+/) : [
  '**/build/compileSync/js/test/testDevelopmentExecutable/kotlin/*-test.mjs',
];

export default {
  testFramework: {
    // Mocha config to match kotlin-test-mocha expectations
    config: {
      ui: 'bdd',
      timeout: 6000000,
      ...(process.env.WTR_GREP ? { grep: process.env.WTR_GREP } : {}),
    },
  },

  browsers: [
    playwrightLauncher({
      product: 'chromium',
      launchOptions: { headless, devtools: process.env.WTR_DEVTOOLS === '1', channel },
    }),
  ],

  // Test files can be overridden via env (WTR_FILES)
  files: selectedFiles,

  // Helpful defaults for CI and debugging
  // Allow overriding via env for aggregated runs (has no effect if there's only one test file)
  concurrency: Number.isFinite(Number(process.env.WTR_CONCURRENCY))
    ? Number(process.env.WTR_CONCURRENCY)
    : 1,

  // Timeouts to avoid premature aborts for large Kotlin/JS bundles
  testsFinishTimeout,
  testsStartTimeout,
  browserStartTimeout,

  // Stream progress. Set WTR_LIVE=1 to print non-static lines continuously
  staticLogging: process.env.WTR_LIVE === '1' ? false : true,
  // Enable browser console logs via env to stream detailed progress
  browserLogs: process.env.WTR_BROWSER_LOGS === '1',
  reporters: [defaultReporter()],

  // Minimal HTML to inject grep-based skipping (no preflight logs)
  testRunnerHtml: (testRunnerImport) => {
    const tf = JSON.stringify(testRunnerImport);
    const grepCode = [
      // Fast mode toggle for tests (reduces iterations when true)
      "window.__CK_FAST__ = " + JSON.stringify(process.env.WTR_FAST === '1') + ";",
      "window.kotlinTest = window.kotlinTest || {};",
      "const grepPattern = " + JSON.stringify(process.env.WTR_GREP || "") + ";",
      "const grep = grepPattern ? new RegExp(grepPattern) : null;",
      "const suiteStack = [];",
      "window.kotlinTest.adapterTransformer = (adapter) => ({",
      "  suite: (name, ignored, fn) => {",
      "    suiteStack.push(String(name || ''));",
      "    try { adapter.suite(name, ignored, fn); } finally { suiteStack.pop(); }",
      "  },",
      "  test: (name, ignored, fn) => {",
      "    const title = String(name || '');",
      "    const full = (suiteStack.length ? suiteStack.join(' ') + ' ' : '') + title;",
      "    if (grep && !grep.test(full)) {",
      "      if (typeof window.xit === 'function') { window.xit(title, fn); return; }",
      "      return adapter.test(title, true, fn);",
      "    }",
      "    return adapter.test(name, ignored, fn);",
      "  },",
      "});",
    ].join("\n");
    return (
      '<!DOCTYPE html>' +
      '<html><head><meta charset="utf-8" /></head><body>' +
      '<script type="module">' +
      '  (async () => {' +
      '    try {' +
      grepCode +
      '    } catch (e) {} finally {' +
      '      await import(' + tf + ');' +
      '    }' +
      '  })();' +
      '</script>' +
      '</body></html>'
    );
  },
};
