// QuickFW E2E dashboard smoke test.
//
// Runs in headed Chromium via Xvfb, accepts self-signed cert, authenticates
// with Basic auth, walks every page, takes a screenshot, checks that each
// page renders without errors (no "Error loading...", no red alert text,
// and that key DOM elements are present).
//
// Artifacts written to /tmp/playwright-e2e/ :
//   dashboard.png, network.png, firewall.png, ... (one per page)
//   results.json                                   (pass/fail per page)
//   trace.zip                                      (Playwright trace)

const { chromium } = require('playwright');
const fs = require('fs');

const BASE = process.env.BASE_URL || 'https://127.0.0.1:8443';
const USER = process.env.QFW_USER || 'admin';
const PASS = process.env.QFW_PASS || 'Quickfw-Lab-2026!';
const ART  = process.env.ART_DIR  || '/tmp/playwright-e2e';

fs.mkdirSync(ART, { recursive: true });

const pages = [
  { slug: 'dashboard', path: '/',          mustContain: ['Dashboard', 'System Info', 'Traffic', 'Services', 'Gateway', 'Quick Actions'] },
  { slug: 'network',   path: '/network',   mustContain: ['Network', 'Interfaces'] },
  { slug: 'firewall',  path: '/firewall',  mustContain: ['Firewall Rules', 'Add Rule'] },
  { slug: 'nat',       path: '/nat',       mustContain: ['NAT', 'Masquerade'] },
  { slug: 'routing',   path: '/routing',   mustContain: ['Routing', 'OSPF', 'BGP'] },
  { slug: 'tools',     path: '/tools',     mustContain: ['Tools', 'Ping', 'Traceroute'] },
  { slug: 'audit',     path: '/audit',     mustContain: ['Audit Log'] },
  { slug: 'settings',  path: '/settings',  mustContain: ['Settings', 'General'] },
];

(async () => {
  const results = [];
  const browser = await chromium.launch({
    headless: false,
    args: ['--ignore-certificate-errors', '--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    // Keep Basic auth as fallback for things like /api/health probes the SPA
    // skips. The main auth is via session cookie (see bootstrap below).
    httpCredentials: { username: USER, password: PASS },
    viewport: { width: 1440, height: 900 },
    recordVideo: { dir: ART },
  });
  await context.tracing.start({ screenshots: true, snapshots: true });
  const page = await context.newPage();

  // Bootstrap: load / first (so the BrowserContext has an origin), then
  // log in from inside the page's fetch so the session cookie lands in the
  // browser's cookie jar (not just the APIRequestContext's).
  console.log('[e2e] bootstrap: page.goto / then fetch login');
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 15000 });

  const loginResult = await page.evaluate(async ({ user, pass }) => {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
      credentials: 'include',
    });
    const body = await r.text();
    return { status: r.status, body };
  }, { user: USER, pass: PASS });

  if (loginResult.status !== 200) {
    console.error(`[e2e] login FAILED (HTTP ${loginResult.status}): ${loginResult.body}`);
    await browser.close();
    process.exit(2);
  }
  console.log(`[e2e] login OK (HTTP ${loginResult.status})`);

  // Verify cookie is in the context
  const cookies = await context.cookies();
  const session = cookies.find(c => c.name === 'quickfw_session');
  console.log(`[e2e] session cookie present: ${!!session}`);

  // Capture console errors per page
  const consoleErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', err => consoleErrors.push(`pageerror: ${err.message}`));

  for (const p of pages) {
    const url = BASE + p.path;
    const errorsBefore = consoleErrors.length;
    console.log(`[e2e] ${p.slug}: GET ${url}`);

    let ok = true;
    const issues = [];

    try {
      const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
      if (!resp || !resp.ok()) {
        ok = false;
        issues.push(`HTTP ${resp ? resp.status() : 'no-response'}`);
      }

      // Wait for the SPA to actually render the page
      await page.waitForTimeout(1500);

      const bodyText = await page.locator('body').innerText();

      for (const needle of p.mustContain) {
        if (!bodyText.includes(needle)) {
          ok = false;
          issues.push(`missing text: "${needle}"`);
        }
      }
      if (bodyText.includes('Error loading')) {
        ok = false;
        issues.push('page shows "Error loading" placeholder');
      }
      if (bodyText.match(/Failed to load/i)) {
        ok = false;
        issues.push('page shows "Failed to load" text');
      }

      await page.screenshot({ path: `${ART}/${p.slug}.png`, fullPage: true });
    } catch (e) {
      ok = false;
      issues.push(`exception: ${e.message}`);
    }

    const newErrors = consoleErrors.slice(errorsBefore);
    if (newErrors.length) issues.push(`console errors: ${newErrors.length}`);

    results.push({ page: p.slug, url: p.path, ok, issues, newConsoleErrors: newErrors });
    console.log(`  -> ${ok ? 'OK' : 'FAIL'}${issues.length ? ' | ' + issues.join(' | ') : ''}`);
  }

  // Modal smoke: try Add Rule on firewall page
  try {
    await page.goto(BASE + '/firewall', { waitUntil: 'networkidle', timeout: 10000 });
    await page.waitForTimeout(800);
    await page.click('#add-rule-btn', { timeout: 5000 });
    await page.waitForSelector('.modal', { timeout: 5000 });
    await page.screenshot({ path: `${ART}/firewall-add-rule-modal.png`, fullPage: true });
    results.push({ page: 'firewall-modal', ok: true, issues: [] });
    console.log('[e2e] firewall-modal: OK');
  } catch (e) {
    results.push({ page: 'firewall-modal', ok: false, issues: [`exception: ${e.message}`] });
    console.log(`[e2e] firewall-modal: FAIL (${e.message})`);
  }

  await context.tracing.stop({ path: `${ART}/trace.zip` });
  fs.writeFileSync(`${ART}/results.json`, JSON.stringify(results, null, 2));
  await context.close();
  await browser.close();

  const failed = results.filter(r => !r.ok);
  console.log(`\n========== RESULTS ==========`);
  console.log(`Total:  ${results.length}`);
  console.log(`Passed: ${results.length - failed.length}`);
  console.log(`Failed: ${failed.length}`);
  if (failed.length) {
    console.log(`\nFailures:`);
    for (const f of failed) console.log(`  - ${f.page}: ${f.issues.join(' | ')}`);
  }
  console.log(`\nArtifacts in ${ART}`);
  process.exit(failed.length ? 1 : 0);
})();
