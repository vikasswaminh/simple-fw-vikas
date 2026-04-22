// QuickFW XSS regression test.
//
// Creates a firewall rule with an XSS payload as the rule name,
// navigates to the Firewall page, and asserts that:
//   - The page renders without the script executing (no window.__xss set)
//   - The payload appears in the DOM as escaped text (&lt;img..., not <img)
//
// Runs in headed Chromium via Xvfb, same harness as playwright-e2e.js.

const { chromium } = require('playwright');
const fs = require('fs');

const BASE = process.env.BASE_URL || 'https://127.0.0.1:8443';
const USER = process.env.QFW_USER || 'admin';
const PASS = process.env.QFW_PASS || 'Quickfw-Lab-2026!';
const ART  = process.env.ART_DIR  || '/tmp/playwright-xss';

const PAYLOAD_NAME = '<img src=x onerror="window.__xss=1">';

fs.mkdirSync(ART, { recursive: true });

(async () => {
  const browser = await chromium.launch({
    headless: false,
    args: ['--ignore-certificate-errors', '--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    httpCredentials: { username: USER, password: PASS },
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  const failures = [];

  // Bootstrap login
  await page.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 15000 });
  const login = await page.evaluate(async ({ user, pass }) => {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
      credentials: 'include',
    });
    return { status: r.status };
  }, { user: USER, pass: PASS });
  if (login.status !== 200) {
    console.error(`[xss] login FAILED: ${login.status}`);
    await browser.close();
    process.exit(2);
  }

  // Plant an XSS-payload rule via API
  const plant = await page.evaluate(async (payloadName) => {
    const r = await fetch('/api/firewall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        rules: [{
          name: payloadName,
          direction: 'forward',
          protocol: 'any',
          src_ip: '', src_port: '', dst_ip: '', dst_port: '',
          action: 'accept',
          enabled: true,
          log: false,
          ipv6: false,
        }],
        forward_policy: 'drop',
        input_policy: 'drop',
        output_policy: 'accept',
        zones: [],
      }),
    });
    return { status: r.status, body: await r.text() };
  }, PAYLOAD_NAME);

  // NB: the backend validator may reject the payload name — that's also a
  // valid defense. If it does, we skip the DOM-level test but don't fail.
  console.log(`[xss] plant rule: HTTP ${plant.status}`);
  const validatorRejected = plant.status === 400;

  // Navigate to Firewall page and observe
  await page.goto(BASE + '/firewall', { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(1500);

  const xssFlag = await page.evaluate(() => (window).__xss);
  if (xssFlag) {
    failures.push('window.__xss is set — payload executed!');
  }

  const bodyHtml = await page.content();
  if (bodyHtml.includes('<img src=x onerror=')) {
    failures.push('payload appears UNESCAPED in rendered HTML');
  }

  if (!validatorRejected) {
    // If the validator accepted the payload, the rule should render in the
    // table. Check the escaped form is visible.
    if (!bodyHtml.includes('&lt;img')) {
      failures.push('payload not found in DOM at all — test may not be exercising the code path');
    }
  }

  await page.screenshot({ path: `${ART}/xss-firewall.png`, fullPage: true });

  // Clean up: clear the firewall rule so we don't leave the planted one
  await page.evaluate(async () => {
    await fetch('/api/firewall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        rules: [],
        forward_policy: 'drop', input_policy: 'drop', output_policy: 'accept',
        zones: [],
      }),
    });
  });

  await browser.close();

  console.log(`\n========== XSS TEST ==========`);
  console.log(`Payload:   ${PAYLOAD_NAME}`);
  console.log(`Validator: ${validatorRejected ? 'rejected (defense-in-depth)' : 'accepted'}`);
  console.log(`XSS flag:  ${xssFlag ? 'SET (VULN)' : 'not set (OK)'}`);
  console.log(`Failures:  ${failures.length}`);
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(failures.length ? 1 : 0);
})();
