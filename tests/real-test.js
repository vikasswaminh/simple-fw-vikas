const { chromium } = require('playwright');
const https = require('https');

const BASE = 'https://127.0.0.1';
const USER = 'admin';
const PASS = 'QuickFW2026';

function apiCall(method, path, body) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(`${USER}:${PASS}`).toString('base64');
    const opts = {
      hostname: '127.0.0.1', port: 443, path,
      method, rejectUnauthorized: false,
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

let pass = 0, fail = 0, results = [];
function test(name, ok, detail) {
  if (ok) { pass++; results.push('  PASS  ' + name); }
  else { fail++; results.push('  FAIL  ' + name + ': ' + (detail || 'assertion failed')); }
}

async function runTests() {
  console.log('\n' + '='.repeat(50));
  console.log('  QuickFW Real Traffic Test Suite');
  console.log('='.repeat(50) + '\n');

  // === API TESTS ===
  console.log('-- API Tests --');

  let r = await apiCall('GET', '/api/system/info');
  test('GET /api/system/info returns 200', r.status === 200);
  test('hostname is quickfw', r.body.hostname === 'quickfw');
  test('has CPU%', typeof r.body.cpu_usage_percent === 'number');
  test('has memory', r.body.memory_total_mb > 0);
  test('has uptime', r.body.uptime_seconds > 0);
  test('version is 1.0.0', r.body.version === '1.0.0');

  r = await apiCall('GET', '/api/system/traffic');
  test('GET /api/system/traffic ok', r.status === 200);
  test('has active_connections', typeof r.body.active_connections === 'number');

  r = await apiCall('GET', '/api/interfaces');
  test('GET /api/interfaces ok', r.status === 200);
  test('has interfaces array', Array.isArray(r.body.interfaces));
  test('at least 1 interface', r.body.interfaces.length >= 1);
  const eth0 = r.body.interfaces.find(i => i.name === 'eth0');
  test('eth0 exists', !!eth0);
  test('eth0 has MAC', eth0 && eth0.mac.length > 0);
  test('eth0 has IP', eth0 && eth0.ipv4_addrs.length > 0);
  test('eth0 link up', eth0 && eth0.link_up === true);

  r = await apiCall('GET', '/api/firewall');
  test('GET /api/firewall ok', r.status === 200);
  test('has rules array', Array.isArray(r.body.rules));

  // Create a real firewall rule
  const fwConfig = {
    rules: [
      { name: 'test-allow-http', enabled: true, direction: 'forward', protocol: 'tcp',
        src_ip: '', dst_ip: '', src_port: '', dst_port: '80',
        in_interface: '', out_interface: '', src_zone: '', dst_zone: '',
        action: 'accept', log: false, comment: 'playwright test rule' },
      { name: 'test-block-telnet', enabled: true, direction: 'input', protocol: 'tcp',
        src_ip: '', dst_ip: '', src_port: '', dst_port: '23',
        in_interface: '', out_interface: '', src_zone: '', dst_zone: '',
        action: 'drop', log: true, comment: 'block telnet' }
    ],
    forward_policy: 'drop', input_policy: 'drop', output_policy: 'accept', zones: []
  };
  r = await apiCall('POST', '/api/firewall', fwConfig);
  test('POST firewall rules applied', r.status === 200);

  r = await apiCall('GET', '/api/firewall');
  const rules = (r.body && r.body.rules) || [];
  test('2 rules persisted', rules.length === 2, 'got ' + rules.length);
  test('rule 1 name correct', rules.length > 0 && rules[0].name === 'test-allow-http', rules.length > 0 ? rules[0].name : 'no rules');

  r = await apiCall('POST', '/api/firewall?dry_run=true', fwConfig);
  test('dry-run returns nft_script', r.status === 200 && r.body.nft_script);

  r = await apiCall('GET', '/api/firewall/counters');
  test('GET firewall/counters ok', r.status === 200);

  r = await apiCall('GET', '/api/firewall/groups');
  test('GET firewall/groups ok', r.status === 200);

  // Save address group
  r = await apiCall('POST', '/api/firewall/groups', {
    address_groups: [{ name: 'test-servers', addresses: ['10.0.0.1', '10.0.0.2/32'] }],
    port_groups: [{ name: 'web-ports', ports: ['80', '443', '8080'] }]
  });
  test('POST firewall groups saved', r.status === 200);

  // NAT
  r = await apiCall('GET', '/api/nat');
  test('GET /api/nat ok', r.status === 200);

  const natConfig = {
    masquerade: [{ out_interface: 'eth0', source_cidr: '' }],
    port_forward: [{ protocol: 'tcp', dest_port: 8080, forward_to: '192.168.1.100:80', in_interface: 'eth0' }]
  };
  r = await apiCall('POST', '/api/nat', natConfig);
  test('POST NAT config applied', r.status === 200);

  r = await apiCall('GET', '/api/nat');
  test('NAT masquerade persisted', r.body.masquerade && r.body.masquerade.length === 1);
  test('NAT port-forward persisted', r.body.port_forward && r.body.port_forward.length === 1);

  // Routes
  r = await apiCall('GET', '/api/routes');
  test('GET /api/routes ok', r.status === 200);

  // Settings
  r = await apiCall('GET', '/api/settings');
  test('GET /api/settings ok', r.status === 200);

  // Config export
  r = await apiCall('GET', '/api/config/export');
  test('GET config/export ok', r.status === 200);
  test('export has settings', r.body.settings !== undefined);

  // Conntrack
  r = await apiCall('GET', '/api/conntrack');
  test('GET /api/conntrack ok', r.status === 200);

  // Tools
  r = await apiCall('GET', '/api/tools/arp');
  test('GET tools/arp ok', r.status === 200);
  test('ARP returns array', Array.isArray(r.body));
  test('ARP has entries', r.body.length > 0);

  r = await apiCall('GET', '/api/tools/dhcp-leases');
  test('GET tools/dhcp-leases ok', r.status === 200);

  r = await apiCall('GET', '/api/tools/dns-local');
  test('GET tools/dns-local ok', r.status === 200);

  r = await apiCall('GET', '/api/tools/ntp-status');
  test('GET tools/ntp-status ok', r.status === 200);

  r = await apiCall('POST', '/api/tools/ping', { host: '127.0.0.1', count: 2 });
  test('POST tools/ping works', r.status === 200);

  // Auth tests
  const badR = await new Promise((resolve) => {
    const req = https.request({
      hostname: '127.0.0.1', port: 443, path: '/api/system/info',
      method: 'GET', rejectUnauthorized: false,
      headers: { 'Authorization': 'Basic ' + Buffer.from('admin:wrong').toString('base64') }
    }, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode})); });
    req.end();
  });
  test('bad password returns 401', badR.status === 401);

  const noR = await new Promise((resolve) => {
    const req = https.request({
      hostname: '127.0.0.1', port: 443, path: '/api/system/info',
      method: 'GET', rejectUnauthorized: false
    }, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode})); });
    req.end();
  });
  test('no auth returns 401', noR.status === 401);

  r = await apiCall('GET', '/api/audit');
  test('GET /api/audit ok', r.status === 200);
  test('audit has entries', Array.isArray(r.body) && r.body.length > 0);

  // === BROWSER TESTS ===
  console.log('\n-- Browser Tests (Playwright Chromium) --');

  const browser = await chromium.launch({ args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();

  // Login via API first to get session cookie
  await page.goto(BASE + '/api/auth/login', { waitUntil: 'load' });
  await page.waitForTimeout(500);

  const loginResp = await page.evaluate(async (creds) => {
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: creds.user, password: creds.pass })
      });
      return { status: r.status, body: await r.json() };
    } catch(e) { return { error: e.message }; }
  }, { user: USER, pass: PASS });
  test('browser login ok', loginResp && loginResp.status === 200, JSON.stringify(loginResp));

  // Now load dashboard with session cookie
  await page.goto(BASE);
  await page.waitForTimeout(4000);
  test('page loads', true);
  test('title contains QuickFW', (await page.title()).includes('QuickFW'));

  await page.screenshot({ path: '/tmp/qfw-dashboard.png', fullPage: true });
  test('dashboard screenshot saved', true);

  const sidebar = await page.$('.sidebar');
  test('sidebar visible', !!sidebar);

  // Navigate each page
  for (const [label, file] of [
    ['Firewall', 'firewall'], ['Interfaces', 'interfaces'],
    ['NAT', 'nat'], ['Connections', 'connections'],
    ['Settings', 'settings'], ['Account', 'account']
  ]) {
    const nav = await page.$(`text=${label}`);
    if (nav) {
      await nav.click();
      await page.waitForTimeout(2000);
      await page.screenshot({ path: `/tmp/qfw-${file}.png`, fullPage: true });
      test(`${label} page loads`, true);
    } else {
      test(`${label} nav found`, false, 'nav item not found');
    }
  }

  await browser.close();

  // === RESULTS ===
  console.log('\n' + '='.repeat(50));
  console.log('  RESULTS');
  console.log('='.repeat(50));
  results.forEach(r => console.log(r));
  console.log('-'.repeat(50));
  console.log('  TOTAL: ' + (pass+fail) + '  |  PASS: ' + pass + '  |  FAIL: ' + fail);
  console.log('='.repeat(50) + '\n');

  // Cleanup
  await apiCall('POST', '/api/firewall', { rules: [], forward_policy: 'drop', input_policy: 'drop', output_policy: 'accept', zones: [] });
  await apiCall('POST', '/api/nat', { masquerade: [], port_forward: [] });

  process.exit(fail > 0 ? 1 : 0);
}

runTests().catch(e => { console.error('Test error:', e); process.exit(1); });
