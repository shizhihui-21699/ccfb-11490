import { chromium } from 'playwright';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';

const page_url = fileURLToPath(new URL('../dist/index.html', import.meta.url));
const shots = fileURLToPath(new URL('../.smoke-shots', import.meta.url));
mkdirSync(shots, { recursive: true });

const browser = await chromium.launch();
const errors = [];

async function newPage(viewport, colorScheme = 'light') {
  const context = await browser.newContext({ viewport, colorScheme, deviceScaleFactor: 2 });
  const page = await context.newPage();
  page.on('pageerror', (err) => errors.push(`pageerror: ${err.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`console: ${msg.text()}`);
  });
  await page.goto(`file://${page_url}`);
  await page.waitForTimeout(400);
  return page;
}

const desktop = await newPage({ width: 1440, height: 1000 });
await desktop.screenshot({ path: `${shots}/01-paths-light.png`, fullPage: true });

// Expand every "展开依据" on the default path to prove evidence renders.
const expandButtons = desktop.locator('button.ghost', { hasText: '展开依据' });
const n = await expandButtons.count();
for (let i = 0; i < n; i++) await expandButtons.nth(i).click();
await desktop.waitForTimeout(200);
await desktop.screenshot({ path: `${shots}/02-evidence.png`, fullPage: true });
console.log(`expanded ${n} evidence blocks`);

// Tabs
for (const [label, file] of [
  ['Secret 反查', '03-secrets'],
  ['提权图', '04-graph'],
  ['导入数据', '05-import'],
  ['手法清单', '06-techniques'],
]) {
  await desktop.locator('nav button', { hasText: label }).click();
  await desktop.waitForTimeout(250);
  await desktop.screenshot({ path: `${shots}/${file}.png`, fullPage: true });
}

// Dark mode + phone width on the main tab.
await desktop.locator('nav button', { hasText: '提权路径' }).click();
await desktop.selectOption('select[aria-label="主题"]', 'dark');
await desktop.waitForTimeout(250);
await desktop.screenshot({ path: `${shots}/07-dark.png`, fullPage: true });

const phone = await newPage({ width: 390, height: 844 });
await phone.screenshot({ path: `${shots}/08-phone.png`, fullPage: true });
const overflow = await phone.evaluate(() => ({
  scrollW: document.documentElement.scrollWidth,
  clientW: document.documentElement.clientWidth,
}));
console.log('phone overflow check', overflow);

// Text assertions
const bodyText = await desktop.locator('body').innerText();
const checks = [
  ['cluster-admin', bodyText.includes('cluster-admin')],
  ['ci/deployer mention', bodyText.includes('deployer')],
  ['technique catalog', bodyText.includes('创建 Pod')],
];
for (const [name, ok] of checks) console.log(ok ? `ok   ${name}` : `MISS ${name}`);

console.log(errors.length ? `ERRORS:\n${errors.join('\n')}` : 'no console/page errors');
await browser.close();
