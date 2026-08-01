// Capture the HEAVEN web-UI screenshots for the README against an isolated,
// demo-seeded backend (started by regenerate.sh). Login uses the native value
// setter because the inputs are React-controlled; navigation is client-side
// because the JWT lives in memory (a full page.goto would log the session out).
//   BASE=http://127.0.0.1:8443 PASS=<admin-pass> OUT=docs/screenshots \
//   CHROME=<path> node capture_web.mjs
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const CANDIDATES = [
  process.env.CHROME,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
].filter(Boolean);
const CHROME = CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch { return false; } });
if (!CHROME) { console.error("No Chrome found — set CHROME=<path>"); process.exit(1); }

const BASE = process.env.BASE || "http://127.0.0.1:8443";
const PASS = process.env.PASS || "";
const OUT = process.env.OUT || "docs/screenshots";
const USER = process.env.USER_ID || "admin";

const PAGES = [
  { route: "/",           file: "web-app_dashboard.png", settle: 4200 }, // 3D topology needs WebGL warm-up
  { route: "/findings",   file: "findings_dashboard.png", settle: 2200 },
  { route: "/kill-chain", file: "kill_chain_dashboard.png", settle: 2600 },
  { route: "/scans",      file: "scanning_dashboard.png", settle: 2200 },
  { route: "/reports",    file: "reports_dashboard.png", settle: 2200 },
];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--ignore-gpu-blocklist", "--enable-webgl", "--enable-unsafe-swiftshader",
         "--use-gl=angle", "--use-angle=swiftshader", "--no-sandbox",
         "--force-color-profile=srgb", "--hide-scrollbars"],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 900, deviceScaleFactor: 2 });
  // Suppress the first-run tour / welcome overlays before any app script runs.
  await page.evaluateOnNewDocument(() => {
    try {
      localStorage.setItem("heaven.tour.v1", "1");
      localStorage.setItem("heaven.firstrun.dismissed", "1");
    } catch (e) {}
  });

  await page.goto(`${BASE}/login`, { waitUntil: "networkidle0" });
  await page.waitForSelector("#login-pass", { timeout: 15000 });

  const setNative = (sel, val) => page.evaluate((sel, val) => {
    const el = document.querySelector(sel);
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el), "value").set;
    setter.call(el, val);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }, sel, val);
  await setNative("#login-user", USER);
  await setNative("#login-pass", PASS);
  const plen = await page.$eval("#login-pass", (el) => el.value.length);
  console.error(`password field length before submit: ${plen}`);
  await page.evaluate(() => document.querySelector("form.login-card").requestSubmit());

  await page.waitForSelector('a[href="/findings"]', { timeout: 20000 });
  console.error("logged in — app shell present");
  await sleep(1500);

  for (const p of PAGES) {
    await page.evaluate((route) => {
      const a = document.querySelector(`a[href="${route}"]`);
      if (a) a.click();
    }, p.route);
    await sleep(p.settle);
    try { await page.evaluate(async () => { await document.fonts.ready; }); } catch (e) {}
    await page.screenshot({ path: `${OUT}/${p.file}`, fullPage: false });
    const cur = await page.evaluate(() => location.pathname);
    console.error(`captured ${p.file}  (path=${cur})`);
  }
} finally {
  await browser.close();
}
