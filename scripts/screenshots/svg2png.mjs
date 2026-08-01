// Rasterise a Rich-exported SVG to a crisp @2x PNG via headless system Chrome.
//   CHROME=<path> node svg2png.mjs <in.svg> <out.png>
// Requires puppeteer-core (see package.json) and a local Chrome/Chromium.
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const CANDIDATES = [
  process.env.CHROME,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);
const CHROME = CANDIDATES.find((p) => { try { return fs.existsSync(p); } catch { return false; } });
if (!CHROME) { console.error("No Chrome found — set CHROME=<path>"); process.exit(1); }

const [, , svgPath, pngPath] = process.argv;
if (!svgPath || !pngPath) { console.error("usage: node svg2png.mjs <in.svg> <out.png>"); process.exit(1); }

const svg = fs.readFileSync(svgPath, "utf8");
// Force a locally-available monospace so box-drawing (║╔═) stays aligned even
// when the Fira Code webfont the Rich SVG references cannot be fetched offline.
const html = `<!doctype html><html><head><meta charset="utf-8">
<style>
  html,body{margin:0;padding:0;background:transparent}
  svg text,svg tspan{font-family:'Menlo','SF Mono',ui-monospace,'DejaVu Sans Mono','Courier New',monospace !important}
</style></head><body>${svg}</body></html>`;

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "new",
  args: ["--no-sandbox", "--force-color-profile=srgb"],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1800, height: 1200, deviceScaleFactor: 2 });
  await page.setContent(html, { waitUntil: "networkidle0" });
  await page.evaluate(async () => { try { await document.fonts.ready; } catch (e) {} });
  const el = await page.$("svg");
  if (!el) throw new Error("no <svg> element found");
  await el.screenshot({ path: pngPath });
  const box = await el.boundingBox();
  console.log(`wrote ${pngPath}  (${Math.round(box.width)}x${Math.round(box.height)} @2x)`);
} finally {
  await browser.close();
}
