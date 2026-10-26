// Usage: node render3d2.js --shot overview --dur 6.11 [--fps 60] [--ss 2] [--port 8300] [--stills 0,3 --stilldir d] [--only1080 1]
// Writes ../media/shot-<shot>.mp4 (1920x1080) and ../media/shot-<shot>-4k.mp4 (3840x2160), 60 fps, no grain.
const http = require('http'), fs = require('fs'), path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright');

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const FILM = path.resolve(__dirname, '..');
const shot = args.shot, fps = +(args.fps || 60), dur = +args.dur, ss = +(args.ss || 2), port = +(args.port || 8300);
const start = +(args.start || 0), end = args.end ? +args.end : null;   // frame range (for resumable partial renders)

function pick(name) {
  const found = [];
  for (const dir of ['media', 'shots']) for (const ext of ['png', 'jpg', 'jpeg', 'webp']) {
    const f = path.join(FILM, dir, `${name}.${ext}`);
    if (fs.existsSync(f)) found.push({ url: `/${dir}/${name}.${ext}`, mtime: fs.statSync(f).mtimeMs });
  }
  if (!found.length) throw new Error('missing screenshot ' + name);
  found.sort((a, b) => b.mtime - a.mtime);
  return found[0].url;
}
const media = {};
for (const k of ['overview', 'devices', 'device-drawer', 'habits', 'alerts', 'bedtime', 'privacy-report', 'report-card', 'phone']) media[k] = pick(k);

const types = { '.html': 'text/html', '.js': 'text/javascript', '.png': 'image/png', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  const f = path.join(FILM, path.normalize(u));
  if (!f.startsWith(FILM) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': types[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
});

function encoder(out, scale, preset) {
  const vf = (scale ? 'scale=1920:1080:flags=lanczos+accurate_rnd+full_chroma_int,' : '') + 'format=yuv420p';
  const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(fps), '-i', '-', '-vf', vf,
    '-c:v', 'libx264', '-preset', preset, '-crf', '12', '-profile:v', 'high', '-pix_fmt', 'yuv420p', '-colorspace', 'bt709', '-color_primaries', 'bt709', '-color_trc', 'bt709',
    '-movflags', '+faststart', '-r', String(fps), out], { stdio: ['pipe', 'inherit', 'inherit'] });
  const done = new Promise((r, j) => ff.on('close', (c) => (c ? j(new Error('ffmpeg exit ' + c)) : r())));
  return { ff, done };
}

(async () => {
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  const browser = await chromium.launch({ args: process.env.GPU ? ['--use-angle=metal', '--ignore-gpu-blocklist', '--enable-gpu-rasterization'] : ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: ss });
  page.on('console', (m) => { if (m.type() === 'error' || (m.type() === 'warning' && !/GPU stall/.test(m.text()))) console.error('[page]', m.text()); });
  page.on('pageerror', (e) => console.error('[pageerror]', e.message));
  await page.goto(`http://127.0.0.1:${port}/3d/index2.html?ss=${ss}&refl=1`);
  await page.waitForFunction(() => window.__ready === true, null, { timeout: 60000 });
  await page.evaluate(([s, m, d]) => window.setup(s, m, d), [shot, media, dur]);
  const clip = { x: 0, y: 0, width: 1920, height: 1080 };

  if (args.stills) {
    const dir = args.stilldir || '.'; fs.mkdirSync(dir, { recursive: true });
    for (const t of args.stills.split(',').map(Number)) {
      await page.evaluate((tt) => window.renderAt(tt), t);
      const buf = await page.screenshot({ type: 'png', clip });
      fs.writeFileSync(path.join(dir, `${shot}-${t.toFixed(2)}.png`), buf);   // full 2x (3840x2160) resolution
      console.log(path.join(dir, `${shot}-${t.toFixed(2)}.png`));
    }
  } else {
    const n = Math.round(dur * fps), last = end ?? n;
    const o1080 = path.resolve(FILM, 'media', `shot-${shot}.mp4`), o4k = path.resolve(FILM, 'media', `shot-${shot}-4k.mp4`);
    const e1 = encoder(o1080 + '.part.mp4', true, 'slow');
    const e2 = ss >= 2 && !args.only1080 ? encoder(o4k + '.part.mp4', false, 'medium') : null;
    const t0 = Date.now();
    for (let i = start; i < last; i++) {
      await page.evaluate((tt) => window.renderAt(tt), i / fps);
      const buf = await page.screenshot({ type: 'jpeg', quality: 100, clip });
      for (const e of [e1, e2]) if (e && !e.ff.stdin.write(buf)) await new Promise((r) => e.ff.stdin.once('drain', r));
      if (i % 30 === 0) console.log(`${shot} frame ${i}/${n} ${((Date.now() - t0) / (i - start + 1)).toFixed(0)}ms/frame`);
    }
    e1.ff.stdin.end(); if (e2) e2.ff.stdin.end();
    await Promise.all([e1.done, e2 && e2.done]);
    fs.renameSync(o1080 + '.part.mp4', o1080);
    if (e2) fs.renameSync(o4k + '.part.mp4', o4k);
    console.log('wrote', o1080, ((Date.now() - t0) / 1000).toFixed(1) + 's');
  }
  await browser.close(); server.close();
})().catch((e) => { console.error(e); process.exit(1); });
