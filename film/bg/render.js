// Usage: node render.js --shot title --dur 5.8 --name bg-title [--fps 60] [--ss 2] [--port 8131]
//        node render.js --shot title --dur 5.8 --stills 0,2.9,5.7 --stilldir stills
// Renders at 3840x2160 (ss 2). Writes film/media/<name>-4k.mp4 (master, crf 12) and film/media/<name>.mp4 (1080p Lanczos).
const http = require('http'), fs = require('fs'), path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright');
const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const FILM = path.resolve(__dirname, '..');
const shot = args.shot, fps = +(args.fps || 60), dur = +(args.dur || 6), ss = +(args.ss || 2), port = +(args.port || 8131);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.png': 'image/png', '.json': 'application/json', '.mjs': 'text/javascript' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]); const f = path.join(FILM, path.normalize(u));
  if (!f.startsWith(FILM) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': types[path.extname(f)] || 'application/octet-stream' }); fs.createReadStream(f).pipe(res);
});
(async () => {
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  const browser = await chromium.launch({ args: process.env.GPU ? ['--use-angle=metal', '--ignore-gpu-blocklist', '--enable-gpu-rasterization'] : ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'] });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: ss });
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) console.error('[page]', m.text()); });
  page.on('pageerror', (e) => console.error('[pageerror]', e.message));
  await page.goto(`http://127.0.0.1:${port}/bg/index.html?ss=${ss}`);
  await page.waitForFunction(() => window.__ready === true, null, { timeout: 60000 });
  await page.evaluate(([s, d]) => window.setup(s, d), [shot, dur]);
  const clip = { x: 0, y: 0, width: 1920, height: 1080 };
  if (args.stills) {
    const dir = args.stilldir || 'stills'; fs.mkdirSync(dir, { recursive: true });
    for (const t of args.stills.split(',').map(Number)) {
      const t0 = Date.now(); await page.evaluate((tt) => window.renderAt(tt), t);
      const buf = await page.screenshot({ type: 'png', clip });
      const out = path.join(dir, `${shot}-${t.toFixed(2)}`);
      fs.writeFileSync(out + '-4k.png', buf);
      await new Promise((r, j) => { const p = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-i', '-', '-vf', 'scale=1920:1080:flags=lanczos', out + '.png']); p.stdin.end(buf); p.on('close', (c) => c ? j(new Error('ffmpeg')) : r()); });
      console.log(out, (Date.now() - t0) + 'ms');
    }
  } else {
    const n = Math.round(dur * fps), media = path.join(FILM, 'media');
    const x264 = ['-c:v', 'libx264', '-preset', 'slow', '-crf', '12', '-pix_fmt', 'yuv420p', '-r', String(fps), '-movflags', '+faststart'];
    const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(fps), '-i', '-', '-filter_complex',
      `[0:v]format=rgb24,split=2[a][b];[a]format=yuv420p[k];[b]scale=1920:1080:flags=lanczos+accurate_rnd+full_chroma_int,format=yuv420p[h]`,
      '-map', '[k]', ...x264, path.join(media, args.name + '-4k.mp4'), '-map', '[h]', ...x264, path.join(media, args.name + '.mp4')], { stdio: ['pipe', 'inherit', 'inherit'] });
    const done = new Promise((r, j) => ff.on('close', (c) => (c ? j(new Error('ffmpeg exit ' + c)) : r())));
    const t0 = Date.now();
    for (let i = 0; i < n; i++) {
      await page.evaluate((tt) => window.renderAt(tt), i / fps);
      const buf = await page.screenshot({ type: 'png', clip });
      if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r));
      if (i % 30 === 0) console.log(`${shot} ${i}/${n} ${((Date.now() - t0) / (i + 1)).toFixed(0)}ms/frame`);
    }
    ff.stdin.end(); await done; console.log('wrote', args.name, ((Date.now() - t0) / 1000).toFixed(1) + 's');
  }
  await browser.close(); server.close();
})().catch((e) => { console.error(e); process.exit(1); });
