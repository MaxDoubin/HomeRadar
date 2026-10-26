// Animated 3D backgrounds for the Home Radar film's type-on-black beats. Background only, no text.
// window.setup(shot) builds a scene; window.renderAt(t) draws one deterministic frame.
import * as THREE from 'three';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { LineSegments2 } from 'three/addons/lines/LineSegments2.js';
import { LineSegmentsGeometry } from 'three/addons/lines/LineSegmentsGeometry.js';
import { LineMaterial } from 'three/addons/lines/LineMaterial.js';

const W = 1920, H = 1080;
const P = new URLSearchParams(location.search);
const SS = parseFloat(P.get('ss') || '1');
const renderer = new THREE.WebGLRenderer({ antialias: true, preserveDrawingBuffer: true, powerPreference: 'high-performance' });
renderer.setPixelRatio(SS); renderer.setSize(W, H, false);
renderer.domElement.style.width = W + 'px'; renderer.domElement.style.height = H + 'px';
renderer.outputColorSpace = THREE.SRGBColorSpace; renderer.toneMapping = THREE.NoToneMapping;
renderer.setClearColor(0x0a0a0b, 1);
document.body.appendChild(renderer.domElement);

const ACC = '#3dd68c', ACCV = new THREE.Vector3(0.239, 0.839, 0.549);
const clamp01 = (x) => Math.min(1, Math.max(0, x));
const lerp = (a, b, k) => a + (b - a) * k;
const seg = (t, a, b) => clamp01((t - a) / (b - a));
const smooth = (x) => x * x * (3 - 2 * x);
const easeOut = (x) => 1 - Math.pow(1 - x, 3);
const easeInOut = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
const easeOutBack = (x) => { const c1 = 1.2, c3 = c1 + 1; return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2); };
function rng(seed) { let a = seed >>> 0; return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

// ---------- text-safe scrim + head/tail fade (one full-screen quad, drawn last) ----------
function makeOverlay(scrimStrength) {
  const m = new THREE.ShaderMaterial({
    transparent: true, depthTest: false, depthWrite: false,
    uniforms: { uFade: { value: 0 }, uScrim: { value: scrimStrength } },
    vertexShader: 'varying vec2 vUv; void main(){ vUv=uv; gl_Position=vec4(position.xy,0.,1.); }',
    fragmentShader: `varying vec2 vUv; uniform float uFade; uniform float uScrim;
      float rbox(vec2 p, vec2 b){ vec2 q=abs(p)-b; return length(max(q,0.))+min(max(q.x,q.y),0.); }
      void main(){
        vec2 px = vec2(vUv.x*1920., (1.-vUv.y)*1080.);
        float d = rbox(px-vec2(960.,590.), vec2(700.,150.));
        float mask = 1.-smoothstep(0., 230., d);
        float a = max(uFade, uScrim*mask);
        gl_FragColor = vec4(vec3(10./255.,10./255.,11./255.), a);
      }`,
  });
  const mesh = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), m);
  mesh.frustumCulled = false; mesh.renderOrder = 999;
  return mesh;
}

// ---------- device icon sprites (thin-line glass orbs) with pre-blurred depth levels ----------
const BLUR_PX = [0, 2.5, 6, 11];
function rr(ctx, x, y, w, h, r) { ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }
function glyph(ctx, type, s, col) {
  const c = s / 2; ctx.strokeStyle = col; ctx.fillStyle = col; ctx.lineWidth = s * 0.026; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
  const L = (x1, y1, x2, y2) => { ctx.beginPath(); ctx.moveTo(c + x1 * s, c + y1 * s); ctx.lineTo(c + x2 * s, c + y2 * s); ctx.stroke(); };
  const C = (x, y, r) => { ctx.beginPath(); ctx.arc(c + x * s, c + y * s, r * s, 0, Math.PI * 2); ctx.stroke(); };
  if (type === 'phone') { rr(ctx, c - 0.095 * s, c - 0.17 * s, 0.19 * s, 0.34 * s, 0.03 * s); ctx.stroke(); L(-0.03, 0.125, 0.03, 0.125); }
  else if (type === 'tv') { rr(ctx, c - 0.2 * s, c - 0.135 * s, 0.4 * s, 0.25 * s, 0.025 * s); ctx.stroke(); L(-0.07, 0.175, 0.07, 0.175); L(0, 0.115, 0, 0.175); }
  else if (type === 'camera') { C(0, -0.01, 0.13); C(0, -0.01, 0.045); L(-0.08, 0.17, 0.08, 0.17); L(0, 0.12, 0, 0.17); }
  else if (type === 'speaker') { rr(ctx, c - 0.1 * s, c - 0.17 * s, 0.2 * s, 0.34 * s, 0.04 * s); ctx.stroke(); C(0, 0.07, 0.05); C(0, -0.075, 0.024); }
  else if (type === 'laptop') { rr(ctx, c - 0.17 * s, c - 0.13 * s, 0.34 * s, 0.22 * s, 0.02 * s); ctx.stroke(); L(-0.23, 0.14, 0.23, 0.14); }
  else if (type === 'console') { rr(ctx, c - 0.2 * s, c - 0.075 * s, 0.4 * s, 0.16 * s, 0.075 * s); ctx.stroke(); L(-0.13, 0, -0.07, 0); L(-0.1, -0.03, -0.1, 0.03); C(0.1, 0.01, 0.012); C(0.14, -0.015, 0.012); }
  else if (type === 'printer') { rr(ctx, c - 0.17 * s, c - 0.02 * s, 0.34 * s, 0.16 * s, 0.025 * s); ctx.stroke(); rr(ctx, c - 0.1 * s, c - 0.14 * s, 0.2 * s, 0.12 * s, 0.01 * s); ctx.stroke(); L(-0.08, 0.075, 0.08, 0.075); }
  else { ctx.font = `700 ${s * 0.3}px Inter, sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText('?', c, c + s * 0.015); }
}
const iconCache = {};
function iconTex(type, level) {
  const key = type + level; if (iconCache[key]) return iconCache[key];
  const s = 256, cv = document.createElement('canvas'); cv.width = cv.height = s; const ctx = cv.getContext('2d');
  ctx.filter = BLUR_PX[level] ? `blur(${BLUR_PX[level]}px)` : 'none';
  const unk = type === 'unknown', col = unk ? ACC : 'rgb(235,238,242)';
  const g = ctx.createRadialGradient(s * 0.42, s * 0.38, s * 0.04, s / 2, s / 2, s * 0.42);
  g.addColorStop(0, unk ? 'rgba(61,214,140,0.16)' : 'rgba(255,255,255,0.10)'); g.addColorStop(1, 'rgba(255,255,255,0.015)');
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(s / 2, s / 2, s * 0.4, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = unk ? 'rgba(61,214,140,0.85)' : 'rgba(235,238,242,0.55)'; ctx.lineWidth = s * 0.012; ctx.beginPath(); ctx.arc(s / 2, s / 2, s * 0.4, 0, Math.PI * 2); ctx.stroke();
  ctx.strokeStyle = 'rgba(255,255,255,0.22)'; ctx.lineWidth = s * 0.012; ctx.beginPath(); ctx.arc(s / 2, s / 2, s * 0.36, Math.PI * 1.08, Math.PI * 1.42); ctx.stroke();
  ctx.globalAlpha = unk ? 1 : 0.86; glyph(ctx, type, s, col); ctx.globalAlpha = 1;
  const tex = new THREE.CanvasTexture(cv); tex.colorSpace = THREE.SRGBColorSpace; tex.anisotropy = 4; tex.generateMipmaps = true;
  return (iconCache[key] = tex);
}
const glowTex = (() => { const s = 256, cv = document.createElement('canvas'); cv.width = cv.height = s; const x = cv.getContext('2d'); const g = x.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2); g.addColorStop(0, 'rgba(255,255,255,1)'); g.addColorStop(0.25, 'rgba(255,255,255,0.35)'); g.addColorStop(1, 'rgba(255,255,255,0)'); x.fillStyle = g; x.fillRect(0, 0, s, s); const t = new THREE.CanvasTexture(cv); t.colorSpace = THREE.SRGBColorSpace; return t; })();
const ringTex = (() => { const s = 256, cv = document.createElement('canvas'); cv.width = cv.height = s; const x = cv.getContext('2d'); x.strokeStyle = 'rgba(255,255,255,0.9)'; x.lineWidth = 3; x.beginPath(); x.arc(s / 2, s / 2, s * 0.46, 0, Math.PI * 2); x.stroke(); const t = new THREE.CanvasTexture(cv); t.colorSpace = THREE.SRGBColorSpace; return t; })();

// ---------- device constellation (shared by "question" and "close") ----------
function makeConstellation(scene, { hub }) {
  const TYPES = ['phone', 'tv', 'camera', 'speaker', 'laptop', 'console', 'printer', 'unknown', 'phone', 'camera', 'tv', 'laptop', 'speaker', 'console', 'unknown', 'printer'];
  const R = rng(7), group = new THREE.Group(); scene.add(group);
  const nodes = TYPES.map((type, i) => {
    const th = i * 2.399963 + (R() - 0.5) * 0.5, rad = 4.5 + R() * 5.0, y = (R() - 0.5) * 5.0;
    const pos = new THREE.Vector3(Math.cos(th) * rad, y, Math.sin(th) * rad);
    const mk = (lv) => { const m = new THREE.SpriteMaterial({ map: iconTex(type, lv), transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, opacity: 0 }); const s = new THREE.Sprite(m); s.position.copy(pos); group.add(s); return s; };
    const a = mk(0), b = mk(1);
    const ringM = new THREE.SpriteMaterial({ map: ringTex, transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, opacity: 0, color: type === 'unknown' ? 0x3dd68c : 0xe8ecf0 });
    const ring = new THREE.Sprite(ringM); ring.position.copy(pos); group.add(ring);
    return { type, pos, a, b, ring, appear: 0.55 + i * 0.27 + R() * 0.12, pulse: R() < 0.4 || type === 'unknown', ph: R() * 6.28 };
  });
  // links: each node to its two nearest neighbours (unique pairs)
  const pairs = new Set(), links = [];
  nodes.forEach((n, i) => { nodes.map((m, j) => ({ j, d: n.pos.distanceTo(m.pos) })).filter((o) => o.j !== i).sort((p, q) => p.d - q.d).slice(0, 2).forEach((o) => { const k = Math.min(i, o.j) + '-' + Math.max(i, o.j); if (!pairs.has(k)) { pairs.add(k); links.push([i, o.j]); } }); });
  const lineSegs = [];
  links.forEach(([i, j]) => lineSegs.push({ a: i, b: j, hub: false }));
  if (hub) nodes.forEach((n, i) => lineSegs.push({ a: i, b: -1, hub: true }));
  const nSeg = lineSegs.length;
  const geo = new LineSegmentsGeometry(); geo.setPositions(new Float32Array(nSeg * 6)); geo.setColors(new Float32Array(nSeg * 6));
  const lmat = new LineMaterial({ color: 0xffffff, linewidth: 1.3 * SS, vertexColors: true, transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, worldUnits: false });
  lmat.resolution.set(W * SS, H * SS);
  const lines = new LineSegments2(geo, lmat); lines.frustumCulled = false; group.add(lines);
  const posA = geo.attributes.instanceStart.data.array, colA = geo.attributes.instanceColorStart.data.array;
  let hubGlow = null, hubRing = null;
  if (hub) {
    hubGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, color: 0x3dd68c, opacity: 0 }));
    hubGlow.scale.setScalar(7.5); group.add(hubGlow);
    hubRing = new THREE.Sprite(new THREE.SpriteMaterial({ map: ringTex, transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, color: 0x3dd68c, opacity: 0 })); group.add(hubRing);
  }
  const tmp = new THREE.Vector3();
  return {
    group,
    update(t, camPos, opts) {
      const { linkDelay = 0.2, calm = false, hubStart = 0.4 } = opts || {};
      nodes.forEach((n) => {
        const k = easeOutBack(seg(t, n.appear, n.appear + 0.7)), vis = smooth(seg(t, n.appear, n.appear + 0.6));
        n.vis = vis; n.k = k;
        const wp = tmp.copy(n.pos).applyMatrix4(group.matrixWorld);
        const dist = wp.distanceTo(camPos);
        const lvF = clamp01((Math.abs(dist - 13.5) - 2.0) / 7.0) * (BLUR_PX.length - 1), lo = Math.floor(lvF), fr = lvF - lo;
        const nearF = clamp01(1.25 - Math.abs(dist - 13.5) / 9);
        const pulse = (!calm && n.pulse) ? 0.5 + 0.5 * Math.sin(t * 1.5 + n.ph) : 0;
        const sz = (1.55 + pulse * 0.1) * Math.max(0.001, k) * Math.min(1.5, 13.5 / dist) * 0.8;
        const tl = iconTex(n.type, lo), th = iconTex(n.type, Math.min(BLUR_PX.length - 1, lo + 1));
        n.a.material.map = tl; n.b.material.map = th;
        const base = vis * (0.55 + 0.45 * nearF) * (calm ? 0.8 : 0.95);
        n.a.material.opacity = base * (1 - fr); n.b.material.opacity = base * fr;
        n.a.scale.setScalar(sz); n.b.scale.setScalar(sz);
        // soft pulse ring
        const pp = ((t * 0.55 + n.ph / 6.28) % 1);
        n.ring.material.opacity = (!calm && n.pulse) ? vis * (1 - pp) * (1 - pp) * 0.42 * (0.5 + 0.5 * nearF) : 0;
        n.ring.scale.setScalar(sz * (1 + pp * 0.9));
      });
      lineSegs.forEach((s, idx) => {
        const A = nodes[s.a].pos, B = s.hub ? new THREE.Vector3(0, 0, 0) : nodes[s.b].pos;
        const startT = Math.max(nodes[s.a].appear + 0.5, s.hub ? hubStart + s.a * 0.12 : nodes[s.b].appear + 0.5) + linkDelay;
        const pr = easeInOut(seg(t, startT, startT + 0.9));
        const E = tmp.copy(A).lerp(B, pr); if (pr < 0.001) E.x += 0.01;
        const o = idx * 6; posA[o] = A.x; posA[o + 1] = A.y; posA[o + 2] = A.z; posA[o + 3] = E.x; posA[o + 4] = E.y; posA[o + 5] = E.z;
        const c = idx * 6, a0 = s.hub ? 0.3 : 0.16, a1 = s.hub ? 0.0 : 0.16;
        const aS = pr > 0.001 ? a0 : 0, aE = pr > 0.001 ? lerp(a0, a1, pr) : 0;
        const cs = s.hub ? [0.8, 0.9, 0.86] : [0.8, 0.9, 0.86], ce = s.hub ? [0.24, 0.84, 0.55] : [0.8, 0.9, 0.86];
        for (let q = 0; q < 3; q++) { colA[c + q] = cs[q] * aS; colA[c + 3 + q] = ce[q] * aE; }
      });
      geo.attributes.instanceStart.data.needsUpdate = true; geo.attributes.instanceColorStart.data.needsUpdate = true;
      if (hub) {
        const hv = smooth(seg(t, hubStart, hubStart + 1.2));
        hubGlow.material.opacity = hv * (0.5 + 0.06 * Math.sin(t * 1.1)); hubGlow.scale.setScalar(7.5 + 0.5 * Math.sin(t * 1.1));
        const hp = ((t * 0.4) % 1); hubRing.material.opacity = hv * (1 - hp) * 0.28; hubRing.scale.setScalar(2.2 + hp * 6);
      }
    },
  };
}

// ---------- GLSL: drifting light particles (dust / field) ----------
function makeParticles({ count, box, vel, base, color, size, shaft, seed = 3 }) {
  const R = rng(seed), g = new THREE.BufferGeometry(), pos = new Float32Array(count * 3), sd = new Float32Array(count * 4);
  for (let i = 0; i < count; i++) { sd[i * 4] = R() * 2 - 1; sd[i * 4 + 1] = R() * 2 - 1; sd[i * 4 + 2] = R() * 2 - 1; sd[i * 4 + 3] = R(); }
  g.setAttribute('position', new THREE.BufferAttribute(pos, 3)); g.setAttribute('aSeed', new THREE.BufferAttribute(sd, 4));
  const m = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending,
    uniforms: { uT: { value: 0 }, uBox: { value: new THREE.Vector3(...box) }, uVel: { value: new THREE.Vector3(...vel) }, uBase: { value: base }, uColor: { value: new THREE.Vector3(...color) }, uSize: { value: size }, uScale: { value: H * SS * 0.5 }, uShA: { value: new THREE.Vector3(...(shaft ? shaft.a : [0, 0, 0])) }, uShB: { value: new THREE.Vector3(...(shaft ? shaft.b : [0, 1, 0])) }, uShR: { value: shaft ? shaft.r : 1 }, uShBoost: { value: shaft ? shaft.boost : 0 }, uFade: { value: 1 } },
    vertexShader: `attribute vec4 aSeed; uniform float uT, uBase, uSize, uScale, uShR, uShBoost, uFade; uniform vec3 uBox, uVel, uShA, uShB; varying float vA;
      void main(){
        vec3 p = aSeed.xyz*uBox + uVel*uT; p = mod(p+uBox, 2.*uBox) - uBox;
        p += vec3(sin(uT*.31+aSeed.w*6.28), cos(uT*.23+aSeed.w*9.0), sin(uT*.19+aSeed.w*3.0))*.28;
        vec3 ab = uShB-uShA; float h = clamp(dot(p-uShA,ab)/dot(ab,ab),0.,1.); float d = length(p-(uShA+ab*h));
        float inS = exp(-pow(d/max(uShR*(0.25+h*0.9),.001),2.)) * uShBoost;
        vec4 mv = modelViewMatrix*vec4(p,1.); gl_Position = projectionMatrix*mv;
        float tw = .65+.35*sin(uT*(1.2+aSeed.w*1.5)+aSeed.w*40.);
        vA = (uBase*(.35+aSeed.w*.65) + inS)*tw*uFade;
        gl_PointSize = max(uScale/360., uSize*(.5+aSeed.w)*uScale/(-mv.z)*projectionMatrix[1][1]/1.7);
      }`,
    fragmentShader: `uniform vec3 uColor; varying float vA;
      void main(){ float r = length(gl_PointCoord-.5)*2.; float a = pow(clamp(1.-r,0.,1.),2.2); gl_FragColor = vec4(uColor*vA*a, 1.); }`,
  });
  const pts = new THREE.Points(g, m); pts.frustumCulled = false; return pts;
}

// ---------- shots ----------
const state = {};
function lookFrom(cam, p, tgt) { cam.position.set(...p); cam.lookAt(new THREE.Vector3(...tgt)); cam.updateMatrixWorld(); }
function canvasTex(w, h, draw) { const cv = document.createElement('canvas'); cv.width = w; cv.height = h; draw(cv.getContext('2d'), w, h); const t = new THREE.CanvasTexture(cv); t.colorSpace = THREE.SRGBColorSpace; t.anisotropy = 8; return t; }

function buildColdOpen() {
  const scene = new THREE.Scene(); scene.background = new THREE.Color(0x0a0a0b);
  const cam = new THREE.PerspectiveCamera(32, W / H, 0.1, 100); scene.fog = new THREE.Fog(0x0a0a0b, 14, 34);
  const pm = new THREE.PMREMGenerator(renderer); const env = pm.fromScene(new RoomEnvironment(), 0.04).texture;
  const matEnv = 0.22;
  // floor: faint, only lit by the window light
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(60, 60), new THREE.MeshStandardMaterial({ color: 0x101113, roughness: 0.55, metalness: 0.0, envMap: env, envMapIntensity: 0.1 }));
  floor.rotation.x = -Math.PI / 2; scene.add(floor);
  // laptop
  const L = new THREE.Group(); scene.add(L);
  const alu = new THREE.MeshStandardMaterial({ color: 0x2c2e32, metalness: 0.85, roughness: 0.42, envMap: env, envMapIntensity: matEnv });
  const base = new THREE.Mesh(new RoundedBoxGeometry(3.0, 0.1, 2.1, 5, 0.05), alu); base.position.y = 0.05; L.add(base);
  const dustTex = (ctx, w, h, rnd) => { for (let i = 0; i < 900; i++) { ctx.fillStyle = `rgba(210,216,224,${0.03 + rnd() * 0.1})`; ctx.fillRect(rnd() * w, rnd() * h, 1 + rnd() * 2.2, 1 + rnd() * 2.2); } };
  const deck = new THREE.Mesh(new THREE.PlaneGeometry(2.78, 1.9), new THREE.MeshStandardMaterial({ roughness: 0.6, metalness: 0.15, envMap: env, envMapIntensity: 0.12, map: canvasTex(1400, 960, (ctx, w, h) => {
    const r = rng(5); ctx.fillStyle = '#16171a'; ctx.fillRect(0, 0, w, h);
    const rows = [14, 14, 13, 12, 10]; let y = 70; rows.forEach((n, ri) => { const kw = (w - 160) / n; for (let i = 0; i < n; i++) { ctx.fillStyle = '#212327'; ctx.beginPath(); ctx.roundRect(80 + i * kw + 3, y, kw - 8, 92, 12); ctx.fill(); } y += 112; });
    ctx.fillStyle = '#1b1c20'; ctx.beginPath(); ctx.roundRect(w * 0.34, h * 0.69, w * 0.32, h * 0.24, 22); ctx.fill(); ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 3; ctx.stroke(); dustTex(ctx, w, h, r);
  }) }));
  deck.rotation.x = -Math.PI / 2; deck.position.set(0, 0.1015, 0.02); L.add(deck);
  const hinge = new THREE.Group(); hinge.position.set(0, 0.1, -1.0); hinge.rotation.x = -0.3; L.add(hinge);
  const lid = new THREE.Mesh(new RoundedBoxGeometry(3.0, 1.98, 0.06, 5, 0.03), alu); lid.position.set(0, 0.99, 0); hinge.add(lid);
  const screenMat = new THREE.MeshStandardMaterial({ color: 0x050607, roughness: 0.25, metalness: 0.0, emissive: 0xffffff, emissiveIntensity: 0, envMap: env, envMapIntensity: 0.08,
    emissiveMap: canvasTex(1600, 1000, (ctx, w, h) => { // quiet "monitor" UI: soft panels and a radar mark
      ctx.fillStyle = '#04110b'; ctx.fillRect(0, 0, w, h);
      const g = ctx.createRadialGradient(w / 2, h * 0.5, 10, w / 2, h * 0.5, w * 0.6); g.addColorStop(0, 'rgba(61,214,140,0.5)'); g.addColorStop(1, 'rgba(61,214,140,0)'); ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
      ctx.strokeStyle = 'rgba(160,255,210,0.55)'; ctx.lineWidth = 5; [90, 180, 270].forEach((r) => { ctx.beginPath(); ctx.arc(w / 2, h * 0.52, r, 0, Math.PI * 2); ctx.stroke(); });
      ctx.beginPath(); ctx.moveTo(w / 2, h * 0.52); ctx.lineTo(w / 2 + 230, h * 0.52 - 150); ctx.stroke();
      ctx.fillStyle = 'rgba(220,255,240,0.9)'; ctx.beginPath(); ctx.arc(w / 2, h * 0.52, 9, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = 'rgba(160,255,210,0.28)'; for (let i = 0; i < 5; i++) { ctx.beginPath(); ctx.roundRect(110, 120 + i * 62, 260 - i * 26, 24, 8); ctx.fill(); }
    }) });
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(2.78, 1.74), screenMat); screen.position.set(0, 1.0, 0.032); hinge.add(screen);
  const screenLight = new THREE.PointLight(0x7dffc0, 0, 9, 2); screenLight.position.set(0, 1.1, 1.2); L.add(screenLight);
  L.position.set(0.2, 0, 0);
  // key light from a window (upper left) + light shaft
  const keyPos = new THREE.Vector3(-7.5, 8.2, 3.2), keyTgt = new THREE.Vector3(0.2, 0.5, -0.4);
  const spot = new THREE.SpotLight(0xcfe0ff, 0, 40, 0.32, 0.95, 1.6); spot.position.copy(keyPos); spot.target.position.copy(keyTgt); scene.add(spot, spot.target);
  scene.add(new THREE.AmbientLight(0x8899aa, 0.05));
  const dir = keyTgt.clone().sub(keyPos), len = dir.length();
  const shaftMat = new THREE.ShaderMaterial({ transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, uniforms: { uI: { value: 0 } },
    vertexShader: 'varying vec3 vN; varying vec3 vV; varying float vH; void main(){ vN = normalize(normalMatrix*normal); vec4 mv = modelViewMatrix*vec4(position,1.); vV = normalize(-mv.xyz); vH = uv.y; gl_Position = projectionMatrix*mv; }',
    fragmentShader: 'uniform float uI; varying vec3 vN; varying vec3 vV; varying float vH; void main(){ float f = pow(abs(dot(normalize(vN), normalize(vV))), 1.6); float a = f * smoothstep(0.0,0.25,vH) * (1.0 - smoothstep(0.55,1.0,vH)) * uI; gl_FragColor = vec4(vec3(.78,.88,1.0)*a, 1.); }' });
  const shaft = new THREE.Mesh(new THREE.CylinderGeometry(0.15, 2.7, len, 40, 1, true), shaftMat);
  shaft.position.copy(keyPos).add(keyTgt).multiplyScalar(0.5); shaft.quaternion.setFromUnitVectors(new THREE.Vector3(0, -1, 0), dir.clone().normalize()); scene.add(shaft);
  const dust = makeParticles({ count: 420, box: [7.5, 4.0, 5.5], vel: [0.05, 0.035, 0.0], base: 0.07, color: [0.82, 0.9, 1.0], size: 0.055, shaft: { a: keyPos.toArray(), b: keyTgt.toArray(), r: 1.9, boost: 0.75 }, seed: 11 });
  dust.position.set(-0.5, 1.8, 0.5); scene.add(dust);
  // radar ring expanding over the floor
  const ringMesh = new THREE.Mesh(new THREE.RingGeometry(0.985, 1.0, 160), new THREE.MeshBasicMaterial({ color: 0x3dd68c, transparent: true, opacity: 0, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide, fog: false }));
  ringMesh.rotation.x = -Math.PI / 2; ringMesh.position.set(0.2, 0.004, 0); scene.add(ringMesh);
  const overlay = makeOverlay(0.78); scene.add(overlay);
  return { scene, cam, update(t, dur) {
    const lightIn = smooth(seg(t, 0.2, 1.8)); spot.intensity = 230 * lightIn; shaftMat.uniforms.uI.value = 0.055 * lightIn; dust.material.uniforms.uT.value = t + 4;
    const sc = easeInOut(seg(t, 6.3, 8.4)); screenMat.emissiveIntensity = 1.3 * sc; screenLight.intensity = 5 * sc;
    const rp = seg(t, 6.9, 9.3); ringMesh.scale.setScalar(0.4 + easeOut(rp) * 9.5); ringMesh.material.opacity = 0.5 * Math.pow(1 - rp, 1.5) * smooth(seg(rp, 0, 0.08));
    const k = t / dur; lookFrom(cam, [lerp(2.6, 3.6, k), lerp(2.2, 2.3, k), lerp(14.6, 13.4, k)], [lerp(0.2, 0.5, k), 2.75, -0.3]);
    overlay.material.uniforms.uFade.value = Math.max(1 - seg(t, 0, 0.3), seg(t, dur - 0.3, dur));
  } };
}

function buildQuestion(isClose) {
  const scene = new THREE.Scene(); scene.background = new THREE.Color(0x0a0a0b);
  const cam = new THREE.PerspectiveCamera(30, W / H, 0.1, 100);
  const C = makeConstellation(scene, { hub: isClose });
  const dust = makeParticles({ count: 260, box: [11, 6, 11], vel: [0, 0.02, 0.03], base: 0.1, color: [0.8, 0.9, 1.0], size: 0.05, seed: 21 }); scene.add(dust);
  const overlay = makeOverlay(isClose ? 0.55 : 0.8); scene.add(overlay);
  return { scene, cam, update(t, dur) {
    const ang = (isClose ? 0.9 : 0.0) + t * (isClose ? 0.10 : 0.16); C.group.rotation.y = ang; C.group.updateMatrixWorld(true);
    lookFrom(cam, [lerp(0, isClose ? 0.8 : 1.2, t / dur), isClose ? 2.2 : 2.6, isClose ? 15.2 : 16.0 - 0.8 * (t / dur)], [0, 0, 0]);
    C.update(t, cam.position, isClose ? { calm: true, hubStart: 0.3, linkDelay: 0.0 } : { calm: false, linkDelay: 0.25 });
    dust.material.uniforms.uT.value = t; dust.material.uniforms.uFade.value = 1;
    overlay.material.uniforms.uFade.value = Math.max(1 - seg(t, 0, 0.3), seg(t, dur - (isClose ? 0.5 : 0.3), dur));
  } };
}

function buildTitle() {
  const scene = new THREE.Scene(); scene.background = new THREE.Color(0x0a0a0b);
  const cam = new THREE.PerspectiveCamera(40, W / H, 0.1, 200);
  const blips = []; const R = rng(13); for (let i = 0; i < 8; i++) blips.push([2.0 + R() * 5.6, R() * 6.2832]);
  const mat = new THREE.ShaderMaterial({ transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, extensions: { derivatives: true },
    uniforms: { uSweep: { value: 0 }, uIn: { value: 0 }, uBlips: { value: blips.map((b) => new THREE.Vector2(b[0], b[1])) } },
    vertexShader: 'varying vec3 vW; void main(){ vec4 w = modelMatrix*vec4(position,1.); vW = w.xyz; gl_Position = projectionMatrix*viewMatrix*w; }',
    fragmentShader: `varying vec3 vW; uniform float uSweep, uIn; uniform vec2 uBlips[8];
      const float PI = 3.14159265, TAU = 6.2831853, RMAX = 8.6;
      float ln(float d, float w){ float aa = fwidth(d)*1.1; return 1.-smoothstep(w-aa, w+aa+1e-4, abs(d)); }
      void main(){
        float r = length(vW.xz), ang = atan(vW.z, vW.x);
        float inr = uIn*RMAX*1.1; float edge = 1.-smoothstep(inr-1.0, inr, r);
        float fade = (1.-smoothstep(RMAX-0.4, RMAX+0.2, r)) * edge;
        float rd = (abs(fract(r/1.2+.5)-.5))*1.2; float rings = ln(rd, 0.011+r*0.0015) * (.18+.5*exp(-r*.12));
        float step6 = PI/6.; float ad = (abs(fract(ang/step6+.5)-.5))*step6*max(r,.001); float rad = ln(ad, .008) * .12 * smoothstep(1.,2.,r);
        float tick = ln((abs(fract(ang/(PI/36.)+.5)-.5))*(PI/36.)*r, .012) * smoothstep(RMAX-.5,RMAX-.4,r) * (1.-smoothstep(RMAX-.1,RMAX,r)) * .3;
        float dlt = mod(uSweep-ang, TAU); float wedge = exp(-dlt*2.4) * .32 * smoothstep(.4,1.2,r) ; float beam = exp(-dlt*70.) * .75 * smoothstep(.2,1.,r);
        vec3 col = vec3(1.) * (rings*.55 + rad + tick) * fade + vec3(.239,.839,.549) * (wedge + beam) * fade;
        col += vec3(.239,.839,.549) * exp(-r*.45) * .07 * edge;
        for(int i=0;i<8;i++){ vec2 b = uBlips[i]; vec2 bp = b.x*vec2(cos(b.y), sin(b.y)); float d = length(vW.xz-bp); float since = mod(uSweep-b.y, TAU); float seen = step(b.y*0.0, 1.0);
          float glow = exp(-since*.9) * smoothstep(0.,.05,since); float dot_ = (1.-smoothstep(.07,.11,d)) * (.25+.75*glow) + exp(-d*4.5) * .22 * glow;
          col += vec3(.85,1.,.93) * dot_ * .7 * fade; }
        gl_FragColor = vec4(col, 1.);
      }` });
  const plane = new THREE.Mesh(new THREE.PlaneGeometry(60, 60), mat); plane.rotation.x = -Math.PI / 2; scene.add(plane);
  const dust = makeParticles({ count: 200, box: [12, 5, 12], vel: [0, 0.015, 0], base: 0.08, color: [0.85, 0.95, 1.0], size: 0.045, seed: 31 }); dust.position.y = 3; scene.add(dust);
  const overlay = makeOverlay(0.72); scene.add(overlay);
  return { scene, cam, update(t, dur) {
    const k = t / dur; const e = 1 - Math.pow(1 - clamp01(t / (dur * 0.95)), 2.4);
    mat.uniforms.uSweep.value = -1.6 + (2.35 * Math.PI) * e; mat.uniforms.uIn.value = easeOut(seg(t, 0.0, 1.8));
    lookFrom(cam, [0, lerp(3.4, 3.9, k), lerp(14.8, 13.4, k)], [0, 0, 0.6]);
    dust.material.uniforms.uT.value = t;
    overlay.material.uniforms.uFade.value = Math.max(1 - seg(t, 0, 0.3), seg(t, dur - 0.3, dur));
  } };
}

function buildPrice() {
  const scene = new THREE.Scene(); scene.background = new THREE.Color(0x0a0a0b);
  const cam = new THREE.PerspectiveCamera(35, W / H, 0.1, 100);
  const causMat = new THREE.ShaderMaterial({ transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending, uniforms: { uT: { value: 0 } },
    vertexShader: 'varying vec2 vUv; void main(){ vUv=uv; gl_Position=vec4(position.xy,0.,1.); }',
    fragmentShader: `varying vec2 vUv; uniform float uT; const float TAU=6.28318530718;
      float caustic(vec2 uv, float t){ vec2 p = mod(uv*TAU, TAU)-250.; vec2 i = p; float c = 1.; float inten = .005;
        for(int n=0;n<4;n++){ float tt = t*(1.-(3.5/float(n+1))); i = p + vec2(cos(tt-i.x)+sin(tt+i.y), sin(tt-i.y)+cos(tt+i.x)); c += 1./length(vec2(p.x/(sin(i.x+tt)/inten), p.y/(cos(i.y+tt)/inten))); }
        c /= 4.; c = 1.17-pow(c,1.4); return pow(abs(c), 8.); }
      void main(){ vec2 uv = vUv*vec2(1.78,1.)*.55 + vec2(uT*.01, uT*.006); float c = caustic(uv, uT*.35+23.);
        float v = 1.-smoothstep(.35,.95,length(vUv-.5)*1.6); vec3 col = mix(vec3(.45,.62,.55), vec3(.24,.84,.55), .5)*c*.13*(.4+.6*v);
          float h1 = fract(sin(dot(gl_FragCoord.xy, vec2(12.9898,78.233)))*43758.5453), h2 = fract(sin(dot(gl_FragCoord.xy, vec2(26.651,41.173)))*24634.6345);
          col += (h1+h2-1.)*0.5/255.; gl_FragColor = vec4(max(col,0.),1.); }` });
  const cq = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), causMat); cq.frustumCulled = false; cq.renderOrder = -10; scene.add(cq);
  const field = makeParticles({ count: 520, box: [12, 6.5, 14], vel: [0.02, 0.012, 0.35], base: 0.4, color: [0.8, 0.95, 0.9], size: 0.08, seed: 41 }); scene.add(field);
  const overlay = makeOverlay(0.78); scene.add(overlay);
  return { scene, cam, update(t, dur) {
    causMat.uniforms.uT.value = t; field.material.uniforms.uT.value = t + 2;
    lookFrom(cam, [lerp(-0.6, 0.6, t / dur), lerp(0.4, 0.7, t / dur), 12], [0, 0, 0]);
    overlay.material.uniforms.uFade.value = Math.max(1 - seg(t, 0, 0.3), seg(t, dur - 0.3, dur));
  } };
}

window.setup = (shot, dur) => {
  const b = { coldopen: buildColdOpen, question: () => buildQuestion(false), close: () => buildQuestion(true), title: buildTitle, price: buildPrice }[shot]();
  state.b = b; state.dur = dur; return true;
};
window.renderAt = (t) => { state.b.update(t, state.dur); renderer.render(state.b.scene, state.b.cam); return true; };
window.__ready = true;
