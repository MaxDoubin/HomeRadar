// Deterministic studio product renders for the Home Radar film.
// window.setup(shot, media) builds the scene; window.renderAt(t) draws one frame.
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { BokehPass } from 'three/addons/postprocessing/BokehPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { SMAAPass } from 'three/addons/postprocessing/SMAAPass.js';
import { Reflector } from 'three/addons/objects/Reflector.js';

const W = 1920, H = 1080;
const BG = 0x0a0a0b;
// Linear colour that Neutral tone mapping maps back to exactly #0a0a0b, for anything that
// passes through tone mapping (composer output, the floor shader), so every clip's
// background matches the film's #0a0a0b and cuts in and out without a black step.
const BG_TM = new THREE.Color().setRGB(0.022037, 0.022037, 0.022349, THREE.LinearSRGBColorSpace);
const params = new URLSearchParams(location.search);
const SS = parseFloat(params.get('ss') || '1');
const REFL = params.get('refl') !== '0';
const DOF = params.get('dof') !== '0';
const USE_SMAA = params.get('smaa') !== '0';
const RMSAA = parseInt(params.get('rmsaa') || '4', 10);
const LITE = params.get('lite') === '1';
const MSAA = parseInt(params.get('msaa') || '0', 10);

// direct=1: render straight to an MSAA canvas (no composer passes); only valid for shots without depth of field.
const DIRECT = true;
const renderer = new THREE.WebGLRenderer({ antialias: DIRECT, preserveDrawingBuffer: true, powerPreference: 'high-performance' });
renderer.setPixelRatio(SS);
renderer.setSize(W, H, false);
renderer.domElement.style.width = W + 'px';
renderer.domElement.style.height = H + 'px';
renderer.toneMapping = (params.get('tm') || 'neutral') === 'aces' ? THREE.ACESFilmicToneMapping : THREE.NeutralToneMapping;
renderer.toneMappingExposure = parseFloat(params.get('exp') || '1.0');
renderer.outputColorSpace = THREE.SRGBColorSpace;
document.body.appendChild(renderer.domElement);
const maxAniso = Math.min(16, renderer.capabilities.getMaxAnisotropy());

// ---------- helpers ----------
const clamp01 = (x) => Math.min(1, Math.max(0, x));
const lerp = (a, b, k) => a + (b - a) * k;
const seg = (t, a, b) => clamp01((t - a) / (b - a));
const easeInOutCubic = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
const easeOutCubic = (x) => 1 - Math.pow(1 - x, 3);
const easeInOutSine = (x) => -(Math.cos(Math.PI * x) - 1) / 2;
const smooth = (x) => x * x * (3 - 2 * x);

function roundedRectShape(w, h, r) {
  const s = new THREE.Shape();
  const x = -w / 2, y = -h / 2;
  s.moveTo(x + r, y);
  s.lineTo(x + w - r, y);
  s.quadraticCurveTo(x + w, y, x + w, y + r);
  s.lineTo(x + w, y + h - r);
  s.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  s.lineTo(x + r, y + h);
  s.quadraticCurveTo(x, y + h, x, y + h - r);
  s.lineTo(x, y + r);
  s.quadraticCurveTo(x, y, x + r, y);
  return s;
}

// Flat rounded rectangle with 0..1 UVs (optionally cropped to cover an image aspect).
function roundedPlane(w, h, r, curveSegs = 16, uvCrop = null) {
  const g = new THREE.ShapeGeometry(roundedRectShape(w, h, r), curveSegs);
  const pos = g.attributes.position, uv = g.attributes.uv;
  const c = uvCrop || { u0: 0, u1: 1, v0: 0, v1: 1 };
  for (let i = 0; i < pos.count; i++) {
    const u = (pos.getX(i) + w / 2) / w, v = (pos.getY(i) + h / 2) / h;
    uv.setXY(i, lerp(c.u0, c.u1, u), lerp(c.v0, c.v1, v));
  }
  return g;
}

// A slab with a large in-plane corner radius and softly rounded edges, extruded along +Z and centered.
function slab(w, h, depth, cornerR, bevel) {
  const shape = roundedRectShape(w - 2 * bevel, h - 2 * bevel, Math.max(0.001, cornerR - bevel));
  const g = new THREE.ExtrudeGeometry(shape, {
    depth: Math.max(0.0001, depth - 2 * bevel), bevelEnabled: true, bevelThickness: bevel, bevelSize: bevel,
    bevelSegments: 8, curveSegments: 24,
  });
  g.translate(0, 0, -(depth - 2 * bevel) / 2);
  g.computeVertexNormals();
  return g;
}

// Crop UVs so an image of aspect imgA covers a surface of aspect surfA (like CSS object-fit: cover, top-anchored).
function coverCrop(imgA, surfA, anchorTop = true) {
  if (imgA > surfA) { const k = surfA / imgA; return { u0: (1 - k) / 2, u1: (1 + k) / 2, v0: 0, v1: 1 }; }
  const k = imgA / surfA;
  return anchorTop ? { u0: 0, u1: 1, v0: 1 - k, v1: 1 } : { u0: 0, u1: 1, v0: (1 - k) / 2, v1: (1 + k) / 2 };
}

function blobTexture(w, h, r, blurPx, size = 1024) {
  const c = document.createElement('canvas');
  const aspect = w / h;
  c.width = size; c.height = Math.round(size / aspect);
  const ctx = c.getContext('2d');
  const pad = blurPx * 2.2;
  ctx.filter = `blur(${blurPx * size / 512}px)`;
  ctx.fillStyle = '#000';
  const rr = Math.min(r, (c.height - 2 * pad) / 2);
  ctx.beginPath();
  ctx.roundRect(pad, pad, c.width - 2 * pad, c.height - 2 * pad, rr);
  ctx.fill();
  const t = new THREE.CanvasTexture(c);
  return t;
}

function contactShadow(w, d, opacity, blurPx, r = 40, y = 0.002) {
  const tex = blobTexture(w, d, r, blurPx);
  const m = new THREE.Mesh(new THREE.PlaneGeometry(w, d), new THREE.MeshBasicMaterial({
    map: tex, transparent: true, opacity, depthWrite: false, color: 0x000000,
  }));
  m.rotation.x = -Math.PI / 2;
  m.position.y = y;
  m.renderOrder = 2;
  return m;
}

// ---------- materials ----------
const M = {
  aluminium: new THREE.MeshStandardMaterial({ color: 0x8e9196, metalness: 1, roughness: 0.3 }),
  shell: new THREE.MeshStandardMaterial({ color: 0x8e9196, metalness: 1, roughness: 0.3, polygonOffset: true, polygonOffsetFactor: 2, polygonOffsetUnits: 8 }),
  titaniumShell: new THREE.MeshPhysicalMaterial({ color: 0x9c9890, metalness: 1, roughness: 0.26, clearcoat: 0.5, clearcoatRoughness: 0.15, polygonOffset: true, polygonOffsetFactor: 2, polygonOffsetUnits: 8 }),
  aluminiumDark: new THREE.MeshStandardMaterial({ color: 0x55575b, metalness: 1, roughness: 0.42 }),
  standDark: new THREE.MeshStandardMaterial({ color: 0x2e2f32, metalness: 1, roughness: 0.6 }),
  titanium: new THREE.MeshPhysicalMaterial({ color: 0x9c9890, metalness: 1, roughness: 0.26, clearcoat: 0.5, clearcoatRoughness: 0.15 }),
  keycap: new THREE.MeshStandardMaterial({ color: 0x0e0e10, metalness: 0, roughness: 0.55 }),
  well: new THREE.MeshStandardMaterial({ color: 0x2a2b2e, metalness: 0.9, roughness: 0.5 }),
  trackpad: new THREE.MeshPhysicalMaterial({ color: 0x9a9da2, metalness: 0.85, roughness: 0.2, clearcoat: 0.6, clearcoatRoughness: 0.1 }),
  blackGlass: new THREE.MeshPhysicalMaterial({ color: 0x030304, metalness: 0, roughness: 0.06, clearcoat: 1, clearcoatRoughness: 0.03 }),
  hinge: new THREE.MeshStandardMaterial({ color: 0x18181a, metalness: 0.6, roughness: 0.45 }),
  lens: new THREE.MeshPhysicalMaterial({ color: 0x050507, metalness: 0.2, roughness: 0.1, clearcoat: 1 }),
};

if (LITE) {
  for (const k of ['titanium', 'trackpad', 'blackGlass', 'lens']) {
    const m = M[k];
    M[k] = new THREE.MeshStandardMaterial({ color: m.color, metalness: m.metalness, roughness: m.roughness });
  }
}

// Additive glass layer: black diffuse, so only environment reflections are added over the display.
const GLASS_LAYER = 1;
function onGlassLayer(mesh) { mesh.layers.set(GLASS_LAYER); return mesh; }
function glassLayer(strength = 1) {
  return new THREE.MeshPhysicalMaterial({
    color: 0x000000, metalness: 0, roughness: 0.05,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, envMapIntensity: strength,
  });
}

// Moving light-sweep band across a glass surface (additive).
function sweepMaterial() {
  return new THREE.ShaderMaterial({
    uniforms: { uPos: { value: -2 }, uStrength: { value: 0 }, uAngle: { value: 0.55 } },
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
    vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }`,
    fragmentShader: `uniform float uPos, uStrength, uAngle; varying vec2 vUv;
      void main(){
        float d = (vUv.x * cos(uAngle) + vUv.y * sin(uAngle)) - uPos;
        float band = exp(-d*d*420.0) * 0.8 + exp(-d*d*25.0) * 0.12;
        gl_FragColor = vec4(vec3(band * uStrength), 1.0);
      }`,
  });
}

// ---------- texture loading ----------
const loader = new THREE.TextureLoader();
function loadScreen(url) {
  return new Promise((resolve, reject) => loader.load(url, (t) => {
    t.colorSpace = THREE.SRGBColorSpace;
    t.anisotropy = maxAniso;
    t.generateMipmaps = true;
    t.minFilter = THREE.LinearMipmapLinearFilter;
    t.magFilter = THREE.LinearFilter;
    resolve(t);
  }, undefined, reject));
}
function screenMaterial(tex) {
  return new THREE.MeshBasicMaterial({ map: tex, color: 0xffffff });
}

// ---------- devices ----------
function makeLaptop(tex) {
  const g = new THREE.Group();
  const BW = 3.04, BD = 2.15, BT = 0.1;
  const base = new THREE.Mesh(slab(BW, BD, BT, 0.16, 0.035), M.aluminium);
  base.rotation.x = -Math.PI / 2;
  base.position.y = BT / 2;
  g.add(base);

  // keyboard well + keys
  const well = new THREE.Mesh(roundedPlane(2.66, 1.1, 0.05), M.well);
  well.rotation.x = -Math.PI / 2; well.position.set(0, BT + 0.0008, -0.36);
  g.add(well);
  const keyGeo = slab(0.158, 0.158, 0.02, 0.03, 0.006);
  const rows = [
    { n: 14, h: 0.082, w: 0.158 },
    { n: 14, h: 0.158, w: 0.158 }, { n: 14, h: 0.158, w: 0.158 },
    { n: 13, h: 0.158, w: 0.158 }, { n: 12, h: 0.158, w: 0.158 }, { n: 0, h: 0.158 },
  ];
  const pitch = 0.183;
  const keys = [];
  let z = -0.36 - 1.1 / 2 + 0.09;
  rows.forEach((row, ri) => {
    const zc = z + row.h / 2;
    if (ri === 5) {
      const layout = [0.158, 0.158, 0.158, 0.2, 0.92, 0.2, 0.158, 0.158, 0.158];
      const total = layout.reduce((a, b) => a + b, 0) + (layout.length - 1) * 0.025;
      let x = -total / 2;
      layout.forEach((kw) => { keys.push({ x: x + kw / 2, z: zc, w: kw, h: row.h }); x += kw + 0.025; });
    } else {
      const total = 14 * pitch - 0.025;
      const n = row.n;
      // stretch the first/last keys so every row spans the same width
      const extra = (total - (n * pitch - 0.025)) / 2;
      let x = -total / 2;
      for (let i = 0; i < n; i++) {
        let kw = row.w;
        if (i === 0 || i === n - 1) kw += extra;
        keys.push({ x: x + kw / 2, z: zc, w: kw, h: row.h });
        x += kw + 0.025;
      }
    }
    z += row.h + 0.025;
  });
  const km = new THREE.InstancedMesh(keyGeo, M.keycap, keys.length);
  const mtx = new THREE.Matrix4(), q = new THREE.Quaternion().setFromEuler(new THREE.Euler(-Math.PI / 2, 0, 0));
  keys.forEach((k, i) => {
    mtx.compose(new THREE.Vector3(k.x, BT + 0.006, k.z), q, new THREE.Vector3(k.w / 0.158, k.h / 0.158, 1));
    km.setMatrixAt(i, mtx);
  });
  g.add(km);

  const pad = new THREE.Mesh(roundedPlane(1.28, 0.8, 0.06), M.trackpad);
  pad.rotation.x = -Math.PI / 2; pad.position.set(0, BT + 0.0006, 0.6);
  g.add(pad);

  const hinge = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 2.5, 32), M.hinge);
  hinge.rotation.z = Math.PI / 2; hinge.position.set(0, BT + 0.01, -BD / 2 + 0.04);
  g.add(hinge);

  // lid, hinged at the back edge
  const LW = 3.04, LH = 2.06, LT = 0.056;
  const lid = new THREE.Group();
  lid.position.set(0, BT + 0.012, -BD / 2 + 0.03);
  const shell = new THREE.Mesh(slab(LW, LH, LT, 0.15, 0.024), M.shell);
  shell.position.set(0, LH / 2, 0);
  lid.add(shell);
  const bezel = new THREE.Mesh(roundedPlane(LW - 0.056, LH - 0.056, 0.124), M.blackGlass);
  bezel.position.set(0, LH / 2, LT / 2 + 0.003);
  lid.add(bezel);
  const DW = 2.88, DH = 1.8;
  const screenMat = screenMaterial(tex);
  const display = new THREE.Mesh(roundedPlane(DW, DH, 0.02, 8, coverCrop(tex.image.width / tex.image.height, DW / DH)), screenMat);
  display.position.set(0, LH / 2 + 0.04, LT / 2 + 0.005);
  lid.add(display);
  const cam = new THREE.Mesh(new THREE.CircleGeometry(0.012, 24), M.lens);
  cam.position.set(0, LH - 0.045, LT / 2 + 0.0052);
  lid.add(cam);
  const glass = new THREE.Mesh(roundedPlane(LW - 0.056, LH - 0.056, 0.124), glassLayer(0.45));
  glass.position.set(0, LH / 2, LT / 2 + 0.007);
  glass.renderOrder = 3;
  lid.add(onGlassLayer(glass));
  g.add(lid);

  const shadow1 = contactShadow(3.5, 2.65, 0.85, 26, 60);
  const shadow2 = contactShadow(3.12, 2.24, 0.9, 8, 40, 0.0025);
  g.add(shadow1, shadow2);

  g.userData = { lid, screenMat, display, displayCenterLocal: new THREE.Vector3(0, LH / 2 + 0.04, LT / 2), glass };
  return g;
}

function makePhone(tex) {
  const g = new THREE.Group();
  const PW = 0.72, PH = 1.47, PT = 0.08;
  const body = new THREE.Mesh(slab(PW, PH, PT, 0.115, 0.022), M.titaniumShell);
  g.add(body);
  const front = new THREE.Mesh(roundedPlane(PW - 0.046, PH - 0.046, 0.093, 24), M.blackGlass);
  front.position.z = PT / 2 + 0.002;
  g.add(front);
  const back = new THREE.Mesh(roundedPlane(PW - 0.046, PH - 0.046, 0.093, 24), new THREE.MeshPhysicalMaterial({ color: 0x2b2a28, metalness: 0, roughness: 0.32, clearcoat: 1, clearcoatRoughness: 0.2 }));
  back.position.z = -PT / 2 - 0.002; back.rotation.y = Math.PI;
  g.add(back);
  const DW = 0.646, DH = 1.396;
  const screenMat = screenMaterial(tex);
  const display = new THREE.Mesh(roundedPlane(DW, DH, 0.08, 24, coverCrop(tex.image.width / tex.image.height, DW / DH)), screenMat);
  display.position.z = PT / 2 + 0.0035;
  g.add(display);
  const hole = new THREE.Mesh(new THREE.CircleGeometry(0.014, 32), M.lens);
  hole.position.set(0, PH / 2 - 0.055, PT / 2 + 0.0038);
  g.add(hole);
  const glass = new THREE.Mesh(roundedPlane(PW - 0.046, PH - 0.046, 0.093, 24), glassLayer(0.6));
  glass.position.z = PT / 2 + 0.005; glass.renderOrder = 3;
  g.add(onGlassLayer(glass));
  const sweep = new THREE.Mesh(roundedPlane(PW - 0.046, PH - 0.046, 0.093, 24), sweepMaterial());
  sweep.position.z = PT / 2 + 0.006; sweep.renderOrder = 4;
  g.add(onGlassLayer(sweep));
  // side buttons
  const btnGeo = slab(0.02, 0.2, 0.026, 0.008, 0.006);
  const power = new THREE.Mesh(btnGeo, M.titanium);
  power.position.set(PW / 2 + 0.004, 0.22, 0); power.rotation.y = Math.PI / 2;
  g.add(power);
  [0.32, 0.12].forEach((y) => {
    const b = new THREE.Mesh(slab(0.02, 0.14, 0.026, 0.008, 0.006), M.titanium);
    b.position.set(-PW / 2 - 0.004, y, 0); b.rotation.y = Math.PI / 2; g.add(b);
  });
  g.userData = { screenMat, sweep: sweep.material, glass };
  return g;
}

function makeMonitor(tex) {
  const g = new THREE.Group();
  const MW = 4.6, MH = 2.98, MT = 0.07;
  const panel = new THREE.Group();
  panel.position.y = 1.95;
  const shell = new THREE.Mesh(slab(MW, MH, MT, 0.12, 0.02), M.shell);
  panel.add(shell);
  const bezel = new THREE.Mesh(roundedPlane(MW - 0.046, MH - 0.046, 0.1), M.blackGlass);
  bezel.position.z = MT / 2 + 0.003; panel.add(bezel);
  const DW = 4.46, DH = 2.79;
  const screenMat = screenMaterial(tex);
  const display = new THREE.Mesh(roundedPlane(DW, DH, 0.01, 8, coverCrop(tex.image.width / tex.image.height, DW / DH)), screenMat);
  display.position.z = MT / 2 + 0.005; panel.add(display);
  const glass = new THREE.Mesh(roundedPlane(MW - 0.046, MH - 0.046, 0.1), glassLayer(0.4));
  glass.position.z = MT / 2 + 0.007; glass.renderOrder = 3; panel.add(onGlassLayer(glass));
  g.add(panel);
  // stand: a single bent sheet (neck) and a flat foot
  const neck = new THREE.Mesh(slab(0.5, 1.45, 0.04, 0.03, 0.012), M.standDark);
  neck.position.set(0, 0.78, -0.36); neck.rotation.x = -0.2;
  g.add(neck);
  const foot = new THREE.Mesh(slab(1.25, 1.0, 0.04, 0.14, 0.015), M.standDark);
  foot.rotation.x = -Math.PI / 2; foot.position.set(0, 0.02, -0.2);
  g.add(foot);
  g.add(contactShadow(1.6, 1.35, 0.85, 14, 50));
  g.userData = { screenMat };
  return g;
}

// ---------- studio ----------
function buildEnvironment() {
  // A black studio with softboxes: gives crisp, controllable highlight strips on metal and glass.
  const env = new THREE.Scene();
  env.background = new THREE.Color(0x000000);
  const panel = (w, h, k, pos, tint = 0xffffff) => {
    const c = new THREE.Color(tint).multiplyScalar(k);
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ color: c, side: THREE.DoubleSide }));
    m.position.copy(pos); m.lookAt(0, 1, 0); env.add(m);
  };
  panel(10, 4, 3.0, new THREE.Vector3(0, 9, 1.5));            // overhead softbox
  panel(1.4, 8, 3.2, new THREE.Vector3(-8, 3, 2.5));          // left strip
  panel(1.0, 8, 4.0, new THREE.Vector3(7, 3, -5), 0xf3f6ff);  // right-back rim strip
  panel(6, 1.2, 0.9, new THREE.Vector3(2, 1.2, 9));           // low front fill (catches glass edges)
  panel(30, 30, 0.035, new THREE.Vector3(0, -6, 0));          // faint floor bounce
  const pm = new THREE.PMREMGenerator(renderer);
  const rt = pm.fromScene(env, 0.015, 0.1, 100);
  pm.dispose();
  return rt.texture;
}

// Reflector's shader, with HDR highlights compressed so a grazing glint can't blow out the floor.
const SoftReflectorShader = {
  ...Reflector.ReflectorShader,
  fragmentShader: Reflector.ReflectorShader.fragmentShader.replace(
    'vec4 base = texture2DProj( tDiffuse, vUv );',
    'vec4 base = texture2DProj( tDiffuse, vUv ); base.rgb = base.rgb / (1.0 + 2.0 * max(max(base.r, base.g), base.b));',
  ),
};

function buildFloor(scene, center = new THREE.Vector2(0, 0)) {
  const mirror = new Reflector(new THREE.PlaneGeometry(80, 80), {
    clipBias: 0.003, textureWidth: Math.round(W * 0.5), textureHeight: Math.round(H * 0.5), color: 0xb0b0b0,
    multisample: RMSAA, shader: SoftReflectorShader,
  });
  mirror.rotation.x = -Math.PI / 2;
  if (REFL) scene.add(mirror);
  const bg = BG_TM.clone();
  const overlay = new THREE.Mesh(new THREE.PlaneGeometry(80, 80), new THREE.ShaderMaterial({
    transparent: true, depthWrite: false,
    uniforms: {
      cInner: { value: new THREE.Color(0x141417) }, cOuter: { value: bg },
      center: { value: center }, r0: { value: 1.2 }, r1: { value: 9.0 },
      aInner: { value: 0.86 }, aOuter: { value: 1.0 },
    },
    vertexShader: `varying vec3 vWorld; void main(){ vec4 w = modelMatrix * vec4(position,1.0); vWorld = w.xyz; gl_Position = projectionMatrix * viewMatrix * w; }`,
    fragmentShader: `uniform vec3 cInner, cOuter; uniform vec2 center; uniform float r0, r1, aInner, aOuter; varying vec3 vWorld;
      void main(){ float d = distance(vWorld.xz, center); float k = smoothstep(r0, r1, d);
        gl_FragColor = vec4(mix(cInner, cOuter, k), mix(aInner, aOuter, k));
        #include <tonemapping_fragment>
        #include <colorspace_fragment>
      }`,
  }));
  overlay.rotation.x = -Math.PI / 2; overlay.position.y = 0.001; overlay.renderOrder = 1;
  scene.add(overlay);
  return { mirror, overlay };
}

function buildLights(scene) {
  // Specular highlights come from the softbox environment; this key only adds diffuse shaping.
  const key = new THREE.DirectionalLight(0xffffff, 1.2);
  key.position.set(-3.5, 6.5, 5.5);
  const rim = new THREE.DirectionalLight(0xeef3ff, 0.8);
  rim.position.set(5.5, 3.0, -4.5);
  const fill = new THREE.DirectionalLight(0xffffff, 0.25);
  fill.position.set(4, 1.5, 6);
  scene.add(key, rim, fill);
  return { key, rim, fill };
}

// ---------- shots (one per film beat; scene is a pure function of time) ----------
// Layout contract with the editor: the left ~38% of the frame stays dark and empty (headline text goes
// there), so the camera uses a lens shift that centres whatever the camera looks at at x = 1250 px.
const CX = 1250;
const SHIFT = -(CX - W / 2);
const TANH = Math.tan(THREE.MathUtils.degToRad(13)) * (W / H);   // tan(half horizontal fov)
const distFor = (width, frac) => width / (frac * 2 * TANH);       // distance at which `width` fills `frac` of the frame
const FRAC = 0.54;                                                // end framing: display is 54% of frame width (x 731..1769)
const e3 = easeInOutCubic, e1 = easeInOutSine;

function makeFloating(tex, { w, h, depth, corner, bezel, shell }) {
  const g = new THREE.Group();
  g.add(new THREE.Mesh(slab(w, h, depth, corner, 0.018), shell));
  const front = new THREE.Mesh(roundedPlane(w - 0.03, h - 0.03, corner - 0.012, 24), M.blackGlass);
  front.position.z = depth / 2 + 0.002; g.add(front);
  const dw = w - 2 * bezel, dh = h - 2 * bezel;
  const screenMat = screenMaterial(tex);
  const display = new THREE.Mesh(roundedPlane(dw, dh, 0.02, 8, coverCrop(tex.image.width / tex.image.height, dw / dh)), screenMat);
  display.position.z = depth / 2 + 0.0035; g.add(display);
  const glass = new THREE.Mesh(roundedPlane(w - 0.03, h - 0.03, corner - 0.012, 24), glassLayer(0.5));
  glass.position.z = depth / 2 + 0.005; glass.renderOrder = 3; g.add(onGlassLayer(glass));
  const sweep = new THREE.Mesh(roundedPlane(w - 0.03, h - 0.03, corner - 0.012, 24), sweepMaterial());
  sweep.position.z = depth / 2 + 0.006; sweep.renderOrder = 4; g.add(onGlassLayer(sweep));
  g.userData = { screenMat, sweep: sweep.material, dw };
  return g;
}
const makePanel = (tex) => makeFloating(tex, { w: 4.26, h: 2.685, depth: 0.04, corner: 0.1, bezel: 0.03, shell: M.shell });
const makeTablet = (tex) => makeFloating(tex, { w: 2.74, h: 1.78, depth: 0.05, corner: 0.16, bezel: 0.09, shell: M.titaniumShell });

let state = null;
let DUR = 6;
const fadeEl = () => document.getElementById('fade');

async function setup(shot, media, dur) {
  DUR = dur;
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(BG);
  scene.environment = buildEnvironment();
  const lights = buildLights(scene);
  const camera = new THREE.PerspectiveCamera(26, W / H, 0.05, 200);
  camera.layers.enable(GLASS_LAYER);
  camera.setViewOffset(W, H, SHIFT, 0, W, H);
  const objects = {};
  const tex = {};
  const need = {
    overview: ['overview'], devices: ['devices'], trust: ['device-drawer'], habits: ['habits'], alerts: ['alerts'],
    bedtime: ['bedtime'], privacy: ['privacy-report'], 'report-card': ['report-card', 'privacy-report', 'overview'], phone: ['phone'],
  }[shot];
  const loaded = await Promise.all(need.map((k) => loadScreen(media[k])));
  need.forEach((k, i) => { tex[k] = loaded[i]; });
  const floorCenter = new THREE.Vector2(0.4, 0);

  if (shot === 'overview' || shot === 'habits') {
    const m = makeMonitor(tex[need[0]]); scene.add(m); objects.main = m;
  } else if (shot === 'devices' || shot === 'alerts') {
    const l = makeLaptop(tex[need[0]]); l.userData.lid.rotation.x = -0.33; scene.add(l); objects.main = l;
  } else if (shot === 'trust' || shot === 'privacy') {
    const p = makePanel(tex[need[0]]); p.position.y = 1.85; scene.add(p); objects.main = p;
    const sh = contactShadow(3.6, 0.9, 0.3, 30, 50); scene.add(sh);
  } else if (shot === 'bedtime') {
    const t = makeTablet(tex.bedtime); t.position.y = 1.5; scene.add(t); objects.main = t;
    const sh = contactShadow(2.4, 0.8, 0.3, 30, 50); scene.add(sh);
  } else if (shot === 'report-card') {
    const p = makePanel(tex['report-card']); p.position.y = 1.85; scene.add(p); objects.main = p;
    const b1 = makePanel(tex['privacy-report']); b1.position.set(0.7, 2.1, -1.6); b1.userData.screenMat.color.setScalar(0.5); scene.add(b1);
    const b2 = makePanel(tex.overview); b2.position.set(1.3, 2.35, -3.2); b2.userData.screenMat.color.setScalar(0.28); scene.add(b2);
    objects.b1 = b1; objects.b2 = b2;
    scene.add(contactShadow(3.6, 0.9, 0.3, 30, 50));
  } else if (shot === 'phone') {
    const p = makePhone(tex.phone); scene.add(p); objects.main = p;
    const sh = contactShadow(0.95, 0.4, 0.35, 22, 60); scene.add(sh); objects.shadow = sh;
  }
  buildFloor(scene, floorCenter);
  state = { shot, scene, camera, lights, objects };
  return true;
}

function lookFrom(camera, pos, target) { camera.position.copy(pos); camera.lookAt(target); camera.updateMatrixWorld(); }
function orbit(target, az, el, r) {
  const pos = new THREE.Vector3(target.x + r * Math.cos(el) * Math.sin(az), target.y + r * Math.sin(el), target.z + r * Math.cos(el) * Math.cos(az));
  lookFrom(state.camera, pos, target);
}
function setSweep(g, t, a, b, strength = 0.16) {
  const s = seg(t, a, b);
  g.userData.sweep.uniforms.uPos.value = lerp(-0.35, 1.6, easeInOutSine(s));
  g.userData.sweep.uniforms.uStrength.value = strength * Math.sin(Math.PI * s);
}
// Laptop: world-space centre/normal of the display, and the camera angles that look straight at it.
function laptopFrame() {
  // whole laptop in frame (lid, keyboard and its reflection), slightly above level
  return { center: new THREE.Vector3(0, 1.0, -0.35), d: distFor(3.04, 0.5), az: 0.12, el: 0.15 };
}

function renderAt(t) {
  if (!state) throw new Error('setup() first');
  const { shot, objects, lights } = state;
  const u = clamp01(t / DUR);
  const main = objects.main;
  if (shot === 'overview') {            // monitor: arc in from the left
    const target = new THREE.Vector3(0, 1.9, 0);
    orbit(target, lerp(-0.75, 0, e3(u)), lerp(0.03, 0.06, e1(u)), lerp(14.5, distFor(4.46, FRAC), e3(u)));
  } else if (shot === 'habits') {       // monitor: arc in from the right, long and slow
    const target = new THREE.Vector3(0, 1.9, 0);
    orbit(target, lerp(0.7, 0, e1(u)), lerp(0.1, 0.04, e1(u)), lerp(13.5, distFor(4.46, FRAC), e1(u)));
  } else if (shot === 'devices') {      // laptop: high orbit that settles level
    const f = laptopFrame();
    const target = new THREE.Vector3(0, 0.6, -0.1).lerp(f.center, e3(seg(u, 0, 0.95)));
    orbit(target, lerp(0.95, f.az, e3(u)), lerp(0.4, f.el, e3(u)), lerp(10.5, f.d, e3(u)));
    main.userData.screenMat.color.setScalar(smooth(seg(t, 0.15, 0.9)));
  } else if (shot === 'alerts') {       // laptop: low crane up from the keyboard
    const f = laptopFrame();
    const target = new THREE.Vector3(0, 0.3, 0.5).lerp(f.center, e3(seg(u, 0, 0.95)));
    orbit(target, lerp(-0.5, f.az, e3(u)), lerp(0.0, f.el, e1(u)), lerp(9.2, f.d, e3(u)));
    main.userData.screenMat.color.setScalar(smooth(seg(t, 0.15, 0.9)));
  } else if (shot === 'trust' || shot === 'privacy') {   // floating panel, slow orbit
    const dir = shot === 'trust' ? 1 : -1;
    main.position.y = 1.85 + 0.015 * Math.sin(t * 0.8);
    const target = new THREE.Vector3(0, 1.85, 0);
    orbit(target, lerp(0.6 * dir, 0, e3(u)), lerp(0.12, 0.04, e1(u)), lerp(12.5, distFor(4.2, FRAC), e3(u)));
    setSweep(main, t, DUR * 0.3, DUR * 0.8, 0.12);
  } else if (shot === 'bedtime') {      // tablet floats in and settles
    const k = easeOutCubic(seg(t, 0.2, DUR * 0.85));
    main.rotation.set(lerp(-0.22, -0.02, k), lerp(0.6, 0, k), 0);
    main.position.y = 1.5 + 0.02 * Math.sin(t * 0.9);
    const target = new THREE.Vector3(0, 1.5, 0);
    orbit(target, 0, lerp(0.1, 0.04, e1(u)), lerp(9, distFor(2.56, FRAC), e3(u)));
    setSweep(main, t, DUR * 0.35, DUR * 0.8, 0.14);
  } else if (shot === 'report-card') {  // front panel with two dimmed panels stacked behind it, dolly in
    main.position.y = 1.85 + 0.012 * Math.sin(t * 0.7);
    const target = new THREE.Vector3(0.0, 1.9, 0);
    orbit(target, lerp(0.28, 0, e3(u)), lerp(0.1, 0.035, e1(u)), lerp(14.5, distFor(4.2, FRAC), e3(u)));
    setSweep(main, t, DUR * 0.35, DUR * 0.85, 0.1);
  } else if (shot === 'phone') {        // phone turns face-on, light sweeps across the glass
    const p = easeOutCubic(seg(t, 0.1, DUR * 0.85));
    main.rotation.set(lerp(-0.1, 0, p), lerp(Math.PI / 2 - 0.02, 0, p), 0);
    main.position.set(0, 1.0 + 0.01 * Math.sin(t * 0.9), 0);
    orbit(new THREE.Vector3(0, 1.0, 0), 0, lerp(0.02, 0.0, p), lerp(4.6, distFor(1.47 * 0.5625, FRAC) * 0 + 3.98, e1(u)));
    objects.shadow.position.set(0, 0.002, 0); objects.shadow.scale.set(lerp(0.25, 1, p), 1, 1);
    setSweep(main, t, DUR * 0.4, DUR * 0.9, 0.16);
  }
  // fade from / to the film background (a DOM overlay is composited into the screenshot)
  const f = Math.min(smooth(seg(t, 0, 0.4)), smooth(seg(DUR - t, 0, 0.4)));
  fadeEl().style.opacity = String(1 - f);
  state.scene.environmentIntensity = 1;
  lights.key.intensity = 1.2;
  state.renderer = renderer;
  renderer.render(state.scene, state.camera);
  return true;
}

window.__timeRender = (t, n = 3) => {
  const gl = renderer.getContext(); const px = new Uint8Array(4);
  renderAt(t); gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
  const t0 = performance.now();
  for (let i = 0; i < n; i++) { renderAt(t + i / 60); gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px); }
  return (performance.now() - t0) / n;
};
window.setup = setup;
window.renderAt = renderAt;
window.__ready = true;
