const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const net = require("net");
const path = require("path");
const waitOn = require("wait-on");

let backendProcess = null;
let mainWindow = null;
let backendPort = null;
let quitting = false;

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function getBackendExecutablePath() {
  const executable = process.platform === "win32" ? "homeradar-backend.exe" : "homeradar-backend";
  return app.isPackaged
    ? path.join(process.resourcesPath, executable)
    : path.join(__dirname, "resources", executable);
}

function stopBackend() {
  if (!backendProcess || backendProcess.killed) return;
  try {
    backendProcess.kill(process.platform === "win32" ? undefined : "SIGTERM");
  } catch (error) {
    console.error("Could not stop backend", error);
  }
  backendProcess = null;
}

async function startBackend() {
  const backendPath = getBackendExecutablePath();
  if (!fs.existsSync(backendPath)) {
    throw new Error(`The bundled Home Radar backend is missing: ${backendPath}`);
  }

  backendPort = await getFreePort();
  const dataDirectory = app.getPath("userData");
  const environment = {
    ...process.env,
    HOMERADAR_API_HOST: "127.0.0.1",
    HOMERADAR_API_PORT: String(backendPort),
    HOMERADAR_DATA_DIR: dataDirectory,
    HOMERADAR_DB_PATH: path.join(dataDirectory, "homeradar.db"),
    HOMERADAR_BACKUP_DIR: path.join(dataDirectory, "backups"),
    HOMERADAR_DNS_ENABLED: "false",
    HOMERADAR_TRAFFIC_MONITOR_ENABLED: "false",
    HOMERADAR_BLOCKLIST_AUTO_UPDATE: "true",
    PYTHONUNBUFFERED: "1",
  };

  backendProcess = spawn(backendPath, [], {
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  backendProcess.stdout?.on("data", (data) => console.log(`[backend] ${data}`));
  backendProcess.stderr?.on("data", (data) => console.error(`[backend] ${data}`));
  backendProcess.on("error", (error) => console.error("Backend process failed", error));
  backendProcess.on("exit", (code, signal) => {
    console.log(`Backend exited with code ${code} and signal ${signal}`);
    backendProcess = null;
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.loadFile(path.join(__dirname, "error.html"));
    }
  });

  await waitOn({
    resources: [`http-get://127.0.0.1:${backendPort}/health`],
    timeout: 45000,
    interval: 250,
    validateStatus: (status) => status >= 200 && status < 500,
  });
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 940,
    minHeight: 650,
    title: "Home Radar",
    backgroundColor: "#020806",
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
  });

  mainWindow.removeMenu();
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://github.com/MaxDoubin/HomeRadar")) shell.openExternal(url);
    return { action: "deny" };
  });
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const allowed = `http://127.0.0.1:${backendPort}`;
    if (!url.startsWith(allowed)) event.preventDefault();
  });
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  try {
    await startBackend();
    await mainWindow.loadURL(`http://127.0.0.1:${backendPort}`);
  } catch (error) {
    console.error("Home Radar startup failed", error);
    await mainWindow.loadFile(path.join(__dirname, "error.html"));
    mainWindow.show();
    dialog.showErrorBox("Home Radar could not start", error.message);
  }
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(createWindow);

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  quitting = true;
  stopBackend();
});

process.on("exit", stopBackend);
