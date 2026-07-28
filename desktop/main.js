const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");

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

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForBackend(port, timeoutMilliseconds = 45000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() < deadline) {
    const available = await new Promise((resolve) => {
      const request = http.get(
        { hostname: "127.0.0.1", port, path: "/health", timeout: 1500 },
        (response) => {
          response.resume();
          resolve(response.statusCode >= 200 && response.statusCode < 500);
        },
      );
      request.on("timeout", () => {
        request.destroy();
        resolve(false);
      });
      request.on("error", () => resolve(false));
    });
    if (available) return;
    if (backendProcess === null) throw new Error("The Home Radar backend exited during startup.");
    await delay(250);
  }
  throw new Error("The Home Radar backend did not become ready within 45 seconds.");
}

function getBackendExecutablePath() {
  const executable = process.platform === "win32" ? "homeradar-backend.exe" : "homeradar-backend";
  return app.isPackaged
    ? path.join(process.resourcesPath, executable)
    : path.join(__dirname, "resources", executable);
}

function stopBackend() {
  if (!backendProcess || backendProcess.killed) {
    backendProcess = null;
    backendPort = null;
    return;
  }
  try {
    backendProcess.kill(process.platform === "win32" ? undefined : "SIGTERM");
  } catch (error) {
    console.error("Could not stop backend", error);
  }
  backendProcess = null;
  backendPort = null;
}

async function startBackend() {
  if (backendProcess && backendPort) {
    await waitForBackend(backendPort, 5000);
    return;
  }

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

  const selectedPort = backendPort;
  backendProcess = spawn(backendPath, [], {
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  const spawnedProcess = backendProcess;
  spawnedProcess.stdout?.on("data", (data) => console.log(`[backend] ${data}`));
  spawnedProcess.stderr?.on("data", (data) => console.error(`[backend] ${data}`));
  spawnedProcess.on("error", (error) => console.error("Backend process failed", error));
  spawnedProcess.on("exit", (code, signal) => {
    console.log(`Backend exited with code ${code} and signal ${signal}`);
    if (backendProcess === spawnedProcess) {
      backendProcess = null;
      backendPort = null;
    }
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.loadFile(path.join(__dirname, "error.html"));
    }
  });

  await waitForBackend(selectedPort);
}

async function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
    return;
  }

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
    if (!quitting) stopBackend();
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
    } else {
      createWindow();
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
