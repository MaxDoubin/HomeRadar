const { app, BrowserWindow, dialog, shell } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");

let backendProcess = null;
let mainWindow = null;
let backendPort = null;
let backendLogPath = null;
let backendLogStream = null;
let backendOutput = [];
let backendExitDescription = "";
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

function recordBackendOutput(prefix, data) {
  const text = `${prefix}${String(data)}`;
  backendOutput.push(text);
  if (backendOutput.length > 120) backendOutput = backendOutput.slice(-120);
  backendLogStream?.write(text);
}

function getBackendDiagnosticText(error) {
  const details = backendOutput.join("").trim();
  const pieces = [error?.message, backendExitDescription, details].filter(Boolean);
  return pieces.join("\n\n").slice(-12000) || "The backend exited without producing diagnostic output.";
}

async function showStartupError(error) {
  const query = {
    message: error?.message || "The Home Radar backend could not start.",
    details: getBackendDiagnosticText(error),
    logPath: backendLogPath || "No log file was created.",
  };
  await mainWindow.loadFile(path.join(__dirname, "error.html"), { query });
  mainWindow.show();
  dialog.showErrorBox("Home Radar could not start", `${query.message}\n\nLog: ${query.logPath}`);
}

async function waitForBackend(port, timeoutMilliseconds = 120000) {
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
    if (backendProcess === null) {
      throw new Error(backendExitDescription || "The Home Radar backend exited during startup.");
    }
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

function closeBackendLog() {
  if (backendLogStream) {
    backendLogStream.end();
    backendLogStream = null;
  }
}

function stopBackend() {
  if (!backendProcess || backendProcess.killed) {
    backendProcess = null;
    backendPort = null;
    closeBackendLog();
    return;
  }
  try {
    backendProcess.kill(process.platform === "win32" ? undefined : "SIGTERM");
  } catch (error) {
    console.error("Could not stop backend", error);
  }
  backendProcess = null;
  backendPort = null;
  closeBackendLog();
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
  fs.mkdirSync(dataDirectory, { recursive: true });
  backendLogPath = path.join(dataDirectory, "backend.log");
  backendLogStream = fs.createWriteStream(backendLogPath, { flags: "a" });
  backendLogStream.write(`\n\n=== Home Radar startup ${new Date().toISOString()} ===\n`);
  backendOutput = [];
  backendExitDescription = "";

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
  spawnedProcess.stdout?.on("data", (data) => {
    recordBackendOutput("[stdout] ", data);
    console.log(`[backend] ${data}`);
  });
  spawnedProcess.stderr?.on("data", (data) => {
    recordBackendOutput("[stderr] ", data);
    console.error(`[backend] ${data}`);
  });
  spawnedProcess.on("error", (error) => {
    backendExitDescription = `Backend process failed: ${error.message}`;
    recordBackendOutput("[process error] ", `${error.stack || error.message}\n`);
  });
  spawnedProcess.on("exit", (code, signal) => {
    backendExitDescription = `Backend exited with code ${code ?? "unknown"} and signal ${signal ?? "none"}.`;
    recordBackendOutput("[process] ", `${backendExitDescription}\n`);
    if (backendProcess === spawnedProcess) {
      backendProcess = null;
      backendPort = null;
    }
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) {
      showStartupError(new Error(backendExitDescription)).catch(console.error);
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
    if (!url.startsWith(allowed) && !url.startsWith("file://")) event.preventDefault();
  });
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
    if (!quitting) stopBackend();
  });

  // Show a loading screen immediately rather than leaving the window hidden for
  // the whole backend cold-start. A frozen PyInstaller backend can genuinely take
  // tens of seconds to unpack and boot -- especially on the older/slower repurposed
  // hardware this project targets -- and a fully invisible window for that whole
  // stretch reads as "the app didn't open" rather than "it's starting."
  await mainWindow.loadFile(path.join(__dirname, "loading.html"));
  mainWindow.show();

  try {
    await startBackend();
    await mainWindow.loadURL(`http://127.0.0.1:${backendPort}`);
  } catch (error) {
    console.error("Home Radar startup failed", error);
    await showStartupError(error);
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
