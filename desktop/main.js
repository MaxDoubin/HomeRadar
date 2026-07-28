const net = require('net');
function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close(() => {
        resolve(port);
      });
    });
  });
}
const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const waitOn = require('wait-on');
const fs = require('fs');

let backendProcess = null;
let mainWindow = null;

function getBackendExecutablePath() {
  const isWindows = process.platform === 'win32';
  const execName = isWindows ? 'homeradar-backend.exe' : 'homeradar-backend';

  if (app.isPackaged) {
    return path.join(process.resourcesPath, execName);
  } else {
    return path.join(__dirname, 'resources', execName);
  }
}

async function startBackend() {
  const backendPath = getBackendExecutablePath();
  console.log(`Starting backend at ${backendPath}`);

  if (!fs.existsSync(backendPath)) {
    console.error(`Backend executable not found at ${backendPath}`);
  }

  global.backendPort = await getFreePort();

  const env = Object.assign({}, process.env, {
    HOMERADAR_API_PORT: global.backendPort.toString(),
    HOMERADAR_DATA_DIR: app.getPath('userData'),
    HOMERADAR_DB_PATH: path.join(app.getPath('userData'), 'homeradar.db')
  });

  backendProcess = spawn(backendPath, [], {
    env: env,
    stdio: 'inherit'
  });

  backendProcess.on('error', (err) => {
    console.error('Failed to start backend process.', err);
  });

  backendProcess.on('exit', (code, signal) => {
    console.log(`Backend process exited with code ${code} and signal ${signal}`);
  });
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'Home Radar',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  const url = `http://127.0.0.1:${global.backendPort}`;
  const waitOnOptions = {
    resources: [url],
    timeout: 30000,
  };

  try {
    await waitOn(waitOnOptions);
    console.log('Backend is up, loading window');
    mainWindow.loadURL(url);
  } catch (err) {
    console.error('Timeout waiting for backend to start', err);
    mainWindow.loadFile('error.html');
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  await startBackend();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  if (backendProcess) {
    backendProcess.kill();
  }
});
