const { app, BrowserWindow, shell, Menu, session, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');

// Path to the project root. In dev mode (npm start) this is the repo root.
// In a packaged build (electron-builder, asar: false) the structure is identical under
// resources/app, so the same relative paths work in both cases.
const APP_ROOT = path.join(__dirname, '..');
const TOOLBOX_HTML = path.join(APP_ROOT, 'Toolbox.html');
const ICON_PATH = path.join(APP_ROOT, 'build', 'icon.ico');

let mainWindow = null;

function isHttpUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (err) {
        return false;
    }
}

function createWindow() {
    const windowOptions = {
        width: 1440,
        height: 920,
        minWidth: 960,
        minHeight: 640,
        backgroundColor: '#1e1e23',
        autoHideMenuBar: true, // the menu bar is hidden but reachable via the Alt key
        show: false,
        webPreferences: {
            // The tools run as local, static content and never need Node access.
            // These are safe default settings that isolate the page's JS (incl. third-party
            // libraries like jQuery/bitcoinjs/CyberChef) from the operating system.
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            spellcheck: false,
            // Required for Chromium's built-in PDF viewer (used by documentation/phantom.pdf).
            plugins: true,
        },
    };

    if (fs.existsSync(ICON_PATH)) {
        windowOptions.icon = ICON_PATH;
    }

    mainWindow = new BrowserWindow(windowOptions);

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    mainWindow.loadFile(TOOLBOX_HTML);

    // The sidebar's external links/downloads currently open via window.open() after a
    // confirmation dialog in the page itself. Let them open in the system's default browser
    // instead of in a new Electron window.
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (isHttpUrl(url)) {
            shell.openExternal(url);
        }
        return { action: 'deny' };
    });

    // Extra safety net: if some top-level attempt to navigate to an external URL should
    // slip through (e.g. a broken link), open it externally instead of leaving the app.
    mainWindow.webContents.on('will-navigate', (event, url) => {
        if (isHttpUrl(url)) {
            event.preventDefault();
            shell.openExternal(url);
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

function buildMenu() {
    const template = [
        {
            label: 'View',
            submenu: [
                {
                    label: 'Reload',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => mainWindow && mainWindow.webContents.reload(),
                },
                {
                    label: 'Force reload',
                    accelerator: 'CmdOrCtrl+Shift+R',
                    click: () => mainWindow && mainWindow.webContents.reloadIgnoringCache(),
                },
                { type: 'separator' },
                { role: 'resetZoom', label: 'Reset zoom' },
                { role: 'zoomIn', label: 'Zoom in' },
                { role: 'zoomOut', label: 'Zoom out' },
                { type: 'separator' },
                { role: 'togglefullscreen', label: 'Full screen' },
                { type: 'separator' },
                { role: 'toggleDevTools', label: 'Developer tools' },
            ],
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'Open on GitHub',
                    click: () => shell.openExternal('https://github.com/AdrianNeshad/CryptoToolbox'),
                },
                {
                    label: 'About CryptoToolbox',
                    click: () => {
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About CryptoToolbox',
                            message: 'CryptoToolbox',
                            detail: `Version ${app.getVersion()}\n\nRuns entirely locally on this computer. No internet connection is required for the tools — only for the optional GitHub downloads and external links in the sidebar.`,
                        });
                    },
                },
            ],
        },
    ];

    Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// Same AppUserModelID as "appId" in the electron-builder configuration. Makes
// Windows associate the window with the Start-menu shortcut so the correct icon is used
// in the taskbar, even when the app is pinned there.
app.setAppUserModelId('se.adrianneshad.cryptotoolbox');

app.whenReady().then(() => {
    // Show a "Save as" dialog for downloads (e.g. the GitHub zip files in the sidebar)
    // instead of silently saving them to the default downloads folder.
    session.defaultSession.on('will-download', (_event, item) => {
        item.setSaveDialogOptions({ defaultPath: item.getFilename() });
    });

    buildMenu();
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
