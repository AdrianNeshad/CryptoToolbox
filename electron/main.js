const { app, BrowserWindow, shell, Menu, session, dialog } = require('electron');
const path = require('node:path');
const fs = require('node:fs');

// Sökväg till projektroten. I dev-läge (npm start) är detta repo-roten.
// I ett paketerat bygge (electron-builder, asar: false) är strukturen identisk under
// resources/app, så samma relativa sökvägar fungerar i båda fallen.
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
        autoHideMenuBar: true, // menyraden döljs men nås via Alt-tangenten
        show: false,
        webPreferences: {
            // Verktygen körs som lokalt, statiskt innehåll och behöver aldrig Node-åtkomst.
            // Det här är säkra standardinställningar som isolerar sidans JS (inkl. tredjeparts-
            // bibliotek som jQuery/bitcoinjs/CyberChef) från operativsystemet.
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            spellcheck: false,
            // Krävs för Chromiums inbyggda PDF-visare (används av documentation/phantom.pdf).
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

    // Sidopanelens externa länkar/nedladdningar öppnas idag via window.open() efter en
    // bekräftelsedialog i sidan själv. Låt dem öppnas i systemets standardwebbläsare
    // istället för i ett nytt Electron-fönster.
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        if (isHttpUrl(url)) {
            shell.openExternal(url);
        }
        return { action: 'deny' };
    });

    // Extra skyddsnät: om något top-level-försök att navigera till en extern URL skulle
    // slinka igenom (t.ex. en trasig länk), öppna den externt istället för att lämna appen.
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
            label: 'Visa',
            submenu: [
                {
                    label: 'Ladda om',
                    accelerator: 'CmdOrCtrl+R',
                    click: () => mainWindow && mainWindow.webContents.reload(),
                },
                {
                    label: 'Tvinga omladdning',
                    accelerator: 'CmdOrCtrl+Shift+R',
                    click: () => mainWindow && mainWindow.webContents.reloadIgnoringCache(),
                },
                { type: 'separator' },
                { role: 'resetZoom', label: 'Återställ zoom' },
                { role: 'zoomIn', label: 'Zooma in' },
                { role: 'zoomOut', label: 'Zooma ut' },
                { type: 'separator' },
                { role: 'togglefullscreen', label: 'Helskärm' },
                { type: 'separator' },
                { role: 'toggleDevTools', label: 'Utvecklarverktyg' },
            ],
        },
        {
            label: 'Hjälp',
            submenu: [
                {
                    label: 'Öppna på GitHub',
                    click: () => shell.openExternal('https://github.com/AdrianNeshad/CryptoToolbox'),
                },
                {
                    label: 'Om Verktygslådan',
                    click: () => {
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'Om Verktygslådan',
                            message: 'Verktygslådan',
                            detail: `Version ${app.getVersion()}\n\nKörs helt lokalt på den här datorn. Ingen internetanslutning krävs för verktygen — endast för de valfria GitHub-nedladdningarna och externa länkarna i sidopanelen.`,
                        });
                    },
                },
            ],
        },
    ];

    Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// Samma AppUserModelID som "appId" i electron-builder-konfigurationen. Gör att
// Windows kopplar fönstret till startmeny-genvägen så att rätt ikon används
// i aktivitetsfältet, även när appen är fäst där.
app.setAppUserModelId('se.adrianneshad.verktygslada');

app.whenReady().then(() => {
    // Visa en "Spara som"-dialog för nedladdningar (t.ex. GitHub-zip-filerna i sidopanelen)
    // istället för att tyst spara dem i standardmappen för nedladdningar.
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
