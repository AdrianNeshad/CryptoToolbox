// Service worker for the Chrome extension build.
//
// The extension has no popup: clicking the toolbar icon opens the full CryptoToolbox
// UI (Toolbox.html) in a normal browser tab.
//
// This deliberately requires ZERO permissions — chrome.tabs.create on the extension's
// own page needs neither the "tabs" permission nor any host permission, which keeps the
// Chrome Web Store review simple (nothing to justify) and matches the app's "runs fully
// offline, asks for nothing" promise.

chrome.action.onClicked.addListener(() => {
    chrome.tabs.create({ url: chrome.runtime.getURL('Toolbox.html') });
});
