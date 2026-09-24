(function () {
    'use strict';

    /**
     * CyberChef reads ?theme= from the URL as its own theme name (classic/dark/…).
     * The toolbox sends light/dark on that same parameter — "light" is not a valid
     * CyberChef theme, so CyberChef falls back to the OS prefers-color-scheme
     * (often dark). Rewrite light → classic before CyberChef boots, and follow the
     * toolbox's live theme toggle via postMessage.
     */
    function chefTheme(toolboxTheme) {
        return toolboxTheme === 'light' ? 'classic' : 'dark';
    }

    function readToolboxTheme() {
        try {
            var params = new URLSearchParams(location.search);
            var t = params.get('theme');
            if (t === 'light' || t === 'classic' || t === 'solarizedLight') return 'light';
            if (t === 'dark' || t === 'solarizedDark' || t === 'geocities') return 'dark';
        } catch (e) { /* ignored */ }
        try {
            var saved = localStorage.getItem('theme');
            if (saved === 'light' || saved === 'dark') return saved;
        } catch (e) { /* ignored */ }
        return 'dark';
    }

    function writeChefOptions(theme) {
        try {
            var opts = {};
            try { opts = JSON.parse(localStorage.getItem('options')) || {}; } catch (e) { opts = {}; }
            if (typeof opts !== 'object' || !opts) opts = {};
            opts.theme = theme;
            localStorage.setItem('options', JSON.stringify(opts));
        } catch (e) { /* localStorage may be disabled */ }
    }

    function rewriteChefThemeParam(theme) {
        try {
            var url = new URL(location.href);
            if (url.searchParams.get('theme') === theme) return;
            url.searchParams.set('theme', theme);
            history.replaceState(null, '', url.pathname + url.search + url.hash);
        } catch (e) { /* file:// or sandbox */ }
    }

    function paint(theme) {
        try { document.documentElement.className = theme; } catch (e) { /* ignored */ }
        var select = document.getElementById('theme');
        if (!select) return;
        try { select.value = theme; } catch (e) { /* ignored */ }
        if (typeof window.app === 'undefined') return;
        try { select.dispatchEvent(new Event('change', { bubbles: true })); } catch (e) { /* ignored */ }
    }

    function applyChefTheme(toolboxTheme) {
        var theme = chefTheme(toolboxTheme);
        writeChefOptions(theme);
        rewriteChefThemeParam(theme);
        paint(theme);
    }

    applyChefTheme(readToolboxTheme());

    document.addEventListener('DOMContentLoaded', function () {
        paint(chefTheme(readToolboxTheme()));
    });

    window.addEventListener('message', function (event) {
        if (event.source !== window.parent) return;
        var data = event.data;
        if (!data || data.source !== 'cryptotoolbox') return;
        if (data.type === 'theme' && (data.theme === 'light' || data.theme === 'dark')) {
            applyChefTheme(data.theme);
        }
    });
})();
