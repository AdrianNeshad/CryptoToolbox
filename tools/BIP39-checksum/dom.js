const getDOM = {
    typeSelector: () => document.querySelector('select#seedType'),
    textarea: () => document.querySelector('textarea'),
    validation: () => document.querySelector('.validation'),
    result: () => document.querySelector('.result'),
}

const randomElevenWords = (count = 11) => {
    const result = []
    for (let i = 0; i < count; i++) {
        const randomIndex = Math.floor(Math.random() * bipWords.length)
        result.push(bipWords[randomIndex])
    }
    return result
}

const resetValidation = () => {
    getDOM.validation().innerHTML = ''
    getDOM.validation().classList.add('display-none')
}

const getSeedType = () => {
    return getDOM.typeSelector().value || 'bip39_12'
}

const updatePlaceholder = () => {
    const seedType = getSeedType()
    const config = seedConfig[seedType]
    getDOM.textarea().placeholder = `Type ${config.inputWords} words, separated by spaces`
}

const onClickGenerate = async () => {
    const seedType = getSeedType()
    const config = seedConfig[seedType]
    const parsedUserInput = (getDOM.textarea().value || '').split(' ').filter(w => w)

    try {
        const result = await run(parsedUserInput, seedType)
        getDOM.result().querySelector('.list').textContent = result.join(' ')
        const wordLabel = result.length === 1 ? 'word' : 'words'
        getDOM.result().querySelector('.title').textContent = `✅ ${result.length} available ${wordLabel} for ${config.inputWords + 1}th word:`
        if (result.length === 0) getDOM.result().classList.add('display-none')
        else getDOM.result().classList.remove('display-none')
    } catch (e) {
        getDOM.validation().innerHTML = `❌ ${e}`
        getDOM.validation().classList.remove('display-none')
        getDOM.result().classList.add('display-none')
    }
}

const onInput = () => {
    resetValidation()
    onClickGenerate()
}

const onSeedTypeChange = () => {
    const seedType = getSeedType()
    const config = seedConfig[seedType]
    updatePlaceholder()

    // Generate new random words based on type
    getDOM.textarea().value = randomElevenWords(config.inputWords).join(' ')
    onClickGenerate()
}

document.addEventListener('DOMContentLoaded', () => {
    const seedType = getSeedType()
    const config = seedConfig[seedType]
    updatePlaceholder()
    getDOM.textarea().value = randomElevenWords(config.inputWords).join(' ')
    onClickGenerate()
})

// --- Theme sync with CryptoToolbox (postMessage from parent iframe) ---
window.addEventListener('message', function (event) {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.source === 'cryptotoolbox' && data.type === 'theme' &&
        (data.theme === 'light' || data.theme === 'dark')) {
        document.documentElement.setAttribute('data-theme', data.theme);
        try { localStorage.setItem('theme', data.theme); } catch (e) { /* ignored */ }
    }
});