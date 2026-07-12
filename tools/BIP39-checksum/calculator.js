const hexToBinaryString = {
    '0': '0000', '1': '0001', '2': '0010', '3': '0011',
    '4': '0100', '5': '0101', '6': '0110', '7': '0111',
    '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
    'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111',
}

// Konfiguration för olika seedphrase-typer
const seedConfig = {
    bip39_12: {
        name: 'BIP39 (12 words)',
        inputWords: 11,
        totalWords: 12,
        entropyBits: 128,
        checksumBits: 4,
        lastWordBits: 7,  // Sista ordet behöver 7 bits entropi + 4 bits checksum
        checksumHexChars: 1,
        checksumBitSlice: [0, 4]
    },
    bip39_24: {
        name: 'BIP39 (24 words)',
        inputWords: 23,
        totalWords: 24,
        entropyBits: 256,
        checksumBits: 8,
        lastWordBits: 3,  // Sista ordet behöver 3 bits entropi + 8 bits checksum
        checksumHexChars: 2,
        checksumBitSlice: [0, 8]
    },
    polyseed_16: {
        name: 'Polyseed Monero (16 words)',
        inputWords: 15,
        totalWords: 16,
        entropyBits: 172,  // Polyseed använder 172 bits entropi
        checksumBits: 4,
        lastWordBits: 7,   // Sista ordet behöver 7 bits entropi + 4 bits checksum
        checksumHexChars: 1,
        checksumBitSlice: [0, 4]
    }
}

/*
  Calculate the SHA-256 hash of a binary value, given as a form of binary string.
*/
const sha256 = async binaryString => {
    // Convert binary string to bytes
    const byteArray = new Uint8Array(binaryString.length / 8)
    for (let i = 0; i < binaryString.length; i += 8) {
        const byte = binaryString.substring(i, i + 8)
        byteArray[i / 8] = parseInt(byte, 2)
    }

    // Calculate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', byteArray)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(byte => ('00' + byte.toString(16)).slice(-2)).join('')
    return hashHex
}

const asDecimal = validWords => {
    const indices = []
    validWords.forEach(validWord => {
        const found = bipWords.indexOf(validWord)
        if (found >= 0) indices.push(found)
    })
    return indices
}

const asBinary = validWords => asDecimal(validWords).map(d => {
    let b = (d).toString(2)
    while (b.length < 11) b = `0${b}`
    return b
})

const calculateCandidates = async (validWords, config) => {
    const candidates = []
    const maxIterations = config.lastWordBits === 0 ? 1 : Math.pow(2, config.lastWordBits)

    for (let i = 0; i < maxIterations; i++) {
        let entropy = asBinary(validWords).join('')
        let b = ''

        // Endast skapa bits om lastWordBits > 0
        if (config.lastWordBits > 0) {
            b = (i).toString(2)
            while (b.length < config.lastWordBits) b = `0${b}`
            entropy += b
        }

        // Truncate entropi till rätt längd
        entropy = entropy.substring(0, config.entropyBits)

        // Beräkna checksumman
        const checksum = await sha256(entropy)

        // Extrahera checksumbitarna som hex
        const checksumHex = checksum.substring(0, config.checksumHexChars)
        let checksumBinary = ''
        for (let char of checksumHex) {
            checksumBinary += hexToBinaryString[char]
        }

        // Ta rätt antal checksumbitar
        const checksumBits = checksumBinary.substring(config.checksumBitSlice[0], config.checksumBitSlice[1])

        // Kombinera entropi och checksumbitar för ordet
        const wordBits = b + checksumBits

        // Hitta matchande ord
        bipWords.forEach((bipWord, idx) => {
            let wordIndex = (idx).toString(2)
            while (wordIndex.length < 11) wordIndex = `0${wordIndex}`
            if (wordIndex === wordBits) candidates.push(bipWord)
        })
    }
    return candidates
}

const run = async (inputWords, seedType) => {
    if ((inputWords || []).length === 0) return []

    const config = seedConfig[seedType]
    if (!config) return Promise.reject('Ogiltigt seed-typ')

    const validWords = []
    const wrongWords = []
    inputWords.forEach(word => {
        if (bipWords.includes(word)) validWords.push(word)
        else wrongWords.push(word)
    })

    if (wrongWords.length > 0) {
        return Promise.reject(`${wrongWords.join(', ')} are not BIP-39 words. Make sure you only use valid BIP-39 words.`)
    }

    if ((validWords || []).length !== config.inputWords) {
        return Promise.reject(`Input ${config.inputWords} words. You have input ${validWords.length} valid words.`)
    }

    return (await calculateCandidates(validWords, config))
}