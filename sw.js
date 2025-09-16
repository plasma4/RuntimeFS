const DBN = "FileCacheDB"
const SN = "Folders"
const META_SN = "Metadata"
const DB_VERSION = 1
const CACHE_NAME = 'fc'
const APP_SHELL_FILES = ['/', '/index.php', '/index.html', '/main.js']

let dbPromise = null
const folderCache = new Map()
// Manages in-flight promises to prevent concurrent DB requests for the same folder.
const folderLoadingPromises = new Map()

function getDb() {
    if (!dbPromise) {
        dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DBN, DB_VERSION)
            request.onupgradeneeded = event => {
                const db = event.target.result
                if (!db.objectStoreNames.contains(SN)) db.createObjectStore(SN, { keyPath: "id" })
                if (!db.objectStoreNames.contains(META_SN)) db.createObjectStore(META_SN, { keyPath: "id" })
            }
            request.onsuccess = event => resolve(event.target.result)
            request.onerror = event => reject(event.target.error)
        })
    }
    return dbPromise
}

self.addEventListener('install', event => {
    event.waitUntil((async () => {
        const cache = await caches.open(CACHE_NAME)
        const promises = APP_SHELL_FILES.map(async (url) => {
            try {
                const response = await fetch(url)
                if (response.ok) {
                    await cache.put(url, response)
                } else {
                    console.warn(`Skipping cache for ${url} - Status: ${response.status}`)
                }
            } catch (error) {
                console.warn(`Skipping cache for ${url} - Fetch failed:`, error)
            }
        })
        await Promise.all(promises)
        await self.skipWaiting()
    })())
})

self.addEventListener('activate', event => {
    event.waitUntil(getDb().then(() => caches.keys().then(keys => Promise.all(keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null)))).then(() => self.clients.claim()))
})

self.addEventListener("fetch", event => {
    const url = new URL(event.request.url)
    if (url.origin !== self.location.origin) return

    event.respondWith((async () => {
        // First, check if the request is for one of the core application files...
        if (APP_SHELL_FILES.includes(url.pathname)) {
            const cachedResponse = await caches.match(event.request)
            return cachedResponse || fetch(event.request)
        }

        // Second, check if it's a request for a virtual file.
        if (url.pathname.startsWith('/n/')) {
            const pathParts = url.pathname.split('/').slice(2)
            const rules = url.searchParams.get('rules')
            return generateResponseForVirtualFile(pathParts[0], pathParts.slice(1).join('/'), rules ? decodeURIComponent(rules) : null)
        }

        // Third, handle root-relative asset requests from within a virtual folder.
        const referer = event.request.referrer
        if (referer) {
            const refererUrl = new URL(referer)
            if (refererUrl.origin === self.location.origin && refererUrl.pathname.startsWith('/n/')) {
                const pathParts = refererUrl.pathname.split('/').slice(2)
                const rules = refererUrl.searchParams.get('rules')
                return generateResponseForVirtualFile(pathParts[0], url.pathname.substring(1), rules ? decodeURIComponent(rules) : null)
            }
        }

        // For any other request, just fetch it from the network.
        return fetch(event.request)
    })())
})

function getFolderData(folderName) {
    if (folderCache.has(folderName)) {
        return Promise.resolve(folderCache.get(folderName))
    }

    // Check if another request is already loading this folder. If so, wait for it to finish.
    if (folderLoadingPromises.has(folderName)) {
        return folderLoadingPromises.get(folderName)
    }

    const loadingPromise = (async () => {
        try {
            const db = await getDb()
            // The transaction must include both object stores it intends to read from
            const transaction = db.transaction([SN, META_SN], "readonly")

            const manifest = (await promisifyRequest(transaction.objectStore(META_SN).get('folderManifest')))?.data || {}
            const folderId = manifest[folderName] || folderName
            const folderData = await promisifyRequest(transaction.objectStore(SN).get(folderId))

            if (folderData) {
                folderCache.set(folderName, folderData) // Populate the cache for next time.
            }
            return folderData
        } finally {
            folderLoadingPromises.delete(folderName)
        }
    })()

    folderLoadingPromises.set(folderName, loadingPromise)
    return loadingPromise
}

async function generateResponseForVirtualFile(folderName, requestedFilePath, rules) {
    const decodedFolderName = decodeURIComponent(folderName)
    let decodedFilePath = decodeURIComponent(requestedFilePath)

    const folderData = await getFolderData(decodedFolderName)

    if (!folderData || !folderData.files) {
        console.error(`[SW] FAILURE: No data for folder "${decodedFolderName}".`)
        return new Response(`Folder '${decodedFolderName}' not found.`, { status: 404 })
    }

    if (!decodedFilePath) {
        if (folderData.files['index.html']) {
            decodedFilePath = 'index.html'
        } else if (folderData.files['index.php']) {
            decodedFilePath = 'index.php'
        }
    }

    let fileData = folderData.files[decodedFilePath]
    let foundPath = decodedFilePath

    if (!fileData) {
        const matchingPath = Object.keys(folderData.files).find(p => p.endsWith(decodedFilePath))
        if (matchingPath) {
            fileData = folderData.files[matchingPath]
            foundPath = matchingPath
        }
    }

    if (!fileData) {
        console.error(`[SW] No file match for "${decodedFilePath}".`)
        return new Response(`File not found: ${decodedFilePath}`, { status: 404 })
    }

    const contentType = fileData.type || getMimeType(foundPath) || "application/octet-stream"
    const modifiedBuffer = applyRegexRules(foundPath, fileData.buffer, contentType, rules)

    return new Response(modifiedBuffer, { headers: { "Content-Type": contentType } })
}

function getMimeType(filePath) {
    const ext = filePath.split('.').pop().toLowerCase()
    const mimeTypes = {
        'html': 'text/html', 'htm': 'text/html', 'css': 'text/css', 'js': 'application/javascript',
        'mjs': 'application/javascript', 'json': 'application/json', 'xml': 'application/xml',
        'txt': 'text/plain', 'md': 'text/markdown', 'csv': 'text/csv', 'rtf': 'application/rtf',
        'ico': 'image/x-icon', 'bmp': 'image/bmp', 'gif': 'image/gif', 'jpeg': 'image/jpeg',
        'jpg': 'image/jpeg', 'png': 'image/png', 'svg': 'image/svg+xml', 'tif': 'image/tiff',
        'tiff': 'image/tiff', 'webp': 'image/webp', 'avif': 'image/avif',
        'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg', 'weba': 'audio/webm',
        'mp4': 'video/mp4', 'webm': 'video/webm', 'mpeg': 'video/mpeg',
        'pdf': 'application/pdf', 'zip': 'application/zip', 'gz': 'application/gzip',
        'rar': 'application/vnd.rar', 'tar': 'application/x-tar', '7z': 'application/x-7z-compressed',
        'woff': 'font/woff', 'woff2': 'font/woff2', 'ttf': 'font/ttf', 'otf': 'font/otf',
        'eot': 'application/vnd.ms-fontobject', 'wasm': 'application/wasm'
    }
    return mimeTypes[ext]
}

function promisifyRequest(req) {
    return new Promise((r, j) => {
        req.onsuccess = () => r(req.result)
        req.onerror = () => j(req.error)
    })
}

function applyRegexRules(filePath, fileBuffer, fileType, regexRules) {
    if (!regexRules || !regexRules.trim()) {
        return fileBuffer
    }

    const isTextBased = !/^(image|audio|video|font|application\/(octet-stream|pdf|zip|wasm))/.test(fileType)
    if (!isTextBased) {
        return fileBuffer
    }

    try {
        let content = new TextDecoder().decode(fileBuffer)
        const rules = regexRules.trim().split('\n')

        for (const line of rules) {
            const [fileMatchPart, replacePart] = line.split('|').map(s => s.trim())
            if (!fileMatchPart || !replacePart) continue

            const [searchRegexStr, replacement] = replacePart.split('->').map(s => s.trim())
            if (searchRegexStr === undefined || replacement === undefined) continue

            const fileRegex = new RegExp(fileMatchPart === '*' ? '.*' : fileMatchPart)

            if (fileRegex.test(filePath)) {
                const searchRegex = new RegExp(searchRegexStr, 'g')
                content = content.replace(searchRegex, replacement)
            }
        }
        return new TextEncoder().encode(content).buffer
    } catch (e) {
        console.error("Error applying regex:", e)
        return fileBuffer
    }
}