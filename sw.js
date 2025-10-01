// A map to temporarily store regex rules sent from the main thread.
// Rules are associated with a requestId to be applied to a specific fetch.
// They are automatically deleted after 30 seconds to prevent memory leaks.
const ruleStore = new Map()

// A map to temporarily store decryption keys for password-protected folders.
// The key is passed from the main thread just before the fetch request.
// It's also cleared after 30 seconds.
const decryptionKeyStore = new Map()

// Listen for messages from the main application thread.
self.addEventListener("message", e => {
    if (e.data && e.data.type === "REGRULES") {
        // Store regex rules for an upcoming request.
        ruleStore.set(e.data.requestId, e.data.rules)
        setTimeout(() => ruleStore.delete(e.data.requestId), 30000)
    } else if (e.data && e.data.type === "INVALIDATE_CACHE") {
        // When a folder is updated, the main thread asks to invalidate the in-memory cache.
        const folderName = e.data.folderName
        if (folderName) {
            console.log(`Invalidating cache in ServiceWorker for: ${folderName}`)
            folderCache.delete(folderName)
            if (e.source) {
                e.source.postMessage({ type: 'CACHE_INVALIDATED', folderName: folderName })
            }
        }
    } else if (e.data && e.data.type === "DECRYPT_KEY") {
        // Store a decryption key for an upcoming request for an encrypted file.
        decryptionKeyStore.set(e.data.requestId, e.data.key)
        setTimeout(() => decryptionKeyStore.delete(e.data.requestId), 30000)
    } else if (e.data && e.data.type === 'SYNC_AND_OPEN') {
        const { folderName, updates, fileToOpen } = e.data

        // Use event.waitUntil to keep the service worker alive while we do async work
        e.waitUntil((async () => {
            try {
                // 1. Update IndexedDB
                const db = await getDb()
                const transaction = db.transaction([SN], "readwrite")
                const store = transaction.objectStore(SN)
                const folderData = await promisifyRequest(store.get(folderName))

                if (folderData) {
                    for (const update of updates) {
                        if (update.type === "update") {
                            folderData.files[update.path] = update.data
                        } else if (update.type === "delete") {
                            delete folderData.files[update.path]
                        }
                    }
                    store.put(folderData)
                }
                await promisifyTransaction(transaction)
                console.log(`Service Worker successfully synced ${updates.length} changes.`)

                // 2. Invalidate the in-memory cache
                folderCache.delete(folderName)
                console.log(`Service Worker invalidated its own cache for: ${folderName}`)

                // 3. Open the new window
                const urlToOpen = `/n/${encodeURIComponent(folderName)}/${encodeURIComponent(fileToOpen)}?v=${Date.now()}`
                await self.clients.openWindow(urlToOpen)

            } catch (err) {
                console.error("Error during SYNC_AND_OPEN operation in Service Worker:", err)
            }
        })())
    }
})

// Constants for IndexedDB database and object stores.
const DBN = "FileCacheDB"
const SN = "Folders"
const META_SN = "Metadata"
const DB_VERSION = 1

// Name for the cache used to store the application shell.
const CACHE_NAME = "fc"
// A list of core files that make up the application's shell.
const APP_SHELL_FILES = ["./", "./index.php", "./index.html", "./main.js"]

// A promise that resolves with the IndexedDB database connection.
let dbPromise = null
// An in-memory cache for folder data to reduce IndexedDB lookups.
const folderCache = new Map()
// Manages in-flight promises to prevent concurrent DB requests for the same folder.
const folderLoadingPromises = new Map()

// Returns a promise that resolves with the database connection, creating it if necessary.
function getDb() {
    if (!dbPromise) {
        dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DBN, DB_VERSION)
            // This event is triggered when the database version changes.
            request.onupgradeneeded = event => {
                const db = event.target.result
                // Create the object stores if they don't already exist.
                if (!db.objectStoreNames.contains(SN)) db.createObjectStore(SN, { keyPath: "id" })
                if (!db.objectStoreNames.contains(META_SN)) db.createObjectStore(META_SN, { keyPath: "id" })
            }
            request.onsuccess = event => resolve(event.target.result)
            request.onerror = event => reject(event.target.error)
        })
    }
    return dbPromise
}

// The 'install' event is fired when the service worker is first installed.
self.addEventListener("install", event => {
    // waitUntil() ensures that the service worker will not install until the code inside has successfully completed
    event.waitUntil((async () => {
        // Open the application shell cache.
        const cache = await caches.open(CACHE_NAME)
        // Fetch and cache all the application shell files.
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
        // Force the waiting service worker to become the active service worker.
        await self.skipWaiting()
    })())
})

// The 'activate' event is fired when the service worker becomes active.
self.addEventListener("activate", event => {
    event.waitUntil(
        getDb()
            // Clean up old caches.
            .then(() => caches.keys().then(keys => Promise.all(keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null))))
            // Take control of all open clients (pages) at once.
            .then(() => self.clients.claim())
    )
})

// The 'fetch' event is fired for every network request made by the page.
self.addEventListener("fetch", event => {
    const url = new URL(event.request.url)
    // Ignore requests to other origins.
    if (url.origin !== self.location.origin) return

    // respondWith() hijacks the request and allows us to provide our own response.
    event.respondWith((async () => {
        // First, check if the request is for one of the core application files.
        if (APP_SHELL_FILES.includes(url.pathname)) {
            // If so, try to serve it from the cache, falling back to the network.
            const cachedResponse = await caches.match(event.request)
            return cachedResponse || fetch(event.request)
        }

        // Second, check if it's a request for a virtual file.
        // Virtual files are served from IndexedDB and live under the "/n/" path.
        if (url.pathname.startsWith("/n/")) {
            const pathParts = url.pathname.split("/").slice(2)
            const requestId = url.searchParams.get("reqId")
            const rules = ruleStore.get(requestId) || null

            // Once used, the rules can be removed.
            if (requestId) ruleStore.delete(requestId)
            // Generate a response from the file stored in IndexedDB.
            return generateResponseForVirtualFile(pathParts[0], pathParts.slice(1).join("/"), rules)
        }

        // Third, handle root-relative asset requests from within a virtual folder.
        // For example, if a virtual HTML file requests "/style.css".
        const referer = event.request.referrer
        if (referer) {
            const refererUrl = new URL(referer)
            // Check if the request is coming from one of our virtual files.
            if (refererUrl.origin === self.location.origin && refererUrl.pathname.startsWith("/n/")) {
                const pathParts = refererUrl.pathname.split("/").slice(2)
                const rules = refererUrl.searchParams.get("rules")
                // Serve the requested asset from the same virtual folder.
                return generateResponseForVirtualFile(pathParts[0], url.pathname.substring(1), rules ? decodeURIComponent(rules) : null)
            }
        }

        // For any other request, just fetch it from the network.
        return fetch(event.request)
    })())
})

// Retrieves folder data from the in-memory cache or IndexedDB.
function getFolderData(folderName) {
    // First, check the in-memory cache for the data.
    if (folderCache.has(folderName)) {
        return Promise.resolve(folderCache.get(folderName))
    }

    // Check if another request is already loading this folder. If so, wait for it to finish.
    if (folderLoadingPromises.has(folderName)) {
        return folderLoadingPromises.get(folderName)
    }

    // If not cached, create a new promise to fetch the data from IndexedDB.
    const loadingPromise = (async () => {
        try {
            const db = await getDb()
            // The transaction must include both object stores it intends to read from.
            const transaction = db.transaction([SN, META_SN], "readonly")

            // Look up the folder's ID in the manifest.
            const manifest = (await promisifyRequest(transaction.objectStore(META_SN).get("folderManifest")))?.data || {}
            const folderId = manifest[folderName] || folderName
            // Retrieve the folder data using its ID.
            const folderData = await promisifyRequest(transaction.objectStore(SN).get(folderId))

            if (folderData) {
                // Populate the in-memory cache for next time.
                folderCache.set(folderName, folderData)
            }
            return folderData
        } finally {
            // Once the promise is complete, remove it from the in-flight map.
            folderLoadingPromises.delete(folderName)
        }
    })()

    // Store the promise in the map to handle concurrent requests.
    folderLoadingPromises.set(folderName, loadingPromise)
    return loadingPromise
}

// Generates an HTTP response for a requested virtual file.
async function generateResponseForVirtualFile(folderName, requestedFilePath, rules) {
    const decodedFolderName = decodeURIComponent(folderName)
    let decodedFilePath = decodeURIComponent(requestedFilePath)

    // Retrieve the request ID to get the correct decryption key, if any.
    const urlParams = new URL(self.location.href).searchParams
    const requestId = urlParams.get("reqId")
    const decryptionKey = decryptionKeyStore.get(requestId)

    // Once the key is retrieved, it can be deleted.
    if (decryptionKey) decryptionKeyStore.delete(requestId)

    const folderData = await getFolderData(decodedFolderName)
    if (!folderData || !folderData.files) {
        console.warn(`Folder not found: ${decodedFolderName}`)
        return new Response("Folder not found: " + decodedFolderName, { status: 404 })
    }

    // If no specific file is requested, look for an index file.
    if (!decodedFilePath) {
        if (folderData.files["index.html"]) decodedFilePath = "index.html"
        else if (folderData.files["index.php"]) decodedFilePath = "index.php"
    }

    let fileData = folderData.files[decodedFilePath]
    let foundPath = decodedFilePath

    // If the exact file path isn't found, try to find a file that ends with the requested path.
    // This can help resolve requests for files in nested directories.
    if (!fileData) {
        const matchingPath = Object.keys(folderData.files).find(p => p.endsWith(decodedFilePath))
        if (matchingPath) {
            fileData = folderData.files[matchingPath]
            foundPath = matchingPath
        }
    }

    if (!fileData) {
        console.warn(`File not found: ${decodedFilePath}`)
        return new Response("File not found: " + decodedFilePath, { status: 404 })
    }

    // Start with the buffer from storage. This may be encrypted.
    let fileBuffer = fileData.buffer

    // If a decryption key was provided, attempt to decrypt the file buffer.
    if (decryptionKey && decodedFilePath !== ".metadata") {
        try {
            // The first 12 bytes are the IV (Initialization Vector).
            const iv = fileBuffer.slice(0, 12)
            const encryptedData = fileBuffer.slice(12)
            // Use the Web Crypto API to decrypt the data.
            fileBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                decryptionKey,
                encryptedData
            )
        } catch (e) {
            console.error("Decryption failed in Service Worker:", e)
            return new Response("Decryption Failed. Bad password?", { status: 401 })
        }
    }

    // Determine the MIME type of the file.
    const contentType = getMimeType(foundPath) || fileData.type || "application/octet-stream"
    // Apply any regex rules to the file content.
    const modifiedBuffer = applyRegexRules(foundPath, fileBuffer, contentType, rules)
    // Return the final file content as a Response object.
    return new Response(modifiedBuffer, {
        headers: {
            "Content-Type": contentType,
            "Cache-Control": "no-store" // Ensure the browser doesn't cache the virtual file.
        }
    })
}

// A utility function to determine a file's MIME type based on its extension.
function getMimeType(filePath) {
    const ext = filePath.split(".").pop().toLowerCase()
    const mimeTypes = {
        // Web Text/Markup
        "html": "text/html", "htm": "text/html", "css": "text/css",
        "js": "application/javascript", "mjs": "application/javascript",
        "json": "application/json", "xml": "application/xml",
        "txt": "text/plain", "md": "text/markdown", "csv": "text/csv",
        "php": "text/html", "appcache": "text/cache-manifest",
        "xhtml": "application/xhtml+xml",

        // Images
        "ico": "image/x-icon", "bmp": "image/bmp", "gif": "image/gif",
        "jpeg": "image/jpeg", "jpg": "image/jpeg", "png": "image/png",
        "svg": "image/svg+xml", "tif": "image/tiff", "tiff": "image/tiff",
        "webp": "image/webp", "avif": "image/avif",

        // Audio
        "mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg",
        "weba": "audio/webm", "mid": "audio/midi",

        // Video
        "mp4": "video/mp4", "webm": "video/webm", "mpeg": "video/mpeg",
        "ogv": "video/ogg", "3gp": "video/3gpp", "avi": "video/x-msvideo",

        // Documents & Other Apps
        "pdf": "application/pdf", "rtf": "application/rtf",
        "ogg": "application/ogg", // Generic OGG container

        // Archives/Compressed
        "zip": "application/zip", "gz": "application/gzip",
        "rar": "application/vnd.rar", "tar": "application/x-tar",
        "7z": "application/x-7z-compressed",

        // Fonts
        "woff": "font/woff", "woff2": "font/woff2", "ttf": "font/ttf",
        "otf": "font/otf", "eot": "application/vnd.ms-fontobject",

        // WebAssembly
        "wasm": "application/wasm"
    }
    return mimeTypes[ext]
}

// A helper function to convert IndexedDB requests into Promises.
function promisifyRequest(req) {
    return new Promise((r, j) => {
        req.onsuccess = () => r(req.result)
        req.onerror = () => j(req.error)
    })
}

// Escapes a string for use in a regular expression.
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

// Applies search-and-replace rules to the content of a text-based file.
function applyRegexRules(filePath, fileBuffer, fileType, regexRules) {
    // If there are no rules, or the file is not text-based, return the original buffer.
    if (!regexRules || !regexRules.trim()) return fileBuffer
    if (!/^(text|application\/(javascript|json|xml))/.test(fileType)) return fileBuffer

    try {
        // Decode the file buffer into a string.
        let content = new TextDecoder().decode(fileBuffer)
        const rules = regexRules.trim().split("\n")

        // Iterate over each rule.
        for (const line of rules) {
            // Split the rule into the match part and the replacement part.
            const [matchPart, replacePart] = line.split("->").map(s => s.trim())
            if (matchPart === undefined || replacePart === undefined) continue

            // Parse the operator and search pattern from the match part.
            const operatorMatch = matchPart.match(/^(.*?)\s(\$|\$\$|\|\||\|)\s(.*?)$/)
            if (!operatorMatch) continue

            const [, fileMatch, operator, searchPattern] = operatorMatch
            // Check if the rule applies to this file path.
            const fileRegex = new RegExp(fileMatch.trim() === "*" ? ".*" : fileMatch.trim())
            if (!fileRegex.test(filePath)) continue

            let searchRegex
            // Create the appropriate RegExp object based on the operator.
            switch (operator) {
                case "|": // Global Regex
                    searchRegex = new RegExp(searchPattern, "g")
                    break
                case "$": // Global Plain Text
                    searchRegex = new RegExp(escapeRegex(searchPattern), "g")
                    break
                case "||": // First Match Regex
                    searchRegex = new RegExp(searchPattern)
                    break
                case "$$": // First Match Plain Text
                    searchRegex = new RegExp(escapeRegex(searchPattern))
                    break
            }
            // Perform the replacement on the content.
            content = content.replace(searchRegex, replacePart)
        }
        // Encode the modified content back into a buffer and return it.
        return new TextEncoder().encode(content).buffer
    } catch (e) {
        console.error("Error applying regex rules:", e)
        // If an error occurs, return the original buffer.
        return fileBuffer
    }
}