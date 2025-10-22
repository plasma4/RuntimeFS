// Temporary storage for regex rules, keyed by request ID.
// Rules expire after 30 seconds to prevent memory leaks.
const ruleStore = new Map()
// Temporary storage for decryption keys, keyed by request ID.
// Keys expire after 30 seconds.
const decryptionKeyStore = new Map()

// IndexedDB configuration.
const DBN = "FileCacheDB"
const FOLDERS_SN = "Folders"
const FILES_SN = "Files"
const META_SN = "Metadata"
const DB_VERSION = 3
const FOLDER_CACHE_MAX_SIZE = 10

// Application shell caching configuration.
const CACHE_NAME = "fc" // Name for the application shell cache.
// Core files that make up the application's shell.
const APP_SHELL_FILES = ["./", "./index.php", "./index.html", "./main.js", "./cbor-x.js"]

const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(file => new URL(file, self.location.href).href)

const BASE_PATH_URL = new URL('./', self.location.href).href

// Promise for the IndexedDB connection.
let dbPromise = null
// In-memory cache for folder data to reduce IndexedDB lookups.
const folderCache = new Map()
// Tracks promises for ongoing folder data loads to prevent concurrent requests.
const folderLoadingPromises = new Map()

/**
 * Promisifies an IndexedDB request.
 * @param {IDBRequest} req The IndexedDB request.
 * @returns {Promise<any>} A promise that resolves with the request result or rejects on error.
 */
function promisifyRequest(req) {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result)
        req.onerror = () => reject(req.error)
    })
}

/**
 * Promisifies an IndexedDB transaction completion.
 * @param {IDBTransaction} transaction The IndexedDB transaction.
 * @returns {Promise<void>} A promise that resolves when the transaction completes or rejects on error/abort.
 */
function promisifyTransaction(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve()
        transaction.onerror = () => reject(transaction.error)
        transaction.onabort = () => reject(transaction.error || new DOMException("Transaction aborted"))
    })
}

/**
 * Determines the MIME type of a file based on its extension.
 * @param {string} filePath The path to the file.
 * @returns {string | undefined} The MIME type or undefined if not found.
 */
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

/**
 * Escapes special characters in a string for safe use in a regular expression.
 * @param {string} string The string to escape.
 * @returns {string} The escaped string.
 */
function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

/**
 * Applies regex search and replace rules to file content if it's text-based.
 * @param {string} filePath The path of the file being processed.
 * @param {ArrayBuffer} fileBuffer The file's content.
 * @param {string} fileType The file's MIME type.
 * @param {string | null} regexRules The rules string.
 * @returns {ArrayBuffer} The potentially modified file content.
 */
function applyRegexRules(filePath, fileBuffer, fileType, regexRules) {
    if (!regexRules || !regexRules.trim()) return fileBuffer
    // Only apply to text-based files.
    if (!/^(text|application\/(javascript|json|xml))/.test(fileType)) return fileBuffer

    try {
        const content = new TextDecoder().decode(fileBuffer)
        const rules = regexRules.trim().split("\n")
        let modifiedContent = content

        for (const line of rules) {
            const [matchPart, replacePart] = line.split("->").map(s => s.trim())
            if (matchPart === undefined || replacePart === undefined) continue

            const operatorMatch = matchPart.match(/^(.*?)\s(\$|\$\$|\|\||\|)\s(.*?)$/)
            if (!operatorMatch) continue

            const [, fileMatch, operator, searchPattern] = operatorMatch
            const fileRegex = new RegExp(fileMatch.trim() === "*" ? ".*" : fileMatch.trim())

            if (!fileRegex.test(filePath)) continue

            let searchRegex
            switch (operator) {
                case "|": searchRegex = new RegExp(searchPattern, "g"); break
                case "$": searchRegex = new RegExp(escapeRegex(searchPattern), "g"); break
                case "||": searchRegex = new RegExp(searchPattern); break
                case "$$": searchRegex = new RegExp(escapeRegex(searchPattern)); break
            }
            modifiedContent = modifiedContent.replace(searchRegex, replacePart)
        }
        return new TextEncoder().encode(modifiedContent).buffer
    } catch (e) {
        console.error(`Error applying regex rules to ${filePath}:`, e)
        return fileBuffer // Return original buffer on error.
    }
}

/**
 * Gets the IndexedDB connection promise, creating it if it doesn't exist.
 * @returns {Promise<IDBDatabase>} A promise that resolves with the DB instance.
 */
function getDb() {
    if (!dbPromise) {
        // console.log("No DB connection promise found, creating a new one.")
        dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DBN, DB_VERSION)
            request.onupgradeneeded = function (e) {
                const db = e.target.result
                if (!db.objectStoreNames.contains(FOLDERS_SN)) {
                    db.createObjectStore(FOLDERS_SN, { keyPath: "id" })
                }
                if (!db.objectStoreNames.contains(FILES_SN)) {
                    const fileStore = db.createObjectStore(FILES_SN, { autoIncrement: true })
                    fileStore.createIndex("folder", ["folderName", "path"], { unique: true })
                }
                if (!db.objectStoreNames.contains("FileChunks")) {
                    const chunkStore = db.createObjectStore("FileChunks", { keyPath: "id", autoIncrement: true })
                    // Index this by fileId so we can quickly find all chunks for a file.
                    chunkStore.createIndex("by_file", "fileId", { unique: false })
                }

                if (!db.objectStoreNames.contains(META_SN)) {
                    db.createObjectStore(META_SN, { keyPath: "id" })
                }
            }
            request.onsuccess = e => {
                const db = e.target.result
                db.onversionchange = () => {
                    console.warn("Database version change requested, closing connection.")
                    db.close()
                    dbPromise = null
                }
                resolve(db)
            }
            request.onerror = e => reject(e.target.errorCode)
        })
    }
    return dbPromise
}

async function getFolderData(folderName) {
    if (folderCache.has(folderName)) {
        const data = folderCache.get(folderName)
        folderCache.delete(folderName)
        folderCache.set(folderName, data)
        return Promise.resolve(data)
    }

    if (folderLoadingPromises.has(folderName)) {
        return folderLoadingPromises.get(folderName)
    }

    const loadingPromise = (async () => {
        try {
            const db = await getDb()
            const transaction = db.transaction([FOLDERS_SN, FILES_SN], "readonly")
            const folderStore = transaction.objectStore(FOLDERS_SN)
            const fileStore = transaction.objectStore(FILES_SN)
            const fileIndex = fileStore.index("folder")

            const folderMetadata = await promisifyRequest(folderStore.get(folderName))
            if (!folderMetadata) return undefined

            const filesArray = await promisifyRequest(fileIndex.getAll(IDBKeyRange.bound([folderName, ""], [folderName, "\uffff"])))

            // Reconstruct the folder object with a map of path -> metadata.
            const folderData = {
                ...folderMetadata,
                files: new Map() // Use a Map for easier lookups.
            }

            for (const fileRecord of filesArray) {
                folderData.files.set(fileRecord.path, fileRecord)
            }

            // Manage the in-memory cache.
            if (folderCache.size >= FOLDER_CACHE_MAX_SIZE) {
                const oldestKey = folderCache.keys().next().value
                folderCache.delete(oldestKey)
            }
            folderCache.set(folderName, folderData)
            return folderData
        } finally {
            folderLoadingPromises.delete(folderName)
        }
    })()

    folderLoadingPromises.set(folderName, loadingPromise)
    return loadingPromise
}

// Service worker installation. Caches the application shell.
self.addEventListener("install", e => {
    e.waitUntil((async () => {
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
                console.warn(`Fetch failed for ${e.request.url}; trying to serve from cache.`)

                // If the network request failed (e.g., user is offline), try the cache.
                const cachedResponse = await caches.match(e.request)
                if (cachedResponse) {
                    return cachedResponse
                }

                // For other failed requests (images, scripts, etc.), just return an error response.
                return new Response(null, { status: 404, statusText: "Not Found" })
            }
        })
        await Promise.all(promises)
        await self.skipWaiting() // Activate immediately.
    })())
})

// Service worker activation. Cleans up old caches and claims clients.
self.addEventListener("activate", e => {
    e.waitUntil(
        getDb() // 1. Ensure DB is ready.
            .then(() => caches.keys()) // 2. Get all cache keys.
            .then(keys => Promise.all( // 3. Delete all old caches.
                keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null)
            ))
            .then(() => self.clients.claim()) // 4. Take control of all clients.
    )
})

self.addEventListener("fetch", e => {
    const url = new URL(e.request.url)
    if (url.origin !== self.location.origin) return // Ignore cross-origin requests.

    // Handle POST/PUT requests for saving data within virtual apps
    if (e.request.method === "POST" || e.request.method === "PUT") {
        if (url.pathname.startsWith("/n/")) {
            e.respondWith((async () => {
                try {
                    const pathParts = url.pathname.split("/").slice(2)
                    const folderName = decodeURIComponent(pathParts[0])
                    const filePath = decodeURIComponent(pathParts.slice(1).join("/"))
                    const newContent = await e.request.arrayBuffer()

                    const db = await getDb()
                    const transaction = db.transaction([FILES_SN], "readwrite")
                    const fileStore = transaction.objectStore(FILES_SN)
                    const index = fileStore.index("folder")

                    // Find the primary key of the file to update it
                    const fileRecord = await promisifyRequest(index.get([folderName, filePath]))

                    if (fileRecord) {
                        // Update the existing file record
                        fileRecord.content.buffer = newContent
                        fileRecord.content.type = e.request.headers.get("content-type") || "application/octet-stream"
                        await promisifyRequest(fileStore.put(fileRecord))
                    } else {
                        // Or create a new file record if it doesn't exist
                        await promisifyRequest(fileStore.add({
                            folderName: folderName,
                            path: filePath,
                            content: {
                                buffer: newContent,
                                type: e.request.headers.get("content-type") || "application/octet-stream"
                            }
                        }))
                    }

                    await promisifyTransaction(transaction)

                    // Invalidate the in-memory cache
                    folderCache.delete(folderName)

                    return new Response(JSON.stringify({ success: true, message: `Saved ${filePath}` }), { status: 200, headers: { "Content-Type": "application/json" } })
                } catch (err) {
                    console.error(`Failed to save file to virtual folder:`, err)
                    return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers: { "Content-Type": "application/json" } })
                }
            })())
            return
        }
    }

    // Handle GET requests for the app shell and virtual files
    e.respondWith((async () => {
        // First, handle requests for the application shell (cached).
        const requestUrl = e.request.url
        if (requestUrl === BASE_PATH_URL || FULL_APP_SHELL_URLS.includes(requestUrl)) {
            const cachedResponse = await caches.match(e.request)
            return cachedResponse || fetch(e.request)
        }

        // Second, handle requests for virtual files.
        if (url.pathname.startsWith("/n/")) {
            const pathParts = url.pathname.split("/").slice(2)
            const folderName = pathParts[0]
            const filePath = pathParts.slice(1).join("/")
            const requestId = url.searchParams.get("reqId")

            // Get the entire request data object (regex and headers) from the store.
            const requestData = ruleStore.get(requestId) || {}
            if (requestId) ruleStore.delete(requestId)

            const response = await generateResponseForVirtualFile(folderName, filePath, requestData, e)

            // SPA Fallback: If a navigation request fails, try serving index.html.
            if (response.status === 404 && e.request.mode === "navigate" && filePath !== "index.html") {
                console.log(`'${filePath}' not found. Attempting SPA fallback to index.html.`)
                const fallbackResponse = await generateResponseForVirtualFile(folderName, "index.html", requestData, e)
                return fallbackResponse.status === 200 ? fallbackResponse : response
            }

            return response
        }

        // Third, handle asset requests originating from virtual pages.
        const referer = e.request.referrer
        if (referer) {
            const refererUrl = new URL(referer)
            if (refererUrl.origin === self.location.origin && refererUrl.pathname.startsWith("/n/")) {
                const pathParts = refererUrl.pathname.split("/").slice(2)
                // Asset requests from a page won't have custom rules, so we pass an empty object.
                return generateResponseForVirtualFile(pathParts[0], url.pathname.substring(1), {}, e)
            }
        }

        // For all other requests, fall through to the network.
        try {
            var f = await fetch(e.request)
        } catch (err) {
            return new Response(null, { status: 404, statusText: "Couldn't find file content." })
        }
        return f
    })())
})

self.addEventListener("message", e => {
    if (!e.data) return
    switch (e.data.type) {
        case "CUSTOM_RULES":
            ruleStore.set(e.data.requestId, {
                regex: e.data.rules,
                headers: e.data.headers
            })
            setTimeout(() => ruleStore.delete(e.data.requestId), 30000)
            break

        case "INVALIDATE_CACHE":
            const folderName = e.data.folderName
            if (folderName) {
                console.log(`SW: Invalidating cache for: ${folderName}`)
                folderCache.delete(folderName)
                folderLoadingPromises.delete(folderName)
                if (e.source) {
                    e.source.postMessage({ type: "CACHE_INVALIDATED", folderName: folderName })
                }
            }
            break

        case "DECRYPT_KEY":
            decryptionKeyStore.set(e.data.requestId, e.data.key)
            setTimeout(() => decryptionKeyStore.delete(e.data.requestId), 30000)
            break

        case "PREPARE_FOR_IMPORT":
            (async function () {
                console.log("SW: Acquired import lock. Closing DB.")
                folderCache.clear()
                folderLoadingPromises.clear()

                if (dbPromise) {
                    const db = await dbPromise
                    db.close()
                    dbPromise = null
                }

                if (e.source) {
                    e.source.postMessage({ type: "IMPORT_READY" })
                }
            })()
            break

        case "DB_IMPORTED":
            console.log("SW: Received DB_IMPORTED. Clearing cache and acknowledging.")
            folderCache.clear()
            folderLoadingPromises.clear()
            if (dbPromise) {
                dbPromise.then(db => db.close())
                dbPromise = null
            }
            // Send a message back to the client that we are done.
            if (e.source) {
                e.source.postMessage({ type: "DB_ACKNOWLEDGED" })
            }
            break
    }
})

async function generateResponseForVirtualFile(folderName, requestedFilePath, requestData, event) {
    const decodedFolderName = decodeURIComponent(folderName)
    let decodedFilePath = decodeURIComponent(requestedFilePath)

    const folderData = await getFolderData(decodedFolderName)
    if (!folderData || !folderData.files) {
        return new Response("Folder not found: " + decodedFolderName, { status: 404 })
    }

    // Handle empty path / SPA fallback.
    if (!decodedFilePath) {
        if (folderData.files.has("index.html")) decodedFilePath = "index.html"
        else if (folderData.files.has("index.php")) decodedFilePath = "index.php"
    }

    let fileMetadata = folderData.files.get(decodedFilePath)

    if (!fileMetadata) {
        return new Response("File not found: " + requestedFilePath, { status: 404 })
    }

    const requestId = new URL(event.request.url).searchParams.get("reqId")
    const decryptionKey = decryptionKeyStore.get(requestId)
    if (requestId) decryptionKeyStore.delete(requestId)

    let fileBuffer = null
    let fileType = fileMetadata.type || getMimeType(decodedFilePath) || "application/octet-stream"
    const isSmallFile = fileMetadata.content?.isBufferCached === true

    // Check if regex rules are active and apply to this file.
    const hasActiveRegex = requestData.regex && doesRegexApplyToFile(decodedFilePath, requestData.regex)

    // If there's a decryption key or an active regex rule, we MUST load the full file into memory.
    // Case 1: Decryption or Regex is active. We MUST load the full file into a buffer.
    if (decryptionKey || hasActiveRegex) {
        let bufferToProcess = null

        if (fileMetadata.content) { // It's a small file, buffer is ready.
            bufferToProcess = fileMetadata.content.buffer
        } else if (fileMetadata.size) { // It's a large file, we must reassemble it from chunks.
            const db = await getDb()
            bufferToProcess = await reassembleFileFromChunks(db, fileMetadata.id)
        }

        if (!(bufferToProcess instanceof ArrayBuffer)) {
            return new Response("Could not find file content for processing rules.", { status: 500 })
        }

        // If a key exists, decrypt the buffer we just loaded.
        if (decryptionKey) {
            try {
                // The IV is stored with the data for encrypted files.
                const iv = bufferToProcess.slice(0, 12)
                const data = bufferToProcess.slice(12)
                bufferToProcess = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, decryptionKey, data)
            } catch (e) {
                console.error("SW Decryption failed:", e)
                return new Response("Decryption failed. The password may be incorrect.", { status: 403 })
            }
        }

        // Now that we have the final, plaintext buffer, apply regex and serve.
        let finalBuffer = applyRegexRules(decodedFilePath, bufferToProcess, fileType, requestData.regex)
        const headers = applyCustomHeaders({ "Content-Type": fileType, "Content-Length": finalBuffer.byteLength }, decodedFilePath, requestData.headers)
        return new Response(finalBuffer, { headers })
    }

    // Case 2: It's a standard small file with no special rules. Serve the buffer directly.
    if (fileMetadata.content) {
        const fileBuffer = fileMetadata.content.buffer
        if (!(fileBuffer instanceof ArrayBuffer)) {
            console.error(`Error: Invalid content for ${decodedFilePath}. Expected ArrayBuffer.`)
            return new Response("Invalid file content in database.", { status: 500 })
        }
        const headers = applyCustomHeaders({ "Content-Type": fileType, "Content-Length": fileBuffer.byteLength }, decodedFilePath, requestData.headers)
        return new Response(fileBuffer, { headers })
    }

    // Case 3: It's a standard large file with no special rules. Stream it.
    if (fileMetadata.size) {
        const stream = new ReadableStream({
            start(controller) {
                getDb().then(db => {
                    const transaction = db.transaction("FileChunks", "readonly")
                    const chunkStore = transaction.objectStore("FileChunks")
                    const index = chunkStore.index("by_file")
                    const cursorReq = index.openCursor(IDBKeyRange.only(fileMetadata.id))

                    cursorReq.onsuccess = () => {
                        const cursor = cursorReq.result
                        if (cursor) {
                            controller.enqueue(cursor.value.data)
                            cursor.continue()
                        } else {
                            controller.close()
                        }
                    }
                    transaction.onerror = e => controller.error(e.target.error)
                }).catch(e => controller.error(e))
            }
        })

        const headers = applyCustomHeaders({
            "Content-Type": fileType,
            "Content-Length": fileMetadata.size
        }, decodedFilePath, requestData.headers)

        return new Response(stream, { headers })
    }

    // If we ended up with a buffer (from any of the logic above), apply rules and serve it.
    if (fileBuffer !== null) {
        if (!(fileBuffer instanceof ArrayBuffer)) {
            console.error(`Error: Attempted to serve a file (${decodedFilePath}) but the content was not an ArrayBuffer.`, fileBuffer)
            return new Response("Invalid file content found in cache or database.", { status: 500 })
        }

        let finalBuffer = applyRegexRules(decodedFilePath, fileBuffer, fileType, requestData.regex)
        const headers = applyCustomHeaders({ "Content-Type": fileType, "Content-Length": finalBuffer.byteLength }, decodedFilePath, requestData.headers)
        return new Response(finalBuffer, { headers: headers })
    }

    // Fallback for any other case
    return new Response("Could not load file content.", { status: 500 })
}

/**
 * Reads all chunks for a file from IndexedDB and reassembles them into a single ArrayBuffer.
 * @param {IDBDatabase} db The database instance.
 * @param {number} fileId The primary key of the file in the FILES_SN store.
 * @returns {Promise<ArrayBuffer>} A promise that resolves with the complete file buffer.
 */
async function reassembleFileFromChunks(db, fileId) {
    const transaction = db.transaction("FileChunks", "readonly")
    const chunkStore = transaction.objectStore("FileChunks")
    const index = chunkStore.index("by_file")
    const allChunks = await promisifyRequest(index.getAll(IDBKeyRange.only(fileId)))

    // Sort chunks by their index to ensure correct order
    allChunks.sort((a, b) => a.index - b.index)

    let totalSize = 0
    for (const chunk of allChunks) {
        totalSize += chunk.data.byteLength
    }

    const reassembled = new Uint8Array(totalSize)
    let offset = 0
    for (const chunk of allChunks) {
        reassembled.set(new Uint8Array(chunk.data), offset)
        offset += chunk.data.byteLength
    }

    return reassembled.buffer
}


/**
 * Quickly checks if any regex rule applies to a given file path without running the replacement.
 * @param {string} filePath The path of the file.
 * @param {string} regexRules The full string of regex rules.
 * @returns {boolean} True if a rule matches the file path.
 */
function doesRegexApplyToFile(filePath, regexRules) {
    if (!regexRules || !regexRules.trim()) return false
    const rules = regexRules.trim().split("\n")
    for (const line of rules) {
        const [matchPart] = line.split("->")
        if (!matchPart) continue
        const operatorMatch = matchPart.match(/^(.*?)\s(\$|\$\$|\|\||\|)\s(.*?)$/)
        if (!operatorMatch) continue

        const fileMatch = operatorMatch[1].trim()
        const fileRegex = new RegExp(fileMatch === "*" ? ".*" : fileMatch)

        if (fileRegex.test(filePath)) {
            return true // Found a matching rule
        }
    }
    return false // No rules matched
}

function parseCustomHeaders(rulesString) {
    if (!rulesString || !rulesString.trim()) {
        return []
    }
    const rules = []
    rulesString.trim().split("\n").forEach(line => {
        line = line.trim()
        if (line.startsWith("#") || line === "") return

        const parts = line.split("->")
        if (parts.length < 2) return

        const [globPart, ...headerParts] = parts
        const glob = globPart.trim()
        const headerLine = headerParts.join("->").trim()

        const headerMatch = headerLine.match(/^([^:]+):\s*(.*)$/)
        if (!headerMatch) return

        const [, headerName, headerValue] = headerMatch

        // Convert file glob to a regex for matching.
        const regex = new RegExp("^" + glob.replace(/\./g, "\.").replace(/\*/g, ".*").replace(/\?/g, ".") + "$")

        rules.push({
            regex: regex,
            header: headerName.trim(),
            value: headerValue.trim()
        })
    })
    return rules
}

function applyCustomHeaders(baseHeaders, filePath, rulesString) {
    if (!rulesString) {
        return baseHeaders
    }

    const customHeaderRules = parseCustomHeaders(rulesString)

    for (const rule of customHeaderRules) {
        if (rule.regex.test(filePath)) {
            baseHeaders[rule.header] = rule.value
        }
    }

    return baseHeaders
}