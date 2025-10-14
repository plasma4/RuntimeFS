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
const DB_VERSION = 2 // Ensure this matches main.js
const FOLDER_CACHE_MAX_SIZE = 10

// Application shell caching configuration.
const CACHE_NAME = "fc" // Name for the application shell cache.
// Core files that make up the application's shell.
const APP_SHELL_FILES = ["./", "./index.php", "./index.html", "./main.js"]

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
 * Generates a SHA-1 hash of an ArrayBuffer. Used for creating ETags.
 * @param {ArrayBuffer} buffer The buffer to hash.
 * @returns {Promise<string>} A promise resolving with the hex-encoded hash.
 */
async function generateETag(buffer) {
    const hashBuffer = await crypto.subtle.digest("SHA-1", buffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("")
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

/**
 * Retrieves folder data, using cache or fetching from IndexedDB.
 * @param {string} folderName The name of the folder.
 * @returns {Promise<object | undefined>} A promise resolving with folder data or undefined.
 */
function getFolderData(folderName) {
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

            // 1. Get the folder metadata
            const folderMetadata = await promisifyRequest(folderStore.get(folderName))
            if (!folderMetadata) {
                // Folder doesn't exist at all
                return undefined
            }

            // 2. Get all files associated with this folder
            const fileRange = IDBKeyRange.bound([folderName, ""], [folderName, "\uffff"])
            const filesArray = await promisifyRequest(fileIndex.getAll(fileRange))

            // 3. Reconstruct the folder object format that the rest of the code expects
            const folderData = {
                ...folderMetadata, // id, encryptionType, etc.
                files: {}
            }

            for (const fileRecord of filesArray) {
                folderData.files[fileRecord.path] = fileRecord.content
            }

            if (folderData) {
                if (folderCache.size >= FOLDER_CACHE_MAX_SIZE) {
                    // Get the first (oldest) key and delete it.
                    const oldestKey = folderCache.keys().next().value
                    // console.log(`SW: Cache limit reached. Evicting oldest entry: ${oldestKey}`)
                    folderCache.delete(oldestKey)
                }
                folderCache.set(folderName, folderData) // Cache the reconstructed data.
            }
            return folderData
        } finally {
            folderLoadingPromises.delete(folderName) // Clean up loading state.
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
        if (APP_SHELL_FILES.includes(url.pathname)) {
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
            if (response.status === 404 && e.request.mode === "navigate") {
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
        console.log(e.request)
        return fetch(e.request)
    })())
})

self.addEventListener("message", e => {
    if (!e.data) return

    switch (e.data.type) {
        case "CUSTOMRULES":
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
            console.log("SW: Received PREPARE_FOR_IMPORT. Closing DB and clearing caches.")
            // Clear all in-memory state
            folderCache.clear()
            folderLoadingPromises.clear()
            ruleStore.clear()
            decryptionKeyStore.clear()

            // Close the database connection to release the lock
            if (dbPromise) {
                dbPromise.then(db => db.close())
                dbPromise = null // Nullify the promise to force re-initialization later
            }

            // Acknowledge completion back to the client
            if (e.source) {
                e.source.postMessage({ type: "IMPORT_READY" })
            }
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

/**
 * Generates an HTTP response for a requested virtual file. Handles decryption,
 * custom rules, Range requests, MIME types, ETags, and security headers.
 * @param {string} folderName The decoded name of the virtual folder.
 * @param {string} requestedFilePath The decoded path of the requested file.
 *- * @param {object} requestData An object containing { regex, headers } strings.
 * @param {FetchEvent} event The original fetch event object.
 * @returns {Promise<Response>} A promise resolving with the HTTP Response.
 */
async function generateResponseForVirtualFile(folderName, requestedFilePath, requestData, event) {
    const rules = requestData ? requestData.regex : null
    const customHeadersRules = requestData ? requestData.headers : ""
    const parsedCustomHeaders = parseCustomHeaders(customHeadersRules) // You need the parseCustomHeaders helper for this

    const decodedFolderName = decodeURIComponent(folderName)
    let decodedFilePath = decodeURIComponent(requestedFilePath)

    const requestId = new URL(event.request.url).searchParams.get("reqId")
    const decryptionKey = requestId ? decryptionKeyStore.get(requestId) : null
    if (decryptionKey) decryptionKeyStore.delete(requestId)

    const folderData = await getFolderData(decodedFolderName)
    if (!folderData || !folderData.files) {
        console.warn(`Folder not found: ${decodedFolderName}`)
        return new Response("Folder not found: " + decodedFolderName, { status: 404 })
    }

    let filePath = decodedFilePath
    if (!filePath) {
        if (folderData.files["index.html"]) filePath = "index.html"
        else if (folderData.files["index.php"]) filePath = "index.php"
    }

    let fileData = folderData.files[filePath]
    let foundPath = filePath

    if (!fileData && event.request.referrer) {
        const refererUrl = new URL(event.request.referrer)
        const basePath = refererUrl.pathname.substring(0, refererUrl.pathname.lastIndexOf("/"))

        const pathParts = (basePath + "/" + filePath).split("/")
        const resolvedParts = []
        for (const part of pathParts) {
            if (part === "." || part === "") continue
            if (part === "..") {
                resolvedParts.pop()
            } else {
                resolvedParts.push(part)
            }
        }
        // Re-join and remove the leading "/n/folderName" part
        const resolvedPath = resolvedParts.slice(3).join("/")
        if (folderData.files[resolvedPath]) {
            fileData = folderData.files[resolvedPath]
            foundPath = resolvedPath
        }
    }


    if (!fileData) {
        // Only use the SPA fallback as a last resort for navigation requests.
        if (event.request.mode === "navigate" && folderData.files["index.html"]) {
            console.log(`'${filePath}' not found. Attempting SPA fallback to index.html.`)
            fileData = folderData.files["index.html"]
            foundPath = "index.html"
        } else {
            return new Response("File not found: " + decodedFilePath, { status: 404 })
        }
    }

    let fileBuffer = fileData.buffer

    // Decrypt, apply regex rules
    if (decryptionKey && foundPath !== ".metadata") {
        try {
            const iv = fileBuffer.slice(0, 12)
            const encryptedData = fileBuffer.slice(12)
            fileBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, decryptionKey, encryptedData)
        } catch (e) {
            console.error(`Decryption failed for ${foundPath}:`, e)
            return new Response("Decryption Failed. Bad password?", { status: 401 })
        }
    }

    const contentType = getMimeType(foundPath) || fileData.type || "application/octet-stream"
    const modifiedBuffer = applyRegexRules(foundPath, fileBuffer, contentType, rules)
    const totalSize = modifiedBuffer.byteLength

    const headers = {
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=0, must-revalidate", // ETag-friendly caching policy
        "Accept-Ranges": "bytes",
        "ETag": await generateETag(modifiedBuffer)
    }

    // Specific default headers based on file type
    const extension = foundPath.split(".").pop().toLowerCase()
    const fontExtensions = ["woff", "woff2", "ttf", "otf", "eot"]
    if (fontExtensions.includes(extension)) {
        headers["Access-Control-Allow-Origin"] = "*"
    }

    // Custom header overrides
    parsedCustomHeaders.forEach(rule => {
        if (rule.regex.test(foundPath)) {
            console.log(`Applying custom header to ${foundPath}: ${rule.header}`)
            headers[rule.header] = rule.value
        }
    })

    const ifNoneMatch = event.request.headers.get("if-none-match")
    if (ifNoneMatch && ifNoneMatch === headers["ETag"]) {
        console.log(`ETag match for ${foundPath}. Serving 304 Not Modified.`)
        return new Response(null, { status: 304, headers })
    }

    const rangeHeader = event.request.headers.get("range")
    if (rangeHeader) {
        const rangeMatch = rangeHeader.match(/bytes=(\d+)-(\d*)/)
        if (rangeMatch) {
            const start = Number(rangeMatch[1])
            let end = rangeMatch[2] ? Number(rangeMatch[2]) : totalSize - 1

            if (start < totalSize && start <= end) {
                end = Math.min(end, totalSize - 1) // Clamp end to file size
                const chunk = modifiedBuffer.slice(start, end + 1)
                headers["Content-Length"] = chunk.byteLength
                headers["Content-Range"] = `bytes ${start}-${end}/${totalSize}`

                return new Response(chunk, { status: 206, statusText: "Partial Content", headers })
            }
        }
    }

    headers["Content-Length"] = totalSize
    return new Response(modifiedBuffer, { headers })
}

/**
 * Parses a string of custom header rules into a structured array.
 * @param {string} rulesString The raw string from the textarea.
 * @returns {Array<object>} An array of rule objects.
 */
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

        const glob = parts[0].trim()
        const headerPart = parts.slice(1).join("->").trim()

        const headerMatch = headerPart.match(/^([^:]+):\s*(.*)$/)
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