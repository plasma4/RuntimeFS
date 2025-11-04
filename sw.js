// Temporary storage for regex rules, keyed by request ID. Rules expire after 30 seconds to prevent memory leaks.
const ruleStore = new Map()
// Temporary storage for decryption keys, keyed by request ID. Keys expire after 30 seconds.
const decryptionKeyStore = new Map()

const DBN = "FileCacheDB"
const FOLDERS_SN = "Folders"
const FILES_SN = "Files"
const RULES_SN = "Rules"
const DB_VERSION = 11 // Version 1.1

const CACHE_NAME = "fc"
const APP_SHELL_FILES = ["./", "./index.html", "./main.js", "./cbor-x.js"] // core files

const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(file => new URL(file, self.location.href).href)

// Promise for the IndexedDB connection.
let dbPromise = null

const STORE_ENTRY_TTL = 30000 // 30 seconds

const basePath = new URL("./", self.location).pathname
const virtualPathPrefix = basePath + "n/"

function cleanupExpiredStores() {
    const now = Date.now()
    for (const [key, value] of ruleStore.entries()) {
        if (now - value.timestamp > STORE_ENTRY_TTL) {
            ruleStore.delete(key)
        }
    }
    for (const [key, value] of decryptionKeyStore.entries()) {
        if (now - value.timestamp > STORE_ENTRY_TTL) {
            decryptionKeyStore.delete(key)
        }
    }
    console.log("SW: Ran cleanup on expired store entries.")
}
cleanupExpiredStores()

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
        let content = new TextDecoder().decode(fileBuffer)
        const rules = regexRules.trim().split("\n")

        for (const line of rules) {
            const [matchPart, replacePart] = line.split("->").map(s => s.trim())
            if (matchPart == null || replacePart == null) continue

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
            content = content.replace(searchRegex, replacePart)
        }
        return new TextEncoder().encode(content).buffer
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
        dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DBN, DB_VERSION)

            request.onupgradeneeded = function (e) {
                const db = e.target.result
                const transaction = e.target.transaction

                // Create standard stores if they don't exist
                if (!db.objectStoreNames.contains(FOLDERS_SN)) {
                    db.createObjectStore(FOLDERS_SN, { keyPath: "id" })
                }
                if (!db.objectStoreNames.contains(RULES_SN)) {
                    db.createObjectStore(RULES_SN, { keyPath: "id" })
                }

                let fileStore
                if (!db.objectStoreNames.contains(FILES_SN)) {
                    fileStore = db.createObjectStore(FILES_SN, { keyPath: "id", autoIncrement: true })
                } else {
                    fileStore = transaction.objectStore(FILES_SN)
                }

                if (!fileStore.indexNames.contains("lookup")) {
                    fileStore.createIndex("lookup", "lookupPath", { unique: true })
                }

                if (!db.objectStoreNames.contains("FileChunks")) {
                    const chunkStore = db.createObjectStore("FileChunks", { keyPath: "id", autoIncrement: true })
                    chunkStore.createIndex("by_file", "fileId", { unique: false })
                }
            }

            request.onsuccess = e => {
                db = e.target.result
                db.onversionchange = () => {
                    console.warn("Database version change detected, closing connection.")
                    if (db) {
                        db.close()
                    }
                    db = null
                    dbPromise = null
                }
                resolve(db)
            }
            request.onerror = e => reject(e.target.errorCode)
        })
    }
    return dbPromise
}

// Service worker installation. Caches the application shell.
self.addEventListener("install", e => {
    e.waitUntil((async () => {
        console.log("SW: Install event triggered. Caching app shell.")
        const cache = await caches.open(CACHE_NAME)
        // Use Promise.allSettled to ensure installation completes even if one file is missing
        const results = await Promise.allSettled(
            APP_SHELL_FILES.map(url =>
                fetch(url, { cache: "no-cache" }).then(response => {
                    if (!response.ok) {
                        throw new Error(`Request for ${url} failed with status ${response.status}`)
                    }
                    return cache.put(url, response)
                })
            )
        )
        results.forEach(result => {
            if (result.status === "rejected") {
                console.warn(`SW Install: Failed to cache a resource. Reason:`, result.reason.message)
            }
        })
        console.log("SW: Caching finished. Activating...")
        await self.skipWaiting()
    })())
})

// Service worker activation; cleans up stuff!
self.addEventListener("activate", e => {
    e.waitUntil(
        caches.keys()
            .then(keys => Promise.all(
                keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null)
            ))
            .then(() => self.clients.claim())
    )
})

self.addEventListener("fetch", e => {
    const url = new URL(e.request.url)
    if (url.origin !== self.location.origin) return

    if ((e.request.method === "POST" || e.request.method === "PUT") && url.pathname.startsWith(virtualPathPrefix)) {
        e.respondWith((async () => {
            try {
                const pathParts = url.pathname.split("/").slice(2)
                const folderName = decodeURIComponent(pathParts[0])
                const filePath = decodeURIComponent(pathParts.slice(1).join("/"))
                const newContent = await e.request.arrayBuffer()

                const db = await getDb()
                const transaction = db.transaction([FILES_SN], "readwrite")
                const fileStore = transaction.objectStore(FILES_SN)
                const index = fileStore.index("lookup")

                const fileRecord = await promisifyRequest(index.get(`${folderName}/${filePath}`))
                const newRecord = {
                    folderName: folderName,
                    path: filePath,
                    buffer: new Blob([newContent]),
                    type: e.request.headers.get("content-type") || "application/octet-stream",
                    lookupPath: `${folderName}/${filePath}`
                }
                if (fileRecord) newRecord.id = fileRecord.id

                await promisifyRequest(fileStore.put(newRecord))
                await promisifyTransaction(transaction)
                return new Response(JSON.stringify({ success: true }), { status: 200, headers: { "Content-Type": "application/json" } })
            } catch (err) {
                return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers: { "Content-Type": "application/json" } })
            }
        })())
        return
    }

    e.respondWith((async () => {
        if (FULL_APP_SHELL_URLS.includes(e.request.url)) {
            return caches.match(e.request).then(res => res || fetch(e.request))
        }

        const requestPath = url.pathname

        const isVirtualFileNav = e.request.mode === "navigate" && requestPath.startsWith(virtualPathPrefix)

        // Use basic loader for first load
        if (isVirtualFileNav && e.request.url !== e.request.referrer) {
            return new Response("<!DOCTYPE html><script>window.location.replace(window.location.href)<\/script></html>", { headers: { "Content-Type": "text/html" } })
        }

        if (requestPath.startsWith(virtualPathPrefix)) {
            // Check the runtime cache first for this resource.
            const cache = await caches.open(CACHE_NAME)
            const cachedResponse = await cache.match(e.request)
            if (cachedResponse) {
                return cachedResponse
            }

            // If not in cache, generate it from the DB.
            const virtualPath = requestPath.substring(virtualPathPrefix.length)
            const pathParts = virtualPath.split("/")
            const folderName = pathParts[0]
            const filePath = pathParts.slice(1).join("/")
            const requestId = url.searchParams.get("reqId")

            if (folderName && filePath) {
                return generateResponseForVirtualFile(folderName, filePath, e, requestId)
            }
        }

        // For any other request, fall back to the network.
        return fetch(e.request).catch(() => new Response("Network error", { status: 500 }))
    })())
})

self.addEventListener("message", e => {
    if (!e.data) return
    switch (e.data.type) {
        case "SET_RULES":
            ruleStore.set(e.data.requestId, {
                regex: e.data.rules,
                headers: e.data.headers
            })
            setTimeout(() => ruleStore.delete(e.data.requestId), STORE_ENTRY_TTL)
            if (e.source) {
                e.source.postMessage({
                    type: "RULES_READY",
                    requestId: e.data.requestId
                })
            }
            break

        case "INVALIDATE_CACHE":
            (async function () {
                console.log(`SW: Invalidating cache for folder: ${e.data.folderName}`)
                try {
                    const cache = await caches.open(CACHE_NAME)
                    const keys = await cache.keys()
                    const deletionPromises = []
                    const prefix = `${self.location.origin}/n/${encodeURIComponent(e.data.folderName)}/`

                    for (const request of keys) {
                        if (request.url.startsWith(prefix)) {
                            deletionPromises.push(cache.delete(request))
                        }
                    }
                    await Promise.all(deletionPromises)
                    console.log(`SW: Cache invalidated for ${deletionPromises.length} item(s).`)
                } catch (err) {
                    console.error("SW: Cache invalidation failed:", err)
                } finally {
                    // Acknowledge that the operation is complete.
                    if (e.source) {
                        e.source.postMessage({ type: "CACHE_INVALIDATED", folderName: e.data.folderName })
                    }
                }
            })()
            break

        case "DECRYPT_KEY":
            decryptionKeyStore.set(e.data.requestId, e.data.key)
            setTimeout(() => decryptionKeyStore.delete(e.data.requestId), STORE_ENTRY_TTL)
            break

        case "PREPARE_FOR_IMPORT":
            (async function () {
                console.log("SW: Preparing for import, closing DB.")
                if (dbPromise) {
                    try {
                        const db = await dbPromise
                        db.close()
                    } catch (err) {
                        console.warn("SW: Error closing DB during import prep, this is likely okay.", err)
                    } finally {
                        dbPromise = null
                    }
                }
                if (e.source) {
                    e.source.postMessage({ type: "IMPORT_READY" })
                }
            })()
            break
    }
})

/**
 * Creates a ReadableStream to serve a large file directly from its chunks in IndexedDB.
 * This avoids loading the entire file into memory.
 * @param {IDBDatabase} db The database instance.
 * @param {number} fileId The primary key of the file.
 * @returns {ReadableStream}
 */
function streamFileFromChunks(db, fileId) {
    return new ReadableStream({
        async start(controller) {
            try {
                const transaction = db.transaction("FileChunks", "readonly")
                const chunkStore = transaction.objectStore("FileChunks")
                const index = chunkStore.index("by_file")
                const allChunks = await promisifyRequest(index.getAll(IDBKeyRange.only(fileId)))

                if (!allChunks || allChunks.length === 0) {
                    controller.close()
                    return
                }

                // Sort chunks by their index to ensure correct order
                allChunks.sort((a, b) => a.index - b.index)

                for (const chunk of allChunks) {
                    controller.enqueue(new Uint8Array(chunk.data))
                }

                controller.close()
            } catch (error) {
                console.error("Streaming error:", error)
                controller.error(error)
            }
        }
    })
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
 * Quickly checks if any regex rule applies to a given file path.
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

async function generateResponseForVirtualFile(folderName, requestedFilePath, event, requestId, cacheKey) {
    const decodedFolderName = decodeURIComponent(folderName)
    let decodedFilePath = decodeURIComponent(requestedFilePath)

    if (!decodedFilePath || decodedFilePath.endsWith("/")) {
        decodedFilePath = (decodedFilePath || "") + "index.html"
    }

    const db = await getDb()
    const transaction = db.transaction([FILES_SN, FOLDERS_SN], "readonly")

    const fileMetadataPromise = (async () => {
        const index = transaction.objectStore(FILES_SN).index("lookup")
        const lookupKey = `${decodedFolderName}/${decodedFilePath}`
        let metadata = await promisifyRequest(index.get(lookupKey))

        if (!metadata && event.request.mode === "navigate") {
            const fallbackPath = "index.html"
            const fallbackKey = `${decodedFolderName}/${fallbackPath}`
            const fallbackMetadata = await promisifyRequest(index.get(fallbackKey))
            if (fallbackMetadata) {
                decodedFilePath = fallbackPath
                metadata = fallbackMetadata
            }
        }
        return metadata
    })()

    const folderDataPromise = promisifyRequest(transaction.objectStore(FOLDERS_SN).get(decodedFolderName))

    const [fileMetadata, folderData] = await Promise.all([
        fileMetadataPromise,
        folderDataPromise
    ])
    const requestData = ruleStore.get(requestId) || {}

    if (!fileMetadata) {
        return new Response(`File not found: ${requestedFilePath}`, { status: 404 })
    }

    const fileType = fileMetadata.type || getMimeType(decodedFilePath) || "application/octet-stream"
    const regexApplies = doesRegexApplyToFile(decodedFilePath, requestData.regex)
    const isEncrypted = folderData?.encryptionType === "pdf"

    const headers = applyCustomHeaders({ "Content-Type": fileType }, decodedFilePath, requestData.headers)
    let response

    const mustBuffer = regexApplies || isEncrypted

    if (mustBuffer) {
        let fileBuffer = fileMetadata.buffer ? await fileMetadata.buffer.arrayBuffer() : await reassembleFileFromChunks(db, fileMetadata.id)
        if (!fileBuffer) return new Response("Could not load file content for processing.", { status: 500 })

        if (isEncrypted) {
            const key = decryptionKeyStore.get(requestId)
            if (!key) return new Response("Decryption key expired or not found", { status: 403 })
            try {
                const iv = fileBuffer.slice(0, 12)
                const encryptedData = fileBuffer.slice(12)
                fileBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData)
            } catch (e) {
                console.error("SW Decryption Error:", e)
                return new Response("Decryption failed in Service Worker", { status: 500 })
            }
        }

        const finalBuffer = applyRegexRules(decodedFilePath, fileBuffer, fileType, requestData.regex)
        headers["Content-Length"] = finalBuffer.byteLength
        response = new Response(finalBuffer, { headers })
    } else {
        if (fileMetadata.buffer) {
            const fileBuffer = await fileMetadata.buffer.arrayBuffer()
            headers["Content-Length"] = fileBuffer.byteLength
            response = new Response(fileBuffer, { headers })
        } else if (fileMetadata.size) {
            const stream = streamFileFromChunks(db, fileMetadata.id)
            headers["Content-Length"] = fileMetadata.size
            response = new Response(stream, { headers })
        } else {
            return new Response("Could not load file content", { status: 500 })
        }
    }

    if (response.ok && !regexApplies && event.request.mode !== "navigate") {
        const cache = await caches.open(CACHE_NAME)
        cache.put(event.request, response.clone())
    }

    return response
}