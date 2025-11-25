import {CACHE_NAME,clientSessionStore,DBN,DB_VERSION,dbPromise,FILES_SN,FOLDERS_SN,FULL_APP_SHELL_URLS,promisifyRequest,promisifyTransaction,getDb,getMimeType,escapeRegex,applyRegexRules} from './util'
// A single variable to hold data for the very next navigation request.
let pendingNavData = null
function cleanupExpiredStores() {
    const now = Date.now()
    for (const [clientId, sessionData] of clientSessionStore.entries()) {
        if (now - sessionData.timestamp > (STORE_ENTRY_TTL * 2)) {
            clientSessionStore.delete(clientId)
            console.log(`SW: Cleaned up expired session for client ${clientId}.`)
        }
    }
}

cleanupExpiredStores()

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

// Service worker activation cleans up stuff!
self.addEventListener("activate", e => {
    e.waitUntil(
        (async () => {
            // Standard cache cleanup
            const keys = await caches.keys()
            await Promise.all(
                keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null)
            )

            // Ensure the service worker takes control of the page immediately
            await self.clients.claim()

            // Now, wait for the database to be ready and notify clients.
            try {
                await getDb() // This ensures the DB connection is established.
                const allClients = await self.clients.matchAll({ includeUncontrolled: true })
                for (const client of allClients) {
                    client.postMessage({ type: "SW_READY" })
                }
                console.log(`SW: Database is ready, posted "SW_READY" to clients.`)
            } catch (err) {
                console.error("SW: Failed to initialize database during activation:", err)
            }
        })()
    )
})

self.addEventListener("fetch", e => {
    const { request, clientId } = e
    const url = new URL(request.url)

    const isAppShellRequest = FULL_APP_SHELL_URLS.includes(request.url)
    const isVirtualRequest = url.pathname.startsWith(virtualPathPrefix)

    if (!isAppShellRequest && !isVirtualRequest && request.referrer) {
        const referrerUrl = new URL(request.referrer)
        if (referrerUrl.pathname.startsWith(virtualPathPrefix)) {
            // The request is coming from within one of your virtual folders.
            const pathParts = referrerUrl.pathname.substring(virtualPathPrefix.length).split("/")
            const folderName = pathParts[0]

            const newUrl = `${self.location.origin}/n/${folderName}${url.pathname}`
            e.respondWith(fetch(newUrl))
            return; // Stop processing here
        }
    }

    // Main file serving logic
    e.respondWith((async () => {
        if (url.pathname.startsWith(virtualPathPrefix)) {
            // Handle POST/PUT requests for saving files
            if (request.method === "POST" || request.method === "PUT") {
                try {
                    const pathParts = url.pathname.split("/").slice(2)
                    const folderName = decodeURIComponent(pathParts[0])
                    const filePath = decodeURIComponent(pathParts.slice(1).join("/"))
                    const newContent = await request.arrayBuffer()
                    const db = await getDb()
                    const transaction = db.transaction([FILES_SN], "readwrite")
                    const fileStore = transaction.objectStore(FILES_SN)
                    const index = fileStore.index("lookup")
                    const fileRecord = await promisifyRequest(index.get(`${folderName}/${filePath}`))
                    const newRecord = {
                        folderName: folderName,
                        path: filePath,
                        buffer: new Blob([newContent]),
                        type: request.headers.get("content-type") || "application/octet-stream",
                        lookupPath: `${folderName}/${filePath}`
                    }
                    if (fileRecord) newRecord.id = fileRecord.id
                    await promisifyRequest(fileStore.put(newRecord))
                    await promisifyTransaction(transaction)
                    return new Response(JSON.stringify({ success: true }), { status: 200, headers: { "Content-Type": "application/json" } })
                } catch (err) {
                    return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers: { "Content-Type": "application/json" } })
                }
            }

            // Handle all virtual file GET requests
            let session = clientSessionStore.get(clientId)
            if (!session && pendingNavData) {
                session = pendingNavData
            }
            if (request.mode === "navigate" && pendingNavData) {
                clientSessionStore.set(clientId, { ...pendingNavData, timestamp: Date.now() })
                setTimeout(() => { if (pendingNavData === session) pendingNavData = null }, 2000)
            }

            const hasRules = session && session.rules && session.rules.trim().length > 0
            const hasHeaders = session && session.headers && session.headers.trim().length > 0

            // If no rules are active, use a cache-first strategy for performance.
            if (!hasRules && !hasHeaders) {
                const cachedResponse = await caches.match(request)
                if (cachedResponse) return cachedResponse
            }

            // If rules ARE active, or if the item is not in the cache, generate a fresh response.
            const response = await generateResponseForVirtualFile(request, session)

            // Only cache the response if it's successful and no rules were applied.
            if (response.ok && !hasRules && !hasHeaders) {
                const cache = await caches.open(CACHE_NAME)
                cache.put(request, response.clone())
            }

            return response
        }

        // If it's not a virtual file, check if it's a core app shell file.
        if (FULL_APP_SHELL_URLS.includes(request.url)) {
            return caches.match(request).then(res => res || fetch(request))
        }

        // Fallback for any other request
        return fetch(request).catch(() => new Response("Network error", {
            status: 500,
            headers: { "Cache-Control": "no-store" }
        }))
    })())
})

self.addEventListener("message", e => {
    if (!e.data) return
    const clientId = e.source.id
    if (!clientId) return
    switch (e.data.type) {
        case "SET_RULES":
            const { requestId, rules, headers, key } = e.data

            // Prime pendingNavData with a single object containing all session data.
            // This is the correct handoff mechanism.
            pendingNavData = {
                rules: rules,
                headers: headers,
                key: key
            }

            setTimeout(() => {
                if (pendingNavData && pendingNavData.rules === rules) {
                    pendingNavData = null
                }
            }, 5000)

            if (e.source) {
                e.source.postMessage({ type: "RULES_READY", requestId })
            }
            break

        case "PRIME_FOR_NAVIGATE":
            // Store the data (rules, headers, decryption key) for the next tab to claim.
            pendingNavData = e.data.data
            // Set a timeout to clear this data if a navigation never happens.
            setTimeout(() => {
                if (pendingNavData === e.data.data) pendingNavData = null
            }, 5000)
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
                    if (e.source) {
                        e.source.postMessage({ type: "CACHE_INVALIDATED", folderName: e.data.folderName })
                    }
                }
            })()
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

        // This regex is now identical to the one in applyRegexRules, ensuring consistent behavior
        const operatorMatch = matchPart.match(/^(.*?)\s+(\$|\$\$|\|\||\|)\s+(.*)$/s)
        if (!operatorMatch) continue

        const fileMatch = operatorMatch[1].trim()
        try {
            const fileRegex = new RegExp(fileMatch === "*" ? ".*" : fileMatch)
            if (fileRegex.test(filePath)) {
                return true // A rule matches this file, so it should not be cached
            }
        } catch (e) {
            // This prevents a bad user-provided regex from crashing the service worker
            console.warn(`Invalid file match regex in rule: "${line}"`, e)
        }
    }
    return false // No rules matched this file
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

async function generateResponseForVirtualFile(request, session) {
    session = session || {}
    const { mode } = request
    const url = new URL(request.url)

    const requestPath = url.pathname
    const virtualPath = requestPath.substring(virtualPathPrefix.length)
    const pathParts = virtualPath.split("/")
    const folderName = pathParts[0]
    let decodedFilePath = pathParts.slice(1).join("/")

    decodedFilePath = decodedFilePath.replace(/\/+/g, "/")

    if (!decodedFilePath || decodedFilePath.endsWith("/")) {
        decodedFilePath = (decodedFilePath || "") + "index.html"
    }
    const db = await getDb()
    const transaction = db.transaction([FILES_SN, FOLDERS_SN], "readonly") // Locate stuff
    const fileStore = transaction.objectStore(FILES_SN)
    const folderStore = transaction.objectStore(FOLDERS_SN)
    const lookupIndex = fileStore.index("lookup")

    let fileMetadata = await promisifyRequest(lookupIndex.get(`${folderName}/${decodedFilePath}`))
    const folderData = await promisifyRequest(folderStore.get(folderName))

    if (!fileMetadata && mode === "navigate") {
        const fallbackPath = "index.html"
        const fallbackMetadata = await promisifyRequest(lookupIndex.get(`${folderName}/${fallbackPath}`))
        if (fallbackMetadata) {
            decodedFilePath = fallbackPath
            fileMetadata = fallbackMetadata
        }
    }

    if (!fileMetadata) {
        return new Response(`File not found: ${decodedFilePath}`, {
            status: 404,
            headers: { "Cache-Control": "no-store" }
        })
    }

    const fileType = fileMetadata.type || getMimeType(decodedFilePath) || "application/octet-stream"
    const isEncrypted = folderData?.encryptionType === "pdf"

    let fileBuffer = fileMetadata.buffer ? await fileMetadata.buffer.arrayBuffer() : await reassembleFileFromChunks(db, fileMetadata.id)

    if (!fileBuffer) {
        return new Response("Could not load file content for processing.", { status: 500 })
    }

    if (isEncrypted) {
        const key = session.key
        if (!key) {
            return new Response("Decryption key not found for this client session", { status: 403 })
        }
        try {
            const iv = fileBuffer.slice(0, 12)
            const encryptedData = fileBuffer.slice(12)
            fileBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData)
        } catch (e) {
            return new Response("Decryption failed in Service Worker", { status: 500 })
        }
    }

    const finalBuffer = applyRegexRules(decodedFilePath, fileBuffer, fileType, session.rules)
    const headers = applyCustomHeaders({ "Content-Type": fileType, "Content-Length": finalBuffer.byteLength }, decodedFilePath, session.headers)

    return new Response(finalBuffer, { headers })
}