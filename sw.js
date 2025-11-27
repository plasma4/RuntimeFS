// A single variable to hold data for the very next navigation request.
let pendingNavData = null
// A single map to store session data (rules, keys) for each client tab.
const clientSessionStore = new Map()

const RFS_PREFIX = "rfs"
const SYSTEM_FILE = "rfs_system.json"
const CACHE_NAME = "fc"
const APP_SHELL_FILES = ["./", "./index.html", "./main.js", "./cbor-x.js"]
const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(file => new URL(file, self.location.href).href)

const STORE_ENTRY_TTL = 30000 // 30 seconds
const basePath = new URL("./", self.location).pathname
const virtualPathPrefix = basePath + "n/"

// Cache for the system.json registry to avoid disk reads on every request
let registryCache = null

function cleanupExpiredStores() {
    const now = Date.now()
    for (const [clientId, sessionData] of clientSessionStore.entries()) {
        if (now - sessionData.timestamp > STORE_ENTRY_TTL) {
            clientSessionStore.delete(clientId)
        }
    }
}

setInterval(cleanupExpiredStores, 60000)

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function compileRules(rulesString) {
    if (!rulesString || !rulesString.trim()) return []
    const compiled = []
    const lines = rulesString.trim().split(/\r?\n/)

    for (const line of lines) {
        const parts = line.split("->")
        if (parts.length < 2) continue

        const matchPart = parts[0].trim()
        const replacePart = parts.slice(1).join("->").trim()
        const operatorMatch = matchPart.match(/^(.*?)\s+(\$|\$\$|\|\||\|)\s+(.*)$/s)

        if (!operatorMatch) continue

        const [, fileMatch, operator, searchPattern] = operatorMatch
        const fileRegex = new RegExp(fileMatch.trim() === "*" ? ".*" : fileMatch.trim())

        let searchRegex
        try {
            switch (operator) {
                case "|": searchRegex = new RegExp(searchPattern, "g"); break
                case "$": searchRegex = new RegExp(escapeRegex(searchPattern), "g"); break
                case "||": searchRegex = new RegExp(searchPattern); break
                case "$$": searchRegex = new RegExp(escapeRegex(searchPattern)); break
            }
        } catch (e) { continue }

        if (searchRegex) compiled.push({ fileRegex, searchRegex, replacePart })
    }
    return compiled
}

function applyRegexRules(filePath, fileBuffer, fileType, compiledRules) {
    // Optimization: Don't run regex on binaries or huge files
    if (!/^(text\/|application\/(javascript|json|xml|x-javascript|typescript))/.test(fileType)) return fileBuffer
    if (fileBuffer.byteLength > 10 * 1024 * 1024) return fileBuffer

    try {
        let content = new TextDecoder().decode(fileBuffer)
        let modified = false

        for (const rule of compiledRules) {
            if (rule.fileRegex.test(filePath)) {
                if (rule.searchRegex.test(content)) {
                    content = content.replace(rule.searchRegex, rule.replacePart)
                    modified = true
                }
            }
        }
        return modified ? new TextEncoder().encode(content).buffer : fileBuffer
    } catch (e) {
        console.error(`Error applying regex rules to ${filePath}:`, e)
        return fileBuffer
    }
}

async function getRegistry() {
    if (registryCache) return registryCache
    try {
        const root = await navigator.storage.getDirectory()
        const handle = await root.getFileHandle(SYSTEM_FILE)
        const file = await handle.getFile()
        registryCache = JSON.parse(await file.text())
    } catch (e) {
        registryCache = {}
    }
    return registryCache
}

self.addEventListener("install", async function () {
    const cache = await caches.open(CACHE_NAME)
    await Promise.all(APP_SHELL_FILES.map(async (url) => {
        try {
            const response = await fetch(url, { cache: "reload" })
            if (response.ok) await cache.put(url, response)
        } catch (e) { console.warn("Failed to cache app shell file:", url) }
    }))
    await self.skipWaiting()
})

self.addEventListener("activate", e => {
    e.waitUntil((async function () {
        await self.clients.claim()
        registryCache = null
        try { await navigator.storage.getDirectory() } catch (err) { }
        const allClients = await self.clients.matchAll({ includeUncontrolled: true })
        for (const client of allClients) client.postMessage({ type: "SW_READY" })
    })())
})

self.addEventListener("message", e => {
    if (!e.data) return
    const clientId = e.source ? e.source.id : null

    switch (e.data.type) {
        case "SET_RULES":
            const { rules, headers, key } = e.data
            const compiledRules = compileRules(rules)

            // Set data for pending navigation
            pendingNavData = { rules, compiledRules, headers, key }

            // Set data for current client (if any)
            if (clientId) {
                const s = clientSessionStore.get(clientId) || {}
                s.rules = rules
                s.compiledRules = compiledRules
                s.headers = headers
                if (key) s.key = key
                clientSessionStore.set(clientId, s)
            }

            // Important: Reply to unlock main.js
            if (e.ports && e.ports[0]) e.ports[0].postMessage("ACK")

            setTimeout(() => {
                if (pendingNavData && pendingNavData.key === key) pendingNavData = null
            }, 5000)
            break

        case "INVALIDATE_CACHE":
            registryCache = null
            e.waitUntil((async function () {
                const allClients = await self.clients.matchAll({ includeUncontrolled: true })
                for (const client of allClients) {
                    if (client.id !== clientId) client.postMessage({ type: "INVALIDATE_CACHE", folderName: e.data.folderName })
                }
            })())
            break

        case "PREPARE_FOR_IMPORT":
            registryCache = null
            if (e.source) e.source.postMessage({ type: "IMPORT_READY" })
            break
    }
})

function parseCustomHeaders(rulesString) {
    if (!rulesString || !rulesString.trim()) return []
    const rules = []
    rulesString.trim().split("\n").forEach(line => {
        line = line.trim()
        if (line.startsWith("#") || line === "") return
        const parts = line.split("->")
        if (parts.length < 2) return
        const [globPart, ...headerParts] = parts
        const glob = globPart.trim()
        const fullHeaderString = headerParts.join("->").trim()
        const colonIndex = fullHeaderString.indexOf(":")
        if (colonIndex === -1) return

        const headerName = fullHeaderString.substring(0, colonIndex).trim()
        const headerValue = fullHeaderString.substring(colonIndex + 1).trim()

        try {
            const regex = new RegExp("^" + glob.replace(/\./g, "\\.").replace(/\*/g, ".*").replace(/\?/g, ".") + "$")
            rules.push({ regex, header: headerName, value: headerValue })
        } catch (e) { }
    })
    return rules
}

function applyCustomHeaders(baseHeaders, filePath, rulesString) {
    if (!rulesString) return baseHeaders
    const customHeaderRules = parseCustomHeaders(rulesString)
    for (const rule of customHeaderRules) {
        if (rule.regex.test(filePath)) {
            baseHeaders[rule.header] = rule.value
        }
    }
    return baseHeaders
}

function getMimeType(filePath) {
    const ext = filePath.split(".").pop().toLowerCase()
    const mimeTypes = {
        "html": "text/html", "htm": "text/html", "css": "text/css",
        "js": "application/javascript", "mjs": "application/javascript",
        "json": "application/json", "xml": "application/xml",
        "txt": "text/plain", "md": "text/markdown", "csv": "text/csv",
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif",
        "webp": "image/webp", "svg": "image/svg+xml", "ico": "image/x-icon",
        "mp3": "audio/mpeg", "wav": "audio/wav", "ogg": "audio/ogg",
        "mp4": "video/mp4", "webm": "video/webm", "wasm": "application/wasm",
        "pdf": "application/pdf", "zip": "application/zip",
        // Mono / .NET
        "dll": "application/octet-stream",
        "pdb": "application/octet-stream",
        "dat": "application/octet-stream",
        "bin": "application/octet-stream"
    }
    return mimeTypes[ext] || "application/octet-stream"
}

// FETCH HANDLER
self.addEventListener("fetch", e => {
    const { request, clientId } = e
    const url = new URL(request.url)

    // 1. Internal App Shell
    if (FULL_APP_SHELL_URLS.includes(request.url)) {
        e.respondWith((async () => {
            const cached = await caches.match(request)
            return cached || fetch(request)
        })())
        return
    }

    // 2. Virtual File Requests (e.g. /n/Folder/...)
    if (url.pathname.startsWith(virtualPathPrefix)) {
        let session = clientSessionStore.get(clientId)
        if (!session && pendingNavData) session = pendingNavData

        // Persist session on navigation
        if (request.mode === "navigate" && pendingNavData) {
            clientSessionStore.set(clientId, { ...pendingNavData, timestamp: Date.now() })
            setTimeout(() => { if (pendingNavData === session) pendingNavData = null }, 2000)
        }

        e.respondWith(generateResponseForVirtualFile(request, session))
        return
    }

    // 3. Fallback for Relative Virtual Fetches
    // Fixes cases where /mscorlib.dll is requested instead of /n/Celeste/mscorlib.dll
    if (request.referrer && url.origin === self.location.origin) {
        try {
            const referrerUrl = new URL(request.referrer)
            if (referrerUrl.pathname.startsWith(virtualPathPrefix)) {
                // Check if this is arguably a sub-resource request meant for the virtual folder
                const pathParts = referrerUrl.pathname.substring(virtualPathPrefix.length).split("/")
                const folderName = pathParts[0]
                const newVirtualUrl = `${self.location.origin}/n/${folderName}${url.pathname}`

                e.respondWith(fetch(newVirtualUrl))
                return
            }
        } catch (err) { }
    }

    // 5. Standard Network Fetch
    e.respondWith(fetch(request))
})

async function generateResponseForVirtualFile(request, session) {
    try {
        const url = new URL(request.url)
        const { mode } = request

        const isFirefox = typeof InternalError !== "undefined"
        if (isFirefox && mode === "navigate" && !url.searchParams.has("boot")) {
            url.searchParams.set("boot", "1")
            return new Response(`<!DOCTYPE html><script>location.replace("${url.href}");</script>`, {
                headers: { "Content-Type": "text/html" }
            })
        }

        if ((!session || !Object.keys(session).length) && typeof pendingNavData !== "undefined") {
            session = pendingNavData
        }
        session = session || {}

        const virtualPath = url.pathname.substring(virtualPathPrefix.length)
        const pathParts = virtualPath.split("/").map(p => decodeURIComponent(p))
        const folderName = pathParts[0]
        let relativePath = pathParts.slice(1).join("/")

        if (!relativePath || relativePath.endsWith("/")) relativePath += "index.html"

        let root, registry
        try {
            root = await navigator.storage.getDirectory()
            registry = await getRegistry()
        } catch (e) {
            return new Response("System error: OPFS inaccessible", { status: 500 })
        }

        const folderData = registry[folderName] || {}

        async function getFileHandle(dir, name, path) {
            try {
                const parts = [RFS_PREFIX, name, ...path.split("/")]
                let curr = dir
                for (let i = 0; i < parts.length - 1; i++) {
                    curr = await curr.getDirectoryHandle(parts[i])
                }
                return await curr.getFileHandle(parts[parts.length - 1])
            } catch (e) { return null }
        }

        let handle = await getFileHandle(root, folderName, relativePath)

        if (!handle && mode === "navigate") {
            handle = await getFileHandle(root, folderName, "index.html")
            if (handle) relativePath = "index.html"
        } else if (!handle) {
            return new Response("File not found", { status: 404 })
        }

        const file = await handle.getFile()
        let totalSize = file.size

        let contentType = file.type
        if (!contentType || contentType === "application/octet-stream") {
            contentType = getMimeType(relativePath) || "application/octet-stream"
        }

        let compiledRules = session.compiledRules
        if (!compiledRules && folderData.rules) compiledRules = compileRules(folderData.rules)

        const isEncrypted = folderData.encryptionType === "password"
        const hasRegex = compiledRules && compiledRules.length > 0

        const isTooLarge = totalSize > 20 * 1024 * 1024
        const needsProcessing = (isEncrypted || hasRegex) && !isTooLarge

        if (isEncrypted && isTooLarge) {
            return new Response("File too large to decrypt in browser", { status: 413 })
        }

        const baseHeaders = {
            "Content-Type": contentType,
            "Cache-Control": "no-store",
            "Accept-Ranges": "bytes",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin"
        }

        const finalHeaders = applyCustomHeaders(baseHeaders, relativePath, session.headers || folderData.headers)

        if (!needsProcessing) {
            const rangeHeader = request.headers.get("Range")

            if (rangeHeader) {
                const parts = rangeHeader.replace(/bytes=/, "").split("-")
                const start = parseInt(parts[0], 10)
                const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1

                if (start >= totalSize || end >= totalSize) {
                    return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${totalSize}` } })
                }

                const chunkSize = (end - start) + 1
                const slicedBlob = file.slice(start, end + 1)

                finalHeaders["Content-Range"] = `bytes ${start}-${end}/${totalSize}`
                finalHeaders["Content-Length"] = chunkSize

                return new Response(slicedBlob, { status: 206, headers: finalHeaders })
            }

            finalHeaders["Content-Length"] = totalSize
            return new Response(file, { headers: finalHeaders })
        }

        let buffer = await file.arrayBuffer()

        if (isEncrypted) {
            const key = session.key
            if (!key) return new Response("Key required: Session lost!", { status: 403 })
            try {
                const iv = buffer.slice(0, 12)
                const data = buffer.slice(12)
                buffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data)
            } catch (e) {
                return new Response("Decryption failed", { status: 500 })
            }
        }

        if (hasRegex) {
            buffer = applyRegexRules(relativePath, buffer, contentType, compiledRules)
        }

        const processedSize = buffer.byteLength
        const rangeHeader = request.headers.get("Range")

        if (rangeHeader) {
            const parts = rangeHeader.replace(/bytes=/, "").split("-")
            let start = parseInt(parts[0], 10)
            let end = parts[1] ? parseInt(parts[1], 10) : processedSize - 1

            if (isNaN(start)) start = 0
            if (isNaN(end)) end = processedSize - 1
            if (end >= processedSize) end = processedSize - 1

            if (start >= processedSize) {
                return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${processedSize}` } })
            }

            const chunkSize = (end - start) + 1
            const slicedBuffer = buffer.slice(start, end + 1)

            finalHeaders["Content-Range"] = `bytes ${start}-${end}/${processedSize}`
            finalHeaders["Content-Length"] = chunkSize

            return new Response(slicedBuffer, { status: 206, headers: finalHeaders })
        }

        finalHeaders["Content-Length"] = processedSize
        return new Response(buffer, { headers: finalHeaders })

    } catch (e) {
        console.error("SW error:", e)
        return new Response("Internal error", { status: 500 })
    }
}