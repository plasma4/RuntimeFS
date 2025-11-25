
// A single map to store session data (rules, keys) for each client tab.
export const clientSessionStore = new Map()

export const DBN = "FileCacheDB"
export const FOLDERS_SN = "Folders"
export const FILES_SN = "Files"
export const RULES_SN = "Rules"
export const DB_VERSION = 11 // Version 1.1

export const CACHE_NAME = "fc"
export const APP_SHELL_FILES = ["./", "./index.html", "./main.js", "./cbor-x.js"] // core files

export const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(file => new URL(file, self.location.href).href)

// Promise for the IndexedDB connection.
export let dbPromise = null

export const STORE_ENTRY_TTL = 30000 // 30 seconds

export const basePath = new URL("./", self.location).pathname
export const virtualPathPrefix = basePath + "n/"



/**
 * Promisifies an IndexedDB request.
 * @param {IDBRequest} req The IndexedDB request.
 * @returns {Promise<any>} A promise that resolves with the request result or rejects on error.
 */
export function promisifyRequest(req) {
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
export function promisifyTransaction(transaction) {
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
export function getMimeType(filePath) {
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
export function escapeRegex(string) {
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
export function applyRegexRules(filePath, fileBuffer, fileType, regexRules) {
    if (!regexRules || !regexRules.trim()) return fileBuffer

    // A more inclusive check to ensure JS, JSON, and other text files are processed
    if (!/^(text\/|application\/(javascript|json|xml|x-javascript))/.test(fileType)) return fileBuffer

    try {
        let content = new TextDecoder().decode(fileBuffer)
        const rules = regexRules.trim().split("\n")

        for (const line of rules) {
            const parts = line.split("->")
            if (parts.length < 2) continue

            const matchPart = parts[0].trim()
            // This correctly handles cases where "->" might exist in the replacement string
            const replacePart = parts.slice(1).join("->").trim()

            // Use a robust regex that correctly parses the file match, operator, and search pattern
            const operatorMatch = matchPart.match(/^(.*?)\s+(\$|\$\$|\|\||\|)\s+(.*)$/s)
            if (!operatorMatch) continue

            const [, fileMatch, operator, searchPattern] = operatorMatch
            const fileRegex = new RegExp(fileMatch.trim() === "*" ? ".*" : fileMatch.trim())

            // If the rule's file path doesn't match, skip to the next rule
            if (!fileRegex.test(filePath)) continue

            let searchRegex
            switch (operator) {
                case "|": // User provides a full regex pattern
                    searchRegex = new RegExp(searchPattern, "g")
                    break
                case "$": // User provides plain text to be searched
                    searchRegex = new RegExp(escapeRegex(searchPattern), "g")
                    break
                case "||": // Single-match version of regex
                    searchRegex = new RegExp(searchPattern)
                    break
                case "$$": // Single-match version of plain text
                    searchRegex = new RegExp(escapeRegex(searchPattern))
                    break
            }

            if (searchRegex) {
                content = content.replace(searchRegex, replacePart)
            }
        }
        return new TextEncoder().encode(content).buffer
    } catch (e) {
        console.error(`Error applying regex rules to ${filePath}:`, e)
        return fileBuffer
    }
}

/**
 * Gets the IndexedDB connection promise, creating it if it doesn't exist.
 * @returns {Promise<IDBDatabase>} A promise that resolves with the DB instance.
 */
export function getDb() {
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