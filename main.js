// Constants for IndexedDB database names and version.
const DBN = "FileCacheDB"
const FOLDERS_SN = "Folders"
const FILES_SN = "Files" // New object store for individual files
const META_SN = "Metadata"
const DB_VERSION = 3
const CHUNK_SIZE = 4 * 1024 * 1024 // 4MB chunks
// Fetches all folder names from IndexedDB and displays them in the UI.
let isListingFolders = false

// Helper function to wrap IndexedDB requests in a Promise
function promisifyRequest(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
}

function promisifyTransaction(transaction) {
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve()
        transaction.onerror = () => reject(transaction.error)
        transaction.onabort = () => reject(transaction.error || new DOMException("Transaction aborted"))
    })
}

let currentlyBusy = false
function setUiBusy(isBusy) {
    currentlyBusy = isBusy
    Array.from(document.getElementsByTagName("button")).forEach(button => button.disabled = currentlyBusy)
}

// Request persistent storage to prevent the browser from clearing data automatically.
navigator.storage.persist().then(persistent => {
    if (persistent) {
        console.log("Storage will not be cleared except by explicit user action.")
    } else {
        console.log("Storage may be cleared by the browser.")
    }
})

let dbPromise = null
function getDb() {
    if (!dbPromise) {
        // console.log("No DB connection promise, creating a new one.")
        dbPromise = new Promise((resolve, reject) => {
            const request = indexedDB.open(DBN, DB_VERSION)
            request.onupgradeneeded = function (e) {
                const db = e.target.result
                if (!db.objectStoreNames.contains(FOLDERS_SN)) {
                    db.createObjectStore(FOLDERS_SN, { keyPath: "id" })
                }
                if (!db.objectStoreNames.contains(FILES_SN)) {
                    // The keyPath is now "id" and we create the index for lookups.
                    const fileStore = db.createObjectStore(FILES_SN, { keyPath: "id", autoIncrement: true })
                    fileStore.createIndex("folder", ["folderName", "path"], { unique: true })
                }
                // Add the new object store for chunks.
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
                db = e.target.result // Assign to the global 'db' variable
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

// Immediately initialize the DB on load
getDb().then(() => listFolders())

// Global variables to hold state for the currently managed folder.
let folderName, dirHandle, observer
// An array to keep track of file system changes for syncing.
let changes = []

async function uploadFolder() {
    const folderNameInput = document.getElementById("folderName")
    const name = folderNameInput.value.trim()
    if (!name) {
        alert("Please enter a name for the folder.")
        return
    }

    var resetUI = true
    setUiBusy(true)
    try {
        if (!window.showDirectoryPicker) {
            document.getElementById("folderUploadFallbackInput").click()
            resetUI = false
            return
        }

        const localDirHandle = await window.showDirectoryPicker({ mode: "read" })
        dirHandle = localDirHandle
        folderName = name
        let files = {}

        // Check for manifest.enc to determine if the folder is encrypted
        try {
            const manifestHandle = await localDirHandle.getFileHandle("manifest.enc")
            console.log("Encrypted folder detected. Starting decryption process...")
            files = await decryptAndLoadFolder(localDirHandle, manifestHandle)
        } catch (e) {
            // If not found, treat as a plaintext folder
            if (e.name === "NotFoundError") {
                files = await getFilesRecursively(localDirHandle)
                if (observer) {
                    observer.disconnect()
                }

                try {
                    // Create and start the new observer to watch the local folder for changes.
                    observer = new FileSystemObserver((records) => {
                        console.log(`${records.length} file system change(s) detected.`)
                        changes.push(...records)
                    })
                    observer.observe(dirHandle, { recursive: true })
                } catch (e) {
                    if (e.name === "NotSupportedError") {
                        // Older browser/implementation perhaps? Can't observe then.
                        console.error("Cannot observe directories for modifications.")
                        console.warn(e)
                    } else {
                        throw e
                    }
                }

                changes.length = 0
            } else {
                throw e
            }
        }
        // New function to handle the updated database schema
        await processAndStoreFolder(name, files)

        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
        }
        folderNameInput.value = ""
        document.getElementById("openFolderName").value = name
        await listFolders()
    } catch (err) {
        if (err.name !== "AbortError") {
            console.error("Upload error:", err)
            alert("An error occurred during upload: " + err.message)
        }
    } finally {
        if (resetUI) setUiBusy(false)
    }
}

function getFilesFromEntryRecursively(dirEntry) {
    return new Promise((resolve, reject) => {
        const files = {}
        let entriesPending = 0
        let allEntriesRead = false

        const reader = dirEntry.createReader()

        const readEntries = () => {
            reader.readEntries(async (entries) => {
                if (entries.length === 0) {
                    // If no more entries are returned, we might be done.
                    if (entriesPending === 0) {
                        allEntriesRead = true
                        resolve(files)
                    }
                    return
                }

                entriesPending += entries.length

                for (const entry of entries) {
                    if (entry.isFile) {
                        entry.file(async (file) => {
                            const buffer = await file.arrayBuffer()
                            files[entry.fullPath.substring(1)] = { buffer, type: getMimeType(entry.name) || file.type }
                            entriesPending--
                            if (allEntriesRead && entriesPending === 0) resolve(files)
                        }, (err) => reject(err))
                    } else if (entry.isDirectory) {
                        try {
                            const subFiles = await getFilesFromEntryRecursively(entry)
                            Object.assign(files, subFiles)
                        } catch (err) {
                            reject(err)
                        } finally {
                            entriesPending--
                            if (allEntriesRead && entriesPending === 0) resolve(files)
                        }
                    }
                }
                // readEntries is recursive because the API might not return all entries in one go.
                readEntries()
            }, (err) => reject(err))
        }
        readEntries()
    })
}

async function decryptAndLoadFolder(dirHandle, manifestHandle) {
    const manifestFile = await manifestHandle.getFile()
    const manifestBuffer = await manifestFile.arrayBuffer()
    const manifestContent = new TextDecoder().decode(manifestBuffer)
    const manifestWrapper = JSON.parse(manifestContent)

    if (manifestWrapper.encryptionType === "password") {
        const password = prompt("Enter the password for this encrypted folder:")
        if (!password) throw new Error("Password not provided.")

        const salt = base64ToBuffer(manifestWrapper.salt)
        const iv = base64ToBuffer(manifestWrapper.iv)
        const payload = base64ToBuffer(manifestWrapper.payload)

        const key = await deriveKeyFromPassword(password, salt)
        const decryptedPayload = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, payload)
        const pathManifest = JSON.parse(new TextDecoder().decode(decryptedPayload))

        const decryptedFiles = {}
        for (const originalPath in pathManifest) {
            const uuid = pathManifest[originalPath]
            if (uuid === null) continue

            const fileHandle = await dirHandle.getFileHandle(uuid)
            const file = await fileHandle.getFile()
            const encryptedBufferWithIv = await file.arrayBuffer()

            const fileIv = encryptedBufferWithIv.slice(0, 12)
            const encryptedData = encryptedBufferWithIv.slice(12)

            const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fileIv }, key, encryptedData)
            decryptedFiles[originalPath] = { buffer: decryptedBuffer, type: getMimeType(originalPath) || "application/octet-stream" }
        }
        return decryptedFiles

    } else if (manifestWrapper.encryptionType === "rsa") {
        // Re-read the raw file for the RSA decryption function
        const rawManifestBuffer = await manifestFile.arrayBuffer()
        return await decryptFolder(dirHandle, rawManifestBuffer)

    } else {
        throw new Error("Unknown encryption type in manifest.enc")
    }
}

// Decrypts a folder that was encrypted using the public key method.
async function decryptFolder(dirHandle, encryptedManifestBuffer) {
    const privateKeyJwkString = localStorage.getItem("pk")
    if (!privateKeyJwkString) {
        throw new Error("Decryption failed: Private key not found in this browser's localStorage.")
    }
    const privateKeyJwk = JSON.parse(privateKeyJwkString)
    const privateKey = await crypto.subtle.importKey("jwk", privateKeyJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"])

    const decryptedManifestBuffer = await decryptBufferWithPrivateKey(privateKey, encryptedManifestBuffer)
    const manifestObject = JSON.parse(new TextDecoder().decode(decryptedManifestBuffer))
    const pathManifest = manifestObject.paths

    const decryptedFiles = {}
    for (const originalPath in pathManifest) {
        const uuid = pathManifest[originalPath]
        if (uuid === null) continue
        try {
            const fileHandle = await dirHandle.getFileHandle(uuid)
            const file = await fileHandle.getFile()
            const encryptedBuffer = await file.arrayBuffer()
            const decryptedBuffer = await decryptBufferWithPrivateKey(privateKey, encryptedBuffer)
            decryptedFiles[originalPath] = {
                buffer: decryptedBuffer,
                type: getMimeType(originalPath) || "application/octet-stream"
            }
        } catch (e) {
            console.error(`Failed to find or decrypt file for path: ${originalPath}`, e)
        }
    }
    console.log("Folder decryption complete.")
    return decryptedFiles
}

// Recursively reads all files from a directory handle and returns them as a map.
async function getFilesRecursively(dirHandle, path = "") {
    const files = {}
    for await (const entry of dirHandle.values()) {
        const newPath = path ? `${path}/${entry.name}` : entry.name
        if (entry.kind === "file") {
            const file = await entry.getFile()

            // CRITICAL FIX: Only load small files (<= 4MB) into memory.
            if (file.size <= CHUNK_SIZE) {
                files[newPath] = {
                    buffer: await file.arrayBuffer(), // Load ArrayBuffer for small files
                    type: getMimeType(newPath) || file.type
                }
            } else {
                files[newPath] = file
            }
        } else if (entry.kind === "directory") {
            Object.assign(files, await getFilesRecursively(entry, newPath))
        }
    }
    return files
}


async function scanFilesRecursively(dirHandle, path = "") {
    const fileMap = {}
    for await (const entry of dirHandle.values()) {
        const newPath = path ? `${path}/${entry.name}` : entry.name
        if (entry.kind === "file") {
            fileMap[newPath] = await entry.getFile()
        } else if (entry.kind === "directory") {
            fileMap[newPath] = null
            Object.assign(fileMap, await scanFilesRecursively(entry, newPath))
        }
    }
    return fileMap
}

// Opens a file from a virtual folder in a new tab.
async function openFile(overrideFolderName) {
    const folderName = overrideFolderName || document.getElementById("openFolderName").value.trim()
    const fileName = document.getElementById("fileName").value.trim()
    if (!folderName || !fileName) {
        alert(!folderName && !fileName ? "Please provide a folder and file name." : "Please provide both a folder and file name.")
        return
    }

    const db = await getDb()
    const folderData = await db.transaction(FOLDERS_SN).objectStore(FOLDERS_SN).get(folderName)

    if (!folderData) {
        alert(`Folder "${folderName}" not found.`)
        return
    }

    // Check if the folder is encrypted with a password.
    if (folderData.encryptionType === "pdf") {
        const password = prompt(`Enter password for folder "${folderName}":`)
        if (!password) return
        try {
            setUiBusy(true)
            const transaction = db.transaction(FILES_SN, "readonly")
            const fileStore = transaction.objectStore(FILES_SN)
            const fileIndex = fileStore.index("folder")
            const metadataFileRecord = await promisifyRequest(fileIndex.get([folderName, ".metadata"]))

            if (!metadataFileRecord) {
                throw new Error("Encryption metadata is missing for this folder.")
            }
            const salt = new Uint8Array(metadataFileRecord.content.buffer)
            const key = await deriveKeyFromPassword(password, salt)
            const requestId = crypto.randomUUID()
            if (navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({
                    type: "DECRYPT_KEY",
                    requestId: requestId,
                    key: key
                })
            }
            openUrl(folderName, fileName, requestId)
        } catch (e) {
            console.error("Decryption failed:", e)
            alert("Decryption failed. Please check the folder name and password.")
        } finally {
            setUiBusy(false)
        }
    } else {
        // If not encrypted, open the file directly.
        openUrl(folderName, fileName, null)
    }
}

function openUrl(folderName, fileName, decryptionRequestId) {
    const regexRules = document.getElementById("regex").value.trim()
    // Get the custom headers from the new textarea.
    const customHeaders = document.getElementById("headers").value.trim()

    const cacheBust = `v=${Date.now()}`
    let url = `/n/${encodeURIComponent(folderName)}/${encodeURIComponent(fileName)}?${cacheBust}`

    // A request ID is needed if there are regex rules OR custom headers.
    const finalRequestId = decryptionRequestId || ((regexRules || customHeaders) ? crypto.randomUUID() : null)

    if (finalRequestId) {
        url += `&reqId=${finalRequestId}`

        // If there's a request ID, send the context to the service worker.
        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: "CUSTOM_RULES",
                requestId: finalRequestId,
                rules: regexRules,     // Send regex rules
                headers: customHeaders // Send custom headers
            })
        }
    }

    window.open(url, "_blank")
}

async function syncFiles() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")
    if (changes.length === 0) return alert("No changes to sync.")

    setUiBusy(true)
    try {
        const count = await performSyncToDb()
        // Tell the SW to clear cache and WAIT for confirmation
        await invalidateCacheAndWait(folderName)
        alert(`Synced ${count} changes.`)
    } catch (e) {
        console.error(e)
        alert("Sync failed: " + e.message)
    } finally {
        setUiBusy(false)
    }
}

async function syncAndOpenFile() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")

    // Keep the UI locked so the user doesn't close the tab while waiting
    setUiBusy(true)
    try {
        if (changes.length > 0) {
            await performSyncToDb()
            await invalidateCacheAndWait(folderName)
        }
        console.log("Opening file...")
        openFile(folderName)
    } catch (e) {
        console.error(e)
        alert("Error: " + e.message)
    } finally {
        // Re-enable UI *after* the new tab has likely opened.
        setUiBusy(false)
    }
}

async function performSyncToDb() {
    if (changes.length === 0) {
        return 0
    }

    console.log(`Processing ${changes.length} changes for "${folderName}"...`)
    const db = await getDb()
    let updateCount = 0

    // Process each change sequentially to avoid race conditions
    for (const change of changes) {
        const path = change.relativePathComponents.join("/")
        try {
            let fileContent = null
            let operation = null
            let oldPath = null

            // Determine the operation and gather necessary file data first
            switch (change.type) {
                case "created":
                case "modified": {
                    operation = "put"
                    const fileHandle = await getHandleFromPath(dirHandle, path)
                    if (fileHandle?.kind === "file") {
                        const file = await fileHandle.getFile()
                        // Differentiate between large and small files for optimal storage
                        if (file.size > CHUNK_SIZE) {
                            fileContent = file // Keep as File object for streaming
                        } else {
                            fileContent = { // Load small files into memory
                                buffer: await file.arrayBuffer(),
                                type: getMimeType(path) || file.type
                            }
                        }
                    }
                    break
                }
                case "deleted": {
                    operation = "delete"
                    break
                }
                case "moved": {
                    operation = "move"
                    oldPath = change.relativePathMovedFrom.join("/")
                    const fileHandle = await getHandleFromPath(dirHandle, path)
                    if (fileHandle?.kind === "file") {
                        const file = await fileHandle.getFile()
                        if (file.size > CHUNK_SIZE) {
                            fileContent = file
                        } else {
                            fileContent = {
                                buffer: await file.arrayBuffer(),
                                type: getMimeType(path) || file.type
                            }
                        }
                    }
                    break
                }
            }

            if (operation) {
                const transaction = db.transaction([FILES_SN, "FileChunks"], "readwrite")
                const fileStore = transaction.objectStore(FILES_SN)
                const folderIndex = fileStore.index("folder")

                if (operation === "put" && fileContent) {
                    const existing = await promisifyRequest(folderIndex.get([folderName, path]))
                    if (existing?.id) {
                        // If it exists, first delete its old chunks to prevent orphans
                        await deleteFileAndChunks(db, existing.id)
                    }
                    // Now add the new version
                    if (fileContent instanceof File) {
                        await streamFileToDb(db, folderName, path, fileContent)
                    } else {
                        await storeBufferToDb(db, folderName, path, fileContent.buffer, fileContent.type)
                    }
                    updateCount++
                } else if (operation === "delete") {
                    const keyRequest = folderIndex.getKey([folderName, path])
                    const key = await promisifyRequest(keyRequest)
                    if (key) {
                        await deleteFileAndChunks(db, key)
                        updateCount++
                    }
                } else if (operation === "move" && fileContent) {
                    const oldKeyRequest = folderIndex.getKey([folderName, oldPath])
                    const oldKey = await promisifyRequest(oldKeyRequest)
                    if (oldKey) {
                        // Delete the old entry and its chunks
                        await deleteFileAndChunks(db, oldKey)
                    }
                    // Add the new entry
                    if (fileContent instanceof File) {
                        await streamFileToDb(db, folderName, path, fileContent)
                    } else {
                        await storeBufferToDb(db, folderName, path, fileContent.buffer, fileContent.type)
                    }
                    updateCount++
                }
                await promisifyTransaction(transaction)
            }
        } catch (e) {
            // Log and ignore individual file sync failures, allowing the sync to continue
            console.warn(`Skipping sync for path "${path}": ${e.message}`)
        }
    }

    changes.length = 0 // Clear changes after processing
    return updateCount
}

async function deleteFileAndChunks(db, fileId) {
    const transaction = db.transaction([FILES_SN, "FileChunks"], "readwrite")
    const fileStore = transaction.objectStore(FILES_SN)
    const chunkStore = transaction.objectStore("FileChunks")
    const chunkIndex = chunkStore.index("by_file")

    // Delete the main file record
    fileStore.delete(fileId)

    // Delete all chunks associated with this fileId
    const cursorReq = chunkIndex.openCursor(IDBKeyRange.only(fileId))
    await new Promise((resolve, reject) => {
        cursorReq.onsuccess = () => {
            const cursor = cursorReq.result
            if (cursor) {
                cursor.delete()
                cursor.continue()
            } else {
                resolve()
            }
        }
        cursorReq.onerror = () => reject(cursorReq.error)
    })
    return promisifyTransaction(transaction)
}

async function listFolders() {
    if (isListingFolders) {
        console.log("Folder listing already in progress. Skipping.")
        return
    }

    isListingFolders = true
    try {
        const db = await getDb()
        const transaction = db.transaction(FOLDERS_SN, "readonly")
        const store = transaction.objectStore(FOLDERS_SN)
        const allFolders = await promisifyRequest(store.getAll())

        const folderList = document.getElementById("folderList")
        folderList.innerHTML = "" // Clear the current list.

        const fragment = document.createDocumentFragment()
        allFolders.sort((a, b) => a.id.localeCompare(b.id))

        allFolders.forEach(folder => {
            const li = document.createElement("li")
            li.textContent = folder.encryptionType === "pdf" ? `[Locked] ${folder.id}` : folder.id
            fragment.appendChild(li)
        })
        folderList.appendChild(fragment)

    } catch (e) {
        console.error("Failed to list folders:", e)
        const folderList = document.getElementById("folderList")
        folderList.innerHTML = "<li>Error loading folders ):</li>"
    } finally {
        isListingFolders = false
    }
}

async function deleteFolder() {
    const folderName = document.getElementById("deleteFolderName").value.trim()
    if (!folderName) {
        alert("Please enter the name of the folder to delete.")
        return
    }
    if (!confirm(`Are you sure you want to remove the folder "${folderName}"?`)) return
    setUiBusy(true)
    try {
        const db = await getDb()

        const readTx = db.transaction([FILES_SN], "readonly")
        const fileIndex = readTx.objectStore(FILES_SN).index("folder")
        const fileKeysToDelete = await promisifyRequest(fileIndex.getAllKeys(IDBKeyRange.bound([folderName, ""], [folderName, "\uffff"])))
        await promisifyTransaction(readTx)

        if (fileKeysToDelete.length === 0) {
            // No files, just delete the folder entry
            const tx = db.transaction([FOLDERS_SN], "readwrite")
            await promisifyRequest(tx.objectStore(FOLDERS_SN).delete(folderName))
            await promisifyTransaction(tx)
        } else {
            const writeTx = db.transaction([FOLDERS_SN, FILES_SN, "FileChunks"], "readwrite")
            const folderStore = writeTx.objectStore(FOLDERS_SN)
            const fileStore = writeTx.objectStore(FILES_SN)
            const chunkStore = writeTx.objectStore("FileChunks")
            const chunkIndex = chunkStore.index("by_file")

            // Delete the main folder record
            folderStore.delete(folderName)

            // Loop through all file keys to delete files and their chunks
            for (const fileKey of fileKeysToDelete) {
                // Delete the file record
                fileStore.delete(fileKey)

                // Use a cursor to find and delete all associated chunks
                const cursorReq = chunkIndex.openCursor(IDBKeyRange.only(fileKey))
                cursorReq.onsuccess = () => {
                    const cursor = cursorReq.result
                    if (cursor) {
                        cursor.delete()
                        cursor.continue()
                    }
                }
            }
            await promisifyTransaction(writeTx)
        }

        console.log(`Folder "${folderName}" and its data deleted successfully.`)
        document.getElementById("deleteFolderName").value = ""
        await listFolders() // Refresh UI
    } catch (e) {
        console.error("Delete folder error:", e)
        alert("An error occurred during deletion: " + e.message)
    } finally {
        setUiBusy(false)
    }
}

// A helper function to concatenate two ArrayBuffers.
function concatBuffers(buffer1, buffer2) {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength)
    tmp.set(new Uint8Array(buffer1), 0)
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength)
    return tmp.buffer
}

function invalidateCacheAndWait(folderName) {
    return new Promise((resolve, reject) => {
        const controller = navigator.serviceWorker.controller
        if (!controller) {
            console.warn("No SW controller, skipping wait.")
            resolve()
            return
        }

        console.log("Waiting for SW to invalidate cache...")
        // Keep UI busy to prevent user leaving/closing tab
        setUiBusy(true)

        // Set a timeout so we don't hang forever
        const timeout = setTimeout(() => {
            controller.removeEventListener("message", messageListener)
            setUiBusy(false)
            reject(new Error("Service worker cache invalidation timed out."))
        }, 4000)

        // Define listener for the reply
        const messageListener = e => {
            if (e.data.type === "CACHE_INVALIDATED" && e.data.folderName === folderName) {
                clearTimeout(timeout)
                controller.removeEventListener("message", messageListener)
                console.log("Confimation received: Cache invalidated.")
                resolve()
            }
        }

        // Send command
        navigator.serviceWorker.addEventListener("message", messageListener)
        controller.postMessage({ type: "INVALIDATE_CACHE", folderName: folderName })
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

// Retrieves a file or directory handle from a given root directory and a relative path.
async function getHandleFromPath(rootDirHandle, path) {
    const pathParts = path.split("/").filter(p => p)
    let currentHandle = rootDirHandle
    for (let i = 0; i < pathParts.length; i++) {
        const part = pathParts[i]
        try {
            if (i === pathParts.length - 1) {
                // If it's the last part of the path, it's a file.
                currentHandle = await currentHandle.getFileHandle(part)
            } else {
                // Otherwise, it's a directory.
                currentHandle = await currentHandle.getDirectoryHandle(part)
            }
        } catch (e) {
            // Return null if any part of the path is not found.
            return null
        }
    }
    return currentHandle
}

// A helper function to convert an ArrayBuffer to a Base64 string.
function bufferToBase64(buffer) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.readAsDataURL(new Blob([buffer]))
        reader.onload = () => {
            const base64String = reader.result.split(",", 2)[1]
            resolve(base64String)
        }
        reader.onerror = (error) => {
            reject(error)
        }
    })
}

// A helper function to convert a Base64 string to an ArrayBuffer.
function base64ToBuffer(base64) {
    const binaryString = atob(base64)
    const len = binaryString.length
    const bytes = new Uint8Array(len)
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i)
    }
    return bytes.buffer
}

async function processAndStoreFolder(name, files, encryptionType = null) {
    if (!name) {
        alert("Please enter a name for the folder.")
        setUiBusy(false)
        return
    }

    console.log(`Processing ${Object.keys(files).length} files for folder "${name}"...`)
    const db = await getDb()

    // 1. Get all file keys to delete (READONLY, short transaction)
    const fileKeysToDelete = await (async () => {
        const transaction = db.transaction([FILES_SN], "readonly")
        const fileIndex = transaction.objectStore(FILES_SN).index("folder")
        // Get all primary keys for files belonging to this folder
        const keys = await promisifyRequest(fileIndex.getAllKeys(IDBKeyRange.bound([name, ""], [name, "\uffff"])))
        await promisifyTransaction(transaction)
        return keys
    })()

    // 2. Delete all related chunks and file records (READWRITE, short transaction)
    if (fileKeysToDelete.length > 0) {
        const deleteTransaction = db.transaction([FILES_SN, "FileChunks"], "readwrite")
        const fileStoreClear = deleteTransaction.objectStore(FILES_SN)
        const chunkStoreClear = deleteTransaction.objectStore("FileChunks")
        const chunkIndexClear = chunkStoreClear.index("by_file")

        // This MUST be synchronous code that puts requests on the transaction
        const deleteRequests = []

        for (const fileKey of fileKeysToDelete) {
            // Delete the file metadata
            deleteRequests.push(fileStoreClear.delete(fileKey))

            // Delete all chunks for this file using a cursor within the same transaction
            deleteRequests.push(new Promise((resolve, reject) => {
                const cursorReq = chunkIndexClear.openCursor(IDBKeyRange.only(fileKey))
                cursorReq.onsuccess = e => {
                    const cursor = e.target.result
                    if (cursor) {
                        cursor.delete()
                        cursor.continue()
                    } else {
                        resolve()
                    }
                }
                cursorReq.onerror = e => reject(e.target.error)
            }))
        }

        // We must await the resolution of the promises from the requests/cursors
        await Promise.all(deleteRequests.map(p => p instanceof Promise ? p : promisifyRequest(p)))

        // Then wait for the short transaction to complete
        await promisifyTransaction(deleteTransaction)
    }

    // 3. Write folder metadata (short transaction)
    const folderTransaction = db.transaction([FOLDERS_SN], "readwrite")
    const folderStore = folderTransaction.objectStore(FOLDERS_SN)
    const folderObject = { id: name, lastModified: new Date(), encryptionType: encryptionType }
    await promisifyRequest(folderStore.put(folderObject))
    await promisifyTransaction(folderTransaction)

    // 4. Store the new files
    if (Object.keys(files).length > 0) {
        // Use Promise.all to parallelize storage operations
        const storagePromises = []

        for (const path in files) {
            const fileData = files[path]
            // We use a more robust check for ArrayBuffer content, which covers small files and decrypted files
            if (fileData instanceof File) {
                // File objects are handled by the streaming logic
                storagePromises.push(streamFileToDb(db, name, path, fileData))
            } else if (typeof fileData === 'object' && fileData !== null && fileData.buffer instanceof ArrayBuffer) {
                // ArrayBuffers (from getFilesRecursively/decryption) are handled by the buffer logic
                storagePromises.push(storeBufferToDb(db, name, path, fileData.buffer, fileData.type))
            } else {
                console.warn(`Skipping unknown file type for path: ${path}`)
            }
        }

        await Promise.all(storagePromises) // Wait for all storage operations to complete
    }

    if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
    }

    console.log(`Folder "${name}" stored successfully.`)
    document.getElementById("folderName").value = ""
    document.getElementById("openFolderName").value = name
    await listFolders()
}

async function storeInMemoryFilesToDb(db, name, files) {
    const transaction = db.transaction([FILES_SN], "readwrite")
    const fileStore = transaction.objectStore(FILES_SN)
    const promises = []
    for (const path in files) {
        const fileData = files[path]
        const fileRecord = {
            folderName: name,
            path: path,
            content: { buffer: fileData.buffer, type: fileData.type }
        }
        promises.push(promisifyRequest(fileStore.put(fileRecord)))
    }
    await Promise.all(promises)
    await promisifyTransaction(transaction)
}

/**
 * Rewritten to stream chunks directly into the database using a new transaction
 * for each chunk to prevent TransactionInactiveError.
 * @param {IDBDatabase} db The IndexedDB instance
 * @param {string} folderName The virtual folder name
 * @param {string} path The relative file path
 * @param {File} file The native File object to stream
 * @returns {Promise<void>}
 */
async function streamFileToDb(db, folderName, path, file) {
    // 1. Transaction to add file metadata (short and self-contained)
    let fileId
    const metadataTransaction = db.transaction([FILES_SN], "readwrite")
    const fileStore = metadataTransaction.objectStore(FILES_SN)
    const fileMetadata = { folderName, path, type: getMimeType(path) || file.type, size: file.size }
    fileId = await promisifyRequest(fileStore.add(fileMetadata))
    await promisifyTransaction(metadataTransaction)

    // 2. Stream and write chunks (transaction per chunk)
    const reader = file.stream().getReader()
    let chunkIndex = 0

    while (true) {
        // ASYNC I/O here (outside of any transaction)
        const { done, value } = await reader.read()
        if (done) break

        // Start a new transaction for each chunk write
        const chunkTransaction = db.transaction(["FileChunks"], "readwrite")
        const chunkStore = chunkTransaction.objectStore("FileChunks")

        const chunkRecord = { fileId, index: chunkIndex++, data: value }

        // IDB operation submitted synchronously within the transaction block
        const addRequest = chunkStore.add(chunkRecord)

        await promisifyRequest(addRequest)

        // Wait for the transaction to complete before reading the next chunk
        await promisifyTransaction(chunkTransaction)
    }
}

async function storeBufferToDb(db, folderName, path, buffer, fileType) {
    if (buffer.byteLength < CHUNK_SIZE) {
        // Small file: store content in-line in a single transaction
        const transaction = db.transaction([FILES_SN], "readwrite")
        const fileStore = transaction.objectStore(FILES_SN)
        const fileRecord = {
            folderName,
            path,
            content: { buffer, type: fileType }
        }
        await promisifyRequest(fileStore.put(fileRecord))
        await promisifyTransaction(transaction)
    } else {
        // Large file: chunking with separate transactions for metadata and chunks
        // 1. Add file metadata
        let fileId
        const metadataTransaction = db.transaction([FILES_SN], "readwrite")
        const fileStore = metadataTransaction.objectStore(FILES_SN)
        const fileMetadata = { folderName, path, type: fileType, size: buffer.byteLength }
        fileId = await promisifyRequest(fileStore.add(fileMetadata))
        await promisifyTransaction(metadataTransaction)

        // 2. Write chunks (separate transaction per chunk)
        for (let i = 0; i < buffer.byteLength; i += CHUNK_SIZE) {
            // Start a new transaction for each chunk write
            const chunkTransaction = db.transaction(["FileChunks"], "readwrite")
            const chunkStore = chunkTransaction.objectStore("FileChunks")

            const end = Math.min(i + CHUNK_SIZE, buffer.byteLength)
            const chunk = buffer.slice(i, end)
            const chunkRecord = { fileId, index: i / CHUNK_SIZE, data: chunk }

            // IDB operation submitted synchronously within the transaction block
            const addRequest = chunkStore.add(chunkRecord)

            await promisifyRequest(addRequest)

            // Wait for the transaction to complete before looping for the next chunk
            await promisifyTransaction(chunkTransaction)
        }
    }
}

/**
 * Gathers all application data (IndexedDB, localStorage, cookies), optionally
 * encrypts it, and presents a download link to the user.
 */
async function exportData() {
    const password = prompt("Enter an optional password to encrypt the export; leave blank for a plaintext export:")
    setUiBusy(true)

    try {
        const dataToExport = {
            localStorage: {},
            indexedDB: {},
            cookies: ""
        }

        if (document.getElementById("c2").checked) {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i)
                if (key !== "pk") {
                    dataToExport.localStorage[key] = localStorage.getItem(key)
                }
            }
        }

        if (document.getElementById("c1").checked) {
            dataToExport.cookies = document.cookie
        }

        const exportRuntimeFS = document.getElementById("c4").checked
        const exportIndexedDB = document.getElementById("c3").checked
        if (exportRuntimeFS || exportIndexedDB) {
            const allDbs = await indexedDB.databases()
            for (const dbInfo of allDbs) {
                const dbName = dbInfo.name
                if (!exportRuntimeFS && dbName === DBN) continue
                else if (exportRuntimeFS && !exportIndexedDB && dbName !== DBN) continue

                try {
                    const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open(dbName)
                        request.onsuccess = () => resolve(request.result)
                        request.onerror = e => reject(new Error(`Could not open db: ${dbName}`))
                    })

                    const dbExport = { version: db.version, stores: {} }

                    // This is the key change: if the database has no object stores,
                    // we record its existence and version, but don't try to
                    // create a transaction, which would cause an error.
                    if (db.objectStoreNames.length > 0) {
                        const transaction = db.transaction(db.objectStoreNames, "readonly")
                        for (const storeName of db.objectStoreNames) {
                            const store = transaction.objectStore(storeName)
                            const indexes = Array.from(store.indexNames).map(name => {
                                const index = store.index(name)
                                return { name: index.name, keyPath: index.keyPath, unique: index.unique, multiEntry: index.multiEntry }
                            })

                            const records = await new Promise((resolve, reject) => {
                                const cursorReq = store.openCursor()
                                const allRecords = []
                                cursorReq.onerror = e => reject(e.target.error)
                                cursorReq.onsuccess = e => {
                                    const cursor = e.target.result
                                    if (cursor) {
                                        allRecords.push({ key: cursor.key, value: cursor.value })
                                        cursor.continue()
                                    } else {
                                        resolve(allRecords)
                                    }
                                }
                            })

                            dbExport.stores[storeName] = {
                                schema: { keyPath: store.keyPath, autoIncrement: store.autoIncrement, indexes },
                                data: records
                            }
                        }
                    }

                    dataToExport.indexedDB[dbName] = dbExport
                    db.close()
                } catch (e) {
                    console.warn(`Could not export database '${dbName}'. Skipping. Reason: ${e.name} - ${e.message}`)
                }
            }
        }

        const encoded = CBOR.encode(dataToExport)
        let finalBuffer = password ? CBOR.encode(await encryptPayload(encoded, password)) : encoded

        createAndDisplayDownloadLink(finalBuffer, document.getElementById("c3").parentElement, "result.cbor")
        console.log("Data export prepared.")

    } catch (e) {
        console.error("Export failed:", e)
        alert("An error occurred during export: " + (e.message || e.name))
    } finally {
        setUiBusy(false)
    }
}

// Helper for encryption to keep the main function cleaner
async function encryptPayload(payload, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const key = await deriveKeyFromPassword(password, salt)
    const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload)
    return { type: "FS-EE", s: salt, iv: iv, p: new Uint8Array(encryptedBuffer) }
}

async function getServiceWorkerController() {
    const registration = await navigator.serviceWorker.ready
    return registration.active
}

async function importData() {
    const input = document.createElement("input")
    input.type = "file"
    input.click()
    setUiBusy(true)
    input.oncancel = () => setUiBusy(false)

    input.onchange = async function () {
        // Request a lock to ensure no other tab interferes with the import
        await navigator.locks.request("database-import-lock", async function () {
            let data = null
            try {
                const file = input.files[0]
                if (!file) {
                    setUiBusy(false)
                    return
                }

                if (navigator.storage && navigator.storage.estimate) {
                    const estimate = await navigator.storage.estimate()
                    const availableSpace = estimate.quota - estimate.usage

                    if (file.size > availableSpace) {
                        throw new Error(`Import failed: The file size (${(file.size / 1024 / 1024).toFixed(2)} MB) seems to be larger than the available browser storage (${(availableSpace / 1024 / 1024).toFixed(2)} MB). Please free up space and try again.`)
                    }
                }

                const controller = await getServiceWorkerController()
                controller.postMessage({ type: "PREPARE_FOR_IMPORT" })
                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error("SW failed to acknowledge import preparation.")), 5000)

                    const messageListener = e => {
                        if (e.data.type === "IMPORT_READY") {
                            navigator.serviceWorker.removeEventListener("message", messageListener)
                            clearTimeout(timeout)
                            console.log("SW Acknowledged. Proceeding with import.")
                            resolve()
                        }
                    }
                    navigator.serviceWorker.addEventListener("message", messageListener)
                })

                const buffer = await file.arrayBuffer()
                const decodedItems = CBOR.decodeMultiple(new Uint8Array(buffer))

                if (!decodedItems || decodedItems.length === 0) {
                    throw new Error("Import file is empty or not a valid CBOR file.")
                }

                data = decodedItems[0]

                if (data.type === "FS-EE") {
                    const password = prompt("This file is encrypted. Please enter the password (or type nothing to cancel):")
                    if (!password) {
                        setUiBusy(false)
                        return
                    }
                    const key = await deriveKeyFromPassword(password, data.s)
                    let decryptedPayload
                    try {
                        decryptedPayload = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.iv }, key, data.p)
                    } catch (err) {
                        throw new Error("Decryption failed. The password may be incorrect.")
                    }
                    const innerItems = CBOR.decodeMultiple(new Uint8Array(decryptedPayload))
                    if (!innerItems || innerItems.length === 0) {
                        throw new Error("Decrypted payload is empty or invalid.")
                    }
                    data = innerItems[0]
                }
                data = normalizeToArrayBuffers(data)

                if (data.localStorage) {
                    Object.keys(data.localStorage).forEach(key => {
                        if (key !== "pk") localStorage.setItem(key, data.localStorage[key])
                    })
                }

                if (data.indexedDB) {
                    for (const dbName in data.indexedDB) {
                        const dbData = data.indexedDB[dbName]
                        if (Object.keys(dbData.stores).length === 0) {
                            await createEmptyDatabase(dbName, dbData.version)
                            continue // Move to the next database in the loop
                        }
                        await clearAndFillDatabase(dbName, dbData)
                    }
                }

                if (controller) {
                    console.log("Notifying Service Worker and waiting for acknowledgment...")
                    await new Promise((resolve, reject) => {
                        const timeout = setTimeout(() => reject(new Error("SW ack timed out.")), 5000)
                        const messageListener = e => {
                            if (e.data.type === "DB_ACKNOWLEDGED") {
                                navigator.serviceWorker.removeEventListener("message", messageListener)
                                clearTimeout(timeout)
                                resolve()
                            }
                        }
                        navigator.serviceWorker.addEventListener("message", messageListener)
                        controller.postMessage({ type: "DB_IMPORTED" })
                    })
                }

                await listFolders()
                alert("Import complete!")
            } catch (e) {
                console.error("Import failed:", e)
                if (e && e.name === "QuotaExceededError") {
                    alert("The browser ran out of storage space during the import. Please free up disk space or manage site storage in your browser settings.")
                } else {
                    alert(`An error occurred during import: ${e.message || e.name}`)
                }
            } finally {
                // Explicitly nullify the large object to signal the garbage collector.
                data = null
                setUiBusy(false)
            }
        })
    }
}

/**
 * Creates an empty IndexedDB database with a specific version number.
 * This is used to handle edge cases like Emscripten's /idbfs-test.
 * @param {string} dbName The name of the database to create.
 * @param {number} version The version number for the new database.
 * @returns {Promise<void>}
 */
async function createEmptyDatabase(dbName, version) {
    console.log(`Creating special-case empty database: '${dbName}' version ${version}`)

    // 1. Ensure any old version is completely gone.
    await new Promise((resolve, reject) => {
        const delRequest = indexedDB.deleteDatabase(dbName)
        delRequest.onerror = e => reject(new Error(`Could not delete database: ${dbName}`))
        delRequest.onblocked = () => reject(new Error(`Import failed: Database "${dbName}" is open in another tab.`))
        delRequest.onsuccess = () => resolve()
    })

    // 2. Open the database. The 'onupgradeneeded' will fire, creating the DB.
    // We don't need to do anything inside it.
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, version)
        request.onerror = e => reject(new Error(`Could not create empty database: ${dbName}`))
        request.onupgradeneeded = e => {
            // The event itself creates the database, no action needed inside.
        }
        request.onsuccess = e => {
            // IMPORTANT: Close the connection immediately to release the lock.
            e.target.result.close()
            resolve()
        }
    })
}

function normalizeToArrayBuffers(data) {
    if (data instanceof Uint8Array) {
        return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
    }

    // Recurse for arrays and objects
    if (Array.isArray(data)) {
        return data.map(item => normalizeToArrayBuffers(item))
    }

    if (typeof data === "object" && data !== null && data.constructor === Object) {
        const newObj = {}
        for (const key in data) {
            newObj[key] = normalizeToArrayBuffers(data[key])
        }
        return newObj
    }

    // If the data is already an ArrayBuffer (less common from CBOR),
    // we should still make a copy to be safe.
    if (data instanceof ArrayBuffer) {
        return data.slice(0)
    }

    return data
}

/**
 * Opens a database, clears all its object stores, and fills them with new data.
 * @param {string} dbName The name of the database to process.
 * @param {object} dbData The imported data object containing schema and records.
 * @returns {Promise<void>}
 */
async function clearAndFillDatabase(dbName, dbData) {
    await new Promise((resolve, reject) => {
        const delRequest = indexedDB.deleteDatabase(dbName)
        delRequest.onerror = e => reject(new Error(`Could not delete database: ${dbName}. Error: ${e.target.error}`))
        // If a DB is used within another tab, we can't delete the database.
        delRequest.onblocked = () => reject(new Error(`Import failed: Database "${dbName}" is open in another tab. Please close it and try again.`))
        delRequest.onsuccess = () => resolve()
    })

    const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, dbData.version)
        request.onerror = e => reject(new Error(`Could not open database: ${dbName}. Error: ${e.target.error}`))
        request.onupgradeneeded = e => {
            const dbHandle = e.target.result
            for (const storeName in dbData.stores) {
                const { schema } = dbData.stores[storeName]
                const storeHandle = dbHandle.createObjectStore(storeName, { keyPath: schema.keyPath, autoIncrement: schema.autoIncrement })
                schema.indexes?.forEach(idx => {
                    storeHandle.createIndex(idx.name, idx.keyPath, { unique: idx.unique, multiEntry: idx.multiEntry })
                })
            }
        }
        request.onsuccess = e => resolve(e.target.result)
    })

    const storeNames = Object.keys(dbData.stores)
    for (const storeName of storeNames) {
        // console.log(`Restoring store: ${dbName}/${storeName}`)
        const storeInfo = dbData.stores[storeName]
        const transaction = db.transaction([storeName], "readwrite")
        const store = transaction.objectStore(storeName)
        const { keyPath } = storeInfo.schema

        // It's a new database, so no need to clear the store first
        for (const record of storeInfo.data) {
            if (keyPath != null) {
                const valueToPut = { ...record.value, [keyPath]: record.key }
                store.put(valueToPut)
            } else {
                store.put(record.value, record.key)
            }
        }
        await promisifyTransaction(transaction)
    }

    db.close()
    // console.log(`Database '${dbName}' restore complete.`)
}

function createAndDisplayDownloadLink(buffer, parentElement, filename) {
    // Clean up any old links
    const oldLink = document.getElementById("download-link")
    if (oldLink) {
        oldLink.remove()
    }

    var url
    // if (confirm("Export as blob: instead of data:?")) {
    const blob = new Blob([buffer], { type: "application/octet-stream" })
    url = URL.createObjectURL(blob)
    // }

    const a = document.createElement("a")
    a.id = "download-link"
    a.href = url
    a.download = filename
    a.textContent = "Click here to download export!"
    a.style.display = "block"
    a.style.marginTop = "10px"
    a.style.padding = "8px"
    a.style.border = "1px solid #15e264"
    a.style.borderRadius = "5px"
    a.style.textAlign = "center"

    // Revoke the object URL after click to free memory
    a.onclick = () => {
        setTimeout(() => {
            URL.revokeObjectURL(url)
            a.remove()
        }, 200)
    }

    parentElement.appendChild(a)
}

// Derives a cryptographic key from a password using PBKDF2.
async function deriveKeyFromPassword(password, salt, iterations = 250000) {
    const encoder = new TextEncoder()
    const passwordBuffer = encoder.encode(password)
    // Import the password as a base key.
    const baseKey = await crypto.subtle.importKey("raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"])
    // Derive a 256-bit AES-GCM key.
    return await crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
}

// Uploads a folder and encrypts it with a user-provided password.
async function uploadAndEncryptWithPassword() {
    const folderNameInput = document.getElementById("encryptFolderName")
    const name = folderNameInput.value.trim()
    const password = prompt("Enter a secure password:")
    setUiBusy(true)
    try {
        const localDirHandle = await window.showDirectoryPicker({ mode: "read" })
        dirHandle = localDirHandle
        folderName = name
        const files = await getFilesRecursively(localDirHandle)
        // Generate a random salt for the key derivation.
        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt)

        // Encrypt each file in the folder.
        for (const path in files) {
            const file = files[path]
            const iv = crypto.getRandomValues(new Uint8Array(12)) // Generate a new IV for each file.
            const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, file.buffer)
            // Prepend the IV to the encrypted data.
            file.buffer = concatBuffers(iv.buffer, encryptedBuffer)
        }
        // Store the salt in a metadata file.
        files[".metadata"] = { buffer: salt.buffer, type: "application/octet-stream" }

        await processAndStoreFolder(name, files, "pdf")

        console.log(`Folder "${name}" encrypted and stored successfully.`)
        folderNameInput.value = ""
        await listFolders()
    } catch (err) {
        if (err.name !== "AbortError") {
            console.error("Password encryption error:", err)
            alert("An error occurred during encryption: " + err.message)
        }
    } finally {
        setUiBusy(false)
    }
}

// Register the service worker.
if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").then(reg => {
        // Listen for updates to the service worker.
        reg.addEventListener("updatefound", () => {
            const newWorker = reg.installing
            newWorker.addEventListener("statechange", () => {
                // If a new version is installed and there's an active controller,
                // it means the user should refresh to get the latest version.
                if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                    console.log("A new version is available! Please refresh the page to update.")
                }
            })
        })
    }).catch(err => console.log("Service worker not registered.", err))
}

async function encryptAndSaveFolderWithPassword() {
    const password = prompt("After entering a password, first select the folder you want to encrypt, then another folder (ideally empty) to encrypt the data to. Enter a secure password:")
    if (!password) return

    try {
        setUiBusy(true)
        const sourceDirHandle = await window.showDirectoryPicker({ mode: "read" })
        const destDirHandle = await window.showDirectoryPicker({ mode: "readwrite" })

        // 1. Derive the master key from the password.
        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt) // Your existing helper is perfect.

        const fileMap = await scanFilesRecursively(sourceDirHandle)
        const pathManifest = {}

        // 2. Encrypt each file and save it with a UUID name.
        for (const originalPath in fileMap) {
            if (fileMap[originalPath] === null) continue // Skip directories.
            const uuid = crypto.randomUUID()
            pathManifest[originalPath] = uuid
            const fileBuffer = await fileMap[originalPath].arrayBuffer()

            const iv = crypto.getRandomValues(new Uint8Array(12))
            const encryptedContent = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer)

            // Prepend the IV to the encrypted buffer for storage.
            const finalBuffer = concatBuffers(iv.buffer, encryptedContent)

            const newFileHandle = await destDirHandle.getFileHandle(uuid, { create: true })
            const writable = await newFileHandle.createWritable()
            await writable.write(finalBuffer)
            await writable.close()
        }

        // 3. Create and encrypt the manifest payload.
        const manifestString = JSON.stringify(pathManifest)
        const manifestBuffer = new TextEncoder().encode(manifestString)
        const manifestIv = crypto.getRandomValues(new Uint8Array(12))
        const encryptedManifestPayload = await crypto.subtle.encrypt({ name: "AES-GCM", iv: manifestIv }, key, manifestBuffer)

        // 4. Create the final manifest.enc file content.
        const manifestFileObject = {
            encryptionType: "password",
            salt: await bufferToBase64(salt),
            iv: await bufferToBase64(manifestIv),
            payload: await bufferToBase64(new Uint8Array(encryptedManifestPayload))
        }

        const manifestFileHandle = await destDirHandle.getFileHandle("manifest.enc", { create: true })
        const manifestWritable = await manifestFileHandle.createWritable()
        await manifestWritable.write(JSON.stringify(manifestFileObject))
        await manifestWritable.close()

        alert(`Folder successfully encrypted and saved in "${destDirHandle.name}".`)
    } catch (err) {
        if (err.name !== "AbortError") {
            alert("An error occurred during encryption: " + err.message)
        }
    } finally {
        setUiBusy(false)
    }
}

// Add keyboard shortcuts for common actions.
document.getElementById("folderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || uploadFolder()))
document.getElementById("openFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || openFile()))
document.getElementById("fileName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || openFile()))
document.getElementById("deleteFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || deleteFolder()))
document.getElementById("folderUploadFallbackInput").addEventListener("change", uploadFolderFallback)
document.getElementById("folderUploadFallbackInput").addEventListener("cancel", () => setUiBusy(false))
document.body.addEventListener("dragover", e => {
    e.preventDefault()
    document.body.style.backgroundColor = "#385b7e"
})

document.body.addEventListener("dragleave", () => {
    document.body.style.backgroundColor = "" // Reset visual feedback
})

/** Promisifies the reader.readEntries() callback API. */
function readAllEntries(directoryReader) {
    return new Promise((resolve, reject) => {
        let allEntries = []
        const readMore = () => {
            directoryReader.readEntries(
                (entries) => {
                    if (entries.length === 0) resolve(allEntries)
                    else {
                        allEntries = allEntries.concat(entries)
                        readMore()
                    }
                },
                (error) => reject(error)
            )
        }
        readMore()
    })
}

/**
 * Promisifies the entry.file() callback API.
 * @param {FileSystemFileEntry} fileEntry The file entry to convert.
 * @returns {Promise<File>} A promise that resolves with the File object.
 */
function getFileFromEntry(fileEntry) {
    return new Promise((resolve, reject) => {
        fileEntry.file(
            (file) => {
                resolve(file)
            },
            (error) => {
                reject(error)
            }
        )
    })
}

// A new, modern helper to recursively read directory entries using Promises
async function readEntriesAsync(dirReader) {
    return new Promise((resolve, reject) => {
        dirReader.readEntries(resolve, reject)
    })
}

// A new, modern helper to get a File object from a FileEntry using Promises
async function getFileAsync(fileEntry) {
    return new Promise((resolve, reject) => {
        fileEntry.file(resolve, reject)
    })
}

// The rewritten recursive function using modern async/await
async function getFilesFromDroppedItems(dataTransferItemList) {
    const files = {}
    const rootEntries = Array.from(dataTransferItemList).map(item => item.webkitGetAsEntry())

    async function processEntry(entry) {
        if (entry.isFile) {
            const file = await getFileAsync(entry)
            const path = entry.fullPath.substring(1) // Remove leading '/'

            if (file.size <= CHUNK_SIZE) {
                const buffer = await file.arrayBuffer()
                files[path] = { buffer, type: getMimeType(path) || file.type }
            } else {
                files[path] = file // Store large files for streaming
            }
        } else if (entry.isDirectory) {
            const dirReader = entry.createReader()
            // Loop until all entries are read, as readEntries() may not return all at once
            let entries
            do {
                entries = await readEntriesAsync(dirReader)
                await Promise.all(entries.map(processEntry))
            } while (entries.length > 0)
        }
    }

    // Process all top-level dropped items in parallel
    await Promise.all(rootEntries.map(processEntry))
    return files
}


async function uploadFolderFallback(event) {
    setUiBusy(true)
    const name = document.getElementById("folderName").value.trim()
    const input = event.target

    if (!input.files.length) {
        setUiBusy(false)
        return
    }

    try {
        const files = {}
        await Promise.all(Array.from(input.files).map(async (file) => {
            const path = file.webkitRelativePath
            if (file.size <= CHUNK_SIZE) {
                const buffer = await file.arrayBuffer()
                files[path] = { buffer, type: getMimeType(path) || file.type }
            } else {
                files[path] = file // Store large file object
            }
        }))

        await processAndStoreFolder(name, files)

        // Invalidate service worker cache and update UI
        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
        }
        document.getElementById("folderName").value = ""
        document.getElementById("openFolderName").value = name
        await listFolders()

    } catch (err) {
        console.error("Fallback upload error:", err)
        alert("An error occurred during fallback upload: " + err.message)
    } finally {
        input.value = "" // Reset input for next use
        setUiBusy(false)
    }
}

document.body.addEventListener("drop", async e => {
    e.preventDefault()
    document.body.style.backgroundColor = ""

    let defaultFolderName = ""
    const items = e.dataTransfer.items
    if (items && items.length > 0 && items[0].webkitGetAsEntry) {
        // We only want to process if the first item is a directory.
        const firstEntry = items[0].webkitGetAsEntry()
        if (firstEntry.isDirectory) {
            defaultFolderName = firstEntry.name
        } else {
            // If the user dropped a file, inform them and stop.
            alert("Please drop a folder, not a file.")
            return
        }
    } else {
        alert("This browser does not support folder dropping.")
        return
    }

    const name = prompt("Please enter a name for the folder:", defaultFolderName)
    if (name === null) {
        return
    }
    setUiBusy(true)
    try {
        const files = await getFilesFromDroppedItems(items)

        if (Object.keys(files).length === 0) {
            alert("The dropped folder appears to be empty.")
            return
        }

        // Use the name from the prompt to store the folder.
        await processAndStoreFolder(name.trim(), files)
    } catch (err) {
        console.error("Drag-and-drop error:", err)
        alert("An error occurred during drop: " + err.message)
    } finally {
        setUiBusy(false)
    }
})