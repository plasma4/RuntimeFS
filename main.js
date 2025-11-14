const DBN = "FileCacheDB"
const FOLDERS_SN = "Folders"
const FILES_SN = "Files"
const META_SN = "Metadata"
const RULES_SN = "Rules"
const DB_VERSION = 11 // Version 1.1

const CHUNK_SIZE = 4 * 1024 * 1024 // 4MB chunks
const BATCH_SIZE = 50 // Batch of 50
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

    setUiBusy(true)
    try {
        // Modern path using File System Access API
        if (window.showDirectoryPicker) {
            const localDirHandle = await window.showDirectoryPicker({ mode: "read" })
            // If the code reaches here, the user has selected a folder
            await processFolderSelection(name, localDirHandle)
        } else {
            // Fallback path for other browsers like Firefox
            document.getElementById("folderUploadFallbackInput").click()
        }
    } catch (err) {
        // This catch block specifically handles cancellation of showDirectoryPicker
        if (err.name !== "AbortError") {
            console.error("Upload error:", err)
            alert("An error occurred during upload: " + err.message)
        }
        // Always reset the UI if the main path fails or is cancelled
    } finally {
        setUiBusy(false)
    }
}

async function processFolderSelection(name, handle) {
    dirHandle = handle
    folderName = name
    let files = {}

    // Check for manifest.enc to determine if the folder is encrypted
    try {
        const manifestHandle = await handle.getFileHandle("manifest.enc")
        console.log("Encrypted folder detected. Starting decryption process...")
        files = await decryptAndLoadFolder(handle, manifestHandle)
    } catch (e) {
        if (e.name !== "NotFoundError") throw e // Re-throw unexpected errors

        files = await getFilesRecursively(handle)
        if (observer) observer.disconnect()

        try {
            observer = new FileSystemObserver((records) => {
                console.log(`${records.length} file system change(s) detected`)
                changes.push(...records)
            })
            observer.observe(dirHandle, { recursive: true })
        } catch (e) {
            if (e.name !== "NotSupportedError") throw e
            console.error("Cannot observe directories for modifications.")
            console.warn(e)
        }
        changes.length = 0
    }

    await processAndStoreFolder(name, files)

    if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
    }
    document.getElementById("folderName").value = ""
    document.getElementById("openFolderName").value = name
}

async function processFileListAndStore(name, fileList) {
    // Note: The UI should already be set to busy before calling this function
    try {
        if (!fileList.length) {
            console.log("File list is empty, nothing to process")
            return
        }

        const files = {}
        // Determine the common base path from the first file (e.g., "MyProject/")
        // This is necessary because webkitRelativePath includes the selected folder's name
        let basePath = ""
        if (fileList.length > 0 && fileList[0].webkitRelativePath.includes("/")) {
            basePath = fileList[0].webkitRelativePath.split("/")[0] + "/"
        }

        // Use a standard for-loop as FileList is not a true array
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i]
            let path = file.webkitRelativePath

            // Strip the base path to get the correct relative path for storage
            if (basePath && path.startsWith(basePath)) {
                path = path.substring(basePath.length)
            }

            // If path is now empty (e.g., a hidden file at the root), skip it
            if (!path) {
                continue
            }

            if (file.size <= CHUNK_SIZE) {
                const buffer = await file.arrayBuffer()
                files[path] = { buffer, type: getMimeType(path) || file.type }
            } else {
                files[path] = file // Store large file object for streaming
            }
        }

        if (Object.keys(files).length === 0) {
            alert("No valid files found.")
            return
        }

        await processAndStoreFolder(name, files)

        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
        }
        document.getElementById("folderName").value = ""
        document.getElementById("openFolderName").value = name
        await listFolders()
    } catch (err) {
        console.error("File processing error:", err)
        alert("An error occurred during file processing: " + err.message)
    } finally {
        // The calling function is responsible for resetting the UI busy state
    }
}

// Handles the file input change event for fallback folder uploads.
async function uploadFolderFallback(event) {
    const name = document.getElementById("folderName").value.trim()
    const input = event.target

    if (!input.files.length) {
        console.log("Fallback folder selection cancelled.")
        setUiBusy(false) // User cancelled, so reset UI
        return
    }

    try {
        await processFileListAndStore(name, input.files)
    } finally {
        input.value = "" // Reset input for next use
        setUiBusy(false) // Ensure UI is always reset
    }
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

async function syncAndOpenFile() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")

    // Keep the UI locked so the user doesn't close the tab while waiting
    setUiBusy(true)
    if (changes.length > 0) {
        await performSyncToDb()
        await invalidateCacheAndWait(folderName)
    }
    console.log("Opening file...")
    openFile(folderName)
}

async function performSyncToDb() {
    console.log(`Processing ${changes.length} changes for "${folderName}"...`)
    const db = await getDb()
    let updateCount = 0

    const operations = []
    for (const change of changes) {
        const path = change.relativePathComponents.join("/")
        try {
            switch (change.type) {
                case "created":
                case "modified":
                    var fileHandle = await getHandleFromPath(dirHandle, path)
                    if (fileHandle?.kind === "file") {
                        const file = await fileHandle.getFile()
                        operations.push({ type: "put", path, file })
                    }
                    break
                case "deleted":
                    operations.push({ type: "delete", path })
                    break
                case "moved":
                    const oldPath = change.relativePathMovedFrom.join("/")
                    var fileHandle = await getHandleFromPath(dirHandle, path)
                    if (fileHandle?.kind === "file") {
                        const file = await fileHandle.getFile()
                        operations.push({ type: "move", oldPath, path, file })
                    }
                    break
            }
        } catch (e) {
            console.warn(`Skipping sync for path "${path}": ${e.message}`)
        }
    }

    for (const op of operations) {
        if (op.type === "put") {
            await deleteFileByPathAndChunks(db, folderName, op.path)
            if (op.file.size > CHUNK_SIZE) {
                await streamFileToDb(db, folderName, op.path, op.file)
            } else {
                const buffer = await op.file.arrayBuffer()
                const addTx = db.transaction(FILES_SN, "readwrite")
                addTx.objectStore(FILES_SN).put({
                    folderName: folderName,
                    path: op.path,
                    buffer: new Blob([buffer]),
                    type: getMimeType(op.path) || op.file.type,
                    lookupPath: `${folderName}/${op.path}`
                })
                await promisifyTransaction(addTx)
            }
            updateCount++
        } else if (op.type === "delete") {
            await deleteFileByPathAndChunks(db, folderName, op.path)
            updateCount++
        } else if (op.type === "move") {
            await deleteFileByPathAndChunks(db, folderName, op.oldPath)
            if (op.file.size > CHUNK_SIZE) {
                await streamFileToDb(db, folderName, op.path, op.file)
            } else {
                const buffer = await op.file.arrayBuffer()
                const addTx = db.transaction(FILES_SN, "readwrite")
                addTx.objectStore(FILES_SN).put({
                    folderName: folderName,
                    path: op.path,
                    buffer: new Blob([buffer]),
                    type: getMimeType(op.path) || op.file.type,
                    lookupPath: `${folderName}/${op.path}`
                })
                await promisifyTransaction(addTx)
            }
            updateCount++
        }
    }

    changes.length = 0
    return updateCount
}

async function listFolders() {
    if (isListingFolders) {
        return
    }

    isListingFolders = true
    try {
        const db = await getDb()
        const transaction = db.transaction(FOLDERS_SN, "readonly")
        const store = transaction.objectStore(FOLDERS_SN)
        const allFolders = await promisifyRequest(store.getAll())

        const folderList = document.getElementById("folderList")
        folderList.innerHTML = ""

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
        folderList.textContent = "Error loading folders ):"
    } finally {
        isListingFolders = false
    }
}

async function deleteFolder(folderNameToDelete, skipConfirm = false) {
    const folderName = folderNameToDelete || document.getElementById("deleteFolderName").value.trim()
    if (!folderName) {
        alert("Please enter the name of the folder to delete.")
        return
    }
    if (!skipConfirm && !confirm(`Are you sure you want to remove the folder "${folderName}"?`)) return

    setUiBusy(true)
    try {
        const db = await getDb()
        const storesToUse = [FOLDERS_SN]
        // Defensively check if the other stores exist before adding them to the transaction
        if (db.objectStoreNames.contains(FILES_SN)) {
            storesToUse.push(FILES_SN)
        }
        if (db.objectStoreNames.contains("FileChunks")) {
            storesToUse.push("FileChunks")
        }

        const transaction = db.transaction(storesToUse, "readwrite")
        const folderStore = transaction.objectStore(FOLDERS_SN)
        folderStore.delete(folderName)

        // Only attempt to delete files if the Files store and its index actually exist.
        if (db.objectStoreNames.contains(FILES_SN)) {
            const fileStore = transaction.objectStore(FILES_SN)
            if (fileStore.indexNames.contains("lookup")) {
                const chunkStore = transaction.objectStore("FileChunks")
                const lookupIndex = fileStore.index("lookup")
                const chunkIndex = chunkStore.index("by_file")

                const folderFileRange = IDBKeyRange.bound(folderName + "/", folderName + "/\uffff")
                const filesToDelete = await promisifyRequest(lookupIndex.getAll(folderFileRange))

                for (const file of filesToDelete) {
                    const fileId = file.id
                    if (file.size && file.size > 0) {
                        const chunkKeys = await promisifyRequest(chunkIndex.getAllKeys(IDBKeyRange.only(fileId)))
                        for (const chunkKey of chunkKeys) {
                            chunkStore.delete(chunkKey)
                        }
                    }
                    fileStore.delete(fileId)
                }
            }
        }

        await promisifyTransaction(transaction)
        console.log(`Folder "${folderName}" deleted successfully.`)
        if (!folderNameToDelete) {
            document.getElementById("deleteFolderName").value = ""
        }
        await listFolders() // Refresh UI
    } catch (e) {
        console.error("Delete folder error:", e)
        alert("An error occurred during deletion: " + e.message)
    } finally {
        if (!skipConfirm) setUiBusy(false)
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

    // First, clear any old version of this folder
    await deleteFolder(name, true)

    const largeFilesToStream = []
    const smallFileEntries = []

    for (const path in files) {
        const fileData = files[path]
        if (fileData instanceof File && fileData.size > CHUNK_SIZE) {
            largeFilesToStream.push({ path, fileData })
        } else if (fileData) {
            smallFileEntries.push({ path, fileData })
        }
    }

    if (smallFileEntries.length > 0) {
        const transaction = db.transaction([FILES_SN], "readwrite")
        const fileStore = transaction.objectStore(FILES_SN)
        for (const entry of smallFileEntries) {
            const { path, fileData } = entry
            const buffer = await (fileData.buffer ? fileData.buffer : fileData.arrayBuffer())
            const type = fileData.type || getMimeType(path)

            fileStore.put({
                folderName: name,
                path: path,
                buffer: new Blob([buffer]),
                type: type,
                lookupPath: `${name}/${path}`
            })
        }
        await promisifyTransaction(transaction)
    }

    for (const largeFile of largeFilesToStream) {
        await streamFileToDb(db, name, largeFile.path, largeFile.fileData)
    }

    // Save the folder metadata
    const folderTransaction = db.transaction([FOLDERS_SN], "readwrite")
    await promisifyRequest(folderTransaction.objectStore(FOLDERS_SN).put({ id: name, lastModified: new Date(), encryptionType }))
    await promisifyTransaction(folderTransaction)

    // Notify the service worker to invalidate its cache for this folder
    if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
    }

    console.log(`Folder "${name}" stored successfully`)
    document.getElementById("folderName").value = ""
    document.getElementById("openFolderName").value = name
    await listFolders()
}

async function openFile(overrideFolderName) {
    const folderName = overrideFolderName || document.getElementById("openFolderName").value.trim()
    const fileName = document.getElementById("fileName").value.trim()

    if (!folderName) {
        alert("Please provide a folder name.")
        return
    }

    const db = await getDb()
    const folderData = await db.transaction(FOLDERS_SN).objectStore(FOLDERS_SN).get(folderName)

    if (!folderData) {
        alert(`Folder "${folderName}" not found.`)
        return
    }

    // Set the UI to a busy state before starting any long-running operations.
    setUiBusy(true)
    try {
        const regexRules = document.getElementById("regex").value.trim()
        const customHeaders = document.getElementById("headers").value.trim()

        if (regexRules || customHeaders) {
            try {
                await invalidateCacheAndWait(folderName)
            } catch (err) {
                console.error("Cache invalidation failed before opening file:", err)
                alert("Could not clear cache before applying rules. You may see stale content.")
            }
        }

        const isEncrypted = folderData.encryptionType === "pdf"
        let decryptionKey = null

        if (isEncrypted) {
            const password = prompt(`Enter password for folder "${folderName}":`)
            if (!password) return

            try {
                const transaction = db.transaction(FILES_SN, "readonly")
                const fileStore = transaction.objectStore(FILES_SN)
                const fileIndex = fileStore.index("lookup")
                const metadataFileRecord = await promisifyRequest(fileIndex.get(`${folderName}/.metadata`))

                if (!metadataFileRecord) throw new Error("Encryption metadata is missing.")

                const saltBuffer = await metadataFileRecord.buffer.arrayBuffer()
                const salt = new Uint8Array(saltBuffer)
                decryptionKey = await deriveKeyFromPassword(password, salt)
            } catch (e) {
                console.error("Decryption failed:", e)
                alert("Decryption failed. Please check the folder name and password.")
                return
            }
        }

        const requestId = crypto.randomUUID()
        try {
            await new Promise((resolve, reject) => {
                const controller = navigator.serviceWorker.controller
                if (!controller) {
                    return reject(new Error("Service Worker not active."))
                }

                const timeout = setTimeout(() => {
                    reject(new Error("Service Worker acknowledgment timed out."))
                }, 4000)

                const messageListener = e => {
                    if (e.data.type === "RULES_READY" && e.data.requestId === requestId) {
                        clearTimeout(timeout)
                        navigator.serviceWorker.removeEventListener("message", messageListener)
                        resolve()
                    }
                }
                navigator.serviceWorker.addEventListener("message", messageListener)

                controller.postMessage({
                    type: "SET_RULES",
                    requestId: requestId,
                    rules: regexRules,
                    headers: customHeaders,
                    key: decryptionKey
                })
            })
        } catch (err) {
            alert(`Error preparing to open file: ${err.message}`)
            return
        }

        const encodedFolderName = encodeURIComponent(folderName)
        const encodedFilePath = fileName.split("/").map(segment => encodeURIComponent(segment)).join("/")
        const url = `n/${encodedFolderName}/${encodedFilePath}`
        window.open(url, "_blank")
    } finally {
        // This block is guaranteed to run, ensuring the UI is always re-enabled.
        setUiBusy(false)
    }
}

async function syncFiles() {
    if (!folderName || !dirHandle) {
        alert("Please upload a folder first to enable syncing.")
        return
    }

    if (changes.length === 0) {
        alert("No changes detected to sync.")
        return
    }

    setUiBusy(true)
    console.log("Starting file synchronization...")
    try {
        const updateCount = await performSyncToDb()
        if (updateCount > 0) {
            await invalidateCacheAndWait(folderName)
            alert(`Sync complete. ${updateCount} change(s) processed.`)
        } else {
            alert("Sync complete. No changes needed to be applied.")
        }
        console.log("Sync process finished.")
    } catch (err) {
        console.error("Sync failed:", err)
        alert("An error occurred during sync: " + err.message)
    } finally {
        setUiBusy(false)
    }
}

async function storeBufferToDb(db, folderName, path, buffer, fileType) {
    if (buffer.byteLength < CHUNK_SIZE) {
        const transaction = db.transaction([FILES_SN], "readwrite")
        // Storing a flattened object now
        await promisifyRequest(transaction.objectStore(FILES_SN).add({ folderName, path, buffer: buffer, type: fileType }))
        await promisifyTransaction(transaction)
    } else {
        let fileId
        const metadataTransaction = db.transaction([FILES_SN], "readwrite")
        fileId = await promisifyRequest(metadataTransaction.objectStore(FILES_SN).add({ folderName, path, type: fileType, size: buffer.byteLength }))
        await promisifyTransaction(metadataTransaction)

        for (let i = 0; i < buffer.byteLength; i += CHUNK_SIZE) {
            const chunkTransaction = db.transaction(["FileChunks"], "readwrite")
            const chunk = buffer.slice(i, Math.min(i + CHUNK_SIZE, buffer.byteLength))
            await promisifyRequest(chunkTransaction.objectStore("FileChunks").add({ fileId, index: i / CHUNK_SIZE, data: chunk }))
            await promisifyTransaction(chunkTransaction)
        }
    }
}

async function clearAndFillDatabase(dbName, dbData) {
    await new Promise((resolve, reject) => {
        const delRequest = indexedDB.deleteDatabase(dbName)
        delRequest.onerror = e => reject(new Error(`Could not delete database: ${dbName}. Error: ${e.target.error}`))
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

    const idMap = new Map()

    // Special pre-processing ONLY for FileCacheDB's auto-incrementing stores
    if (dbName === DBN && dbData.stores[FILES_SN]) {
        const filesStoreInfo = dbData.stores[FILES_SN]
        const filesTx = db.transaction([FILES_SN], "readwrite")
        const filesStore = filesTx.objectStore(FILES_SN)
        for (const record of filesStoreInfo.data) {
            const oldId = record.key
            let value = record.value
            delete value.id
            const addRequest = filesStore.add(value)
            const newId = await promisifyRequest(addRequest)
            idMap.set(oldId, newId)
        }
        await promisifyTransaction(filesTx)
    }

    const storeNamesToRestore = Object.keys(dbData.stores).filter(name => {
        // Skip stores that were handled in the special block above
        return !(dbName === DBN && name === FILES_SN)
    })

    if (storeNamesToRestore.length > 0) {
        const transaction = db.transaction(storeNamesToRestore, "readwrite")
        for (const storeName of storeNamesToRestore) {
            const storeInfo = dbData.stores[storeName]
            const store = transaction.objectStore(storeName)

            for (const record of storeInfo.data) {
                let valueToPut = record.value

                if (dbName === DBN && storeName === "FileChunks") {
                    const newFileId = idMap.get(valueToPut.fileId)
                    if (newFileId == null) continue // Skip orphaned chunks
                    valueToPut.fileId = newFileId
                }

                // Convert any ArrayBuffers in FileCacheDB back to Blobs
                if (dbName === DBN && storeName === FILES_SN && valueToPut.buffer instanceof ArrayBuffer) {
                    valueToPut.buffer = new Blob([valueToPut.buffer])
                }

                // This is the universal put logic
                if (store.keyPath) {
                    // For stores with in-line keys (like Folders, Rules, etc)
                    store.put(valueToPut)
                } else {
                    // For stores with out-of-line keys
                    store.put(valueToPut, record.key)
                }
            }
        }
        await promisifyTransaction(transaction)
    }

    db.close()
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

async function streamFileToDb(db, folderName, path, file) {
    const metaTx = db.transaction([FILES_SN], "readwrite")
    const fileStore = metaTx.objectStore(FILES_SN)
    const fileMetadata = {
        folderName,
        path,
        type: getMimeType(path) || file.type,
        size: file.size,
        lookupPath: `${folderName}/${path}`
    }
    const fileId = await promisifyRequest(fileStore.add(fileMetadata))
    await promisifyTransaction(metaTx)

    // Now, process the chunks in batches for performance.
    const reader = file.stream().getReader()
    let chunkIndex = 0
    let chunkBatch = []

    while (true) {
        const { done, value } = await reader.read()
        if (value) {
            chunkBatch.push({ fileId, index: chunkIndex++, data: value })
        }

        if ((chunkBatch.length >= BATCH_SIZE || done) && chunkBatch.length > 0) {
            const chunkTx = db.transaction(["FileChunks"], "readwrite")
            const chunkStore = chunkTx.objectStore("FileChunks")
            for (const chunk of chunkBatch) {
                chunkStore.add(chunk)
            }
            await promisifyTransaction(chunkTx)
            chunkBatch = []
        }

        if (done) {
            break // Exit the loop once the file stream is exhausted.
        }
    }
}

async function deleteFileByPathAndChunks(db, folderName, path) {
    const fullPath = `${folderName}/${path}`
    const transaction = db.transaction([FILES_SN, "FileChunks"], "readwrite")
    const fileStore = transaction.objectStore(FILES_SN)
    const chunkStore = transaction.objectStore("FileChunks")
    const lookupIndex = fileStore.index("lookup")
    const chunkIndex = chunkStore.index("by_file")

    const record = await promisifyRequest(lookupIndex.get(fullPath))
    if (record?.id) {
        const chunkKeys = await promisifyRequest(chunkIndex.getAllKeys(IDBKeyRange.only(record.id)))
        for (const key of chunkKeys) {
            chunkStore.delete(key)
        }
        fileStore.delete(record.id)
    }

    return promisifyTransaction(transaction)
}

/**
 * Gathers all application data (IndexedDB, localStorage, cookies), optionally
 * encrypts it, and presents a download link to the user.
 */
// In main.js

/**
 * Gathers all application data (IndexedDB, localStorage, cookies), optionally
 * encrypts it, and presents a download link to the user
 */
async function exportData() {
    const password = prompt("Enter an optional password to encrypt the export leave blank for a plaintext export:")
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

            const dbProcessingPromises = allDbs.map(async (dbInfo) => {
                const dbName = dbInfo.name
                if (!exportRuntimeFS && dbName === DBN) return null
                if (exportRuntimeFS && !exportIndexedDB && dbName !== DBN) return null

                try {
                    const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open(dbName)
                        request.onsuccess = () => resolve(request.result)
                        request.onerror = e => reject(new Error(`Could not open db: ${dbName}`))
                    })

                    const dbExport = { version: db.version, stores: {} }
                    const storeNames = Array.from(db.objectStoreNames)

                    if (storeNames.length > 0) {
                        const transaction = db.transaction(storeNames, "readonly")
                        const storeProcessingPromises = storeNames.map(async (storeName) => {
                            const store = transaction.objectStore(storeName)
                            const indexes = Array.from(store.indexNames).map(name => {
                                const index = store.index(name)
                                return { name: index.name, keyPath: index.keyPath, unique: index.unique, multiEntry: index.multiEntry }
                            })

                            const recordsWithKeys = await new Promise((resolve, reject) => {
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

                            if (dbName === DBN && storeName === FILES_SN) {
                                const recordsWithBlobs = recordsWithKeys.filter(r => r.value.buffer instanceof Blob)
                                if (recordsWithBlobs.length > 0) {
                                    console.log(`Found ${recordsWithBlobs.length} file records with Blobs to process...`)
                                    const MAX_BATCH_SIZE_BYTES = 128 * 1024 * 1024 // 128MB
                                    let currentBatch = []
                                    let currentBatchSizeBytes = 0
                                    let batchNum = 1

                                    for (const recordItem of recordsWithBlobs) {
                                        const recordSize = recordItem.value.buffer.size
                                        if (currentBatch.length > 0 && (currentBatchSizeBytes + recordSize) > MAX_BATCH_SIZE_BYTES) {
                                            console.log(`Processing batch #${batchNum}: ${currentBatch.length} files, ~${(currentBatchSizeBytes / 1024 / 1024).toFixed(2)} MB`)
                                            const conversionPromises = currentBatch.map(async (item) => {
                                                const buffer = await item.value.buffer.arrayBuffer()
                                                item.value.buffer = buffer // Modify the object directly
                                            })
                                            await Promise.all(conversionPromises)
                                            currentBatch = []
                                            currentBatchSizeBytes = 0
                                            batchNum++
                                        }
                                        currentBatch.push(recordItem)
                                        currentBatchSizeBytes += recordSize
                                    }

                                    if (currentBatch.length > 0) {
                                        console.log(`Processing final batch #${batchNum}: ${currentBatch.length} files, ~${(currentBatchSizeBytes / 1024 / 1024).toFixed(2)} MB`)
                                        const conversionPromises = currentBatch.map(async (item) => {
                                            const buffer = await item.value.buffer.arrayBuffer()
                                            item.value.buffer = buffer // Modify the object directly
                                        })
                                        await Promise.all(conversionPromises)
                                    }
                                }
                            }

                            return [storeName, {
                                schema: { keyPath: store.keyPath, autoIncrement: store.autoIncrement, indexes },
                                data: recordsWithKeys
                            }]
                        })

                        const processedStoresArray = await Promise.all(storeProcessingPromises)
                        for (const [storeName, storeData] of processedStoresArray) {
                            dbExport.stores[storeName] = storeData
                        }
                    }

                    db.close()
                    return [dbName, dbExport]
                } catch (e) {
                    console.warn(`Could not export database "${dbName}" Skipping Reason: ${e.name} - ${e.message}`)
                    return null
                }
            })

            const processedDbsArray = (await Promise.all(dbProcessingPromises)).filter(Boolean)
            for (const [dbName, dbExport] of processedDbsArray) {
                dataToExport.indexedDB[dbName] = dbExport
            }
        }

        const encoded = CBOR.encode(dataToExport)
        let finalBuffer = password ? CBOR.encode(await encryptPayload(encoded, password)) : encoded

        if (window.showSaveFilePicker) {
            try {
                const handle = await window.showSaveFilePicker({
                    suggestedName: "result.cbor",
                    types: [{
                        description: "CBOR File",
                        accept: { "application/octet-stream": [".cbor"] },
                    }],
                })
                const writable = await handle.createWritable()
                await writable.write(finalBuffer)
                await writable.close()
                console.log("Data export complete!")
            } catch (err) {
                if (err.name !== "AbortError") {
                    console.error("Could not save file with File System Access API, falling back:", err)
                    createAndDisplayDownloadLink(finalBuffer, document.getElementById("c3").parentElement, "result.cbor")
                }
            }
        } else {
            createAndDisplayDownloadLink(finalBuffer, document.getElementById("c3").parentElement, "result.cbor")
        }

        console.log("Data export prepared")
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

    input.onchange = async e => {
        let data = null // Hoist data to be accessible in the finally block
        try {
            const file = e.target.files[0]
            if (!file) {
                setUiBusy(false)
                return
            }

            // Close all DB connections before proceeding to avoid a deadlock
            const controller = navigator.serviceWorker.controller
            if (controller) {
                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error("SW ack for import prep timed out.")), 5000)
                    const messageListener = msgEvent => {
                        if (msgEvent.data.type === "IMPORT_READY") {
                            navigator.serviceWorker.removeEventListener("message", messageListener)
                            clearTimeout(timeout)
                            resolve()
                        }
                    }
                    navigator.serviceWorker.addEventListener("message", messageListener)
                    controller.postMessage({ type: "PREPARE_FOR_IMPORT" })
                })
            }
            if (dbPromise) {
                const db = await dbPromise
                db.close()
                dbPromise = null
            }

            if (navigator.storage && navigator.storage.estimate) {
                const estimate = await navigator.storage.estimate()
                const availableSpace = estimate.quota - estimate.usage
                if (file.size > availableSpace) {
                    throw new Error("Import failed: The file size is larger than available browser storage.")
                }
            }

            const buffer = await file.arrayBuffer()
            data = CBOR.decodeMultiple(new Uint8Array(buffer))[0]

            if (!data) {
                throw new Error("Import file is empty or not a valid CBOR file.")
            }

            if (data.type === "FS-EE") {
                const password = prompt("This data is encrypted. Please enter the password:")
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

                data = CBOR.decode(new Uint8Array(decryptedPayload))
                if (!data) {
                    throw new Error("Decrypted payload is empty or invalid.")
                }
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
                    await clearAndFillDatabase(dbName, dbData)
                }
            }

            await listFolders()
            alert("Import complete! You may need to reload the page for all changes to take effect.")
        } catch (error) {
            console.error("Import failed:", error)
            alert(`An error occurred during import: ${error.message || error.name}`)
        } finally {
            data = null
            setUiBusy(false)
        }
    }
}

// Crucial for saving memory!
function normalizeToArrayBuffers(data) {
    if (ArrayBuffer.isView(data)) {
        return new data.constructor(data)
    }

    // Handle the case of a standalone ArrayBuffer (used by RuntimeFS).
    if (data instanceof ArrayBuffer) {
        return data.slice(0)
    }

    // Recurse for arrays and objects to process their contents.
    if (Array.isArray(data)) {
        return data.map(item => normalizeToArrayBuffers(item))
    }
    if (data !== null && typeof data === "object" && data.constructor === Object) {
        const newObj = {}
        for (const key in data) {
            newObj[key] = normalizeToArrayBuffers(data[key])
        }
        return newObj
    }

    // Return all other data types (numbers, strings, etc.) as-is.
    return data
}

/**
 * Creates an empty IndexedDB database with a specific version number.
 * This is used to handle edge cases like Emscripten's /idbfs-test.
 * @param {string} dbName The name of the database to create.
 * @param {number} version The version number for the new database.
 * @returns {Promise<void>}
 */
async function createEmptyDatabase(dbName, version) {
    console.log(`Creating special-case empty database: "${dbName}" version ${version}`)

    // Ensure any old version is completely gone.
    await new Promise((resolve, reject) => {
        const delRequest = indexedDB.deleteDatabase(dbName)
        delRequest.onerror = e => reject(new Error(`Could not delete database: ${dbName}`))
        delRequest.onblocked = () => reject(new Error(`Import failed: Database "${dbName}" is open in another tab.`))
        delRequest.onsuccess = () => resolve()
    })

    return new Promise((resolve, reject) => {
        const request = indexedDB.open(dbName, version)
        request.onerror = e => reject(new Error(`Could not create empty database: ${dbName}`))
        request.onupgradeneeded = e => {
            // The event itself creates the database, no action needed inside.
        }
        request.onsuccess = e => {
            e.target.result.close()
            resolve()
        }
    })
}

async function createAndDisplayDownloadLink(buffer, parentElement, filename) {
    const blob = new Blob([buffer], { type: "application/octet-stream" })
    const url = URL.createObjectURL(blob)

    const a = document.createElement("a")
    a.style.display = "none"
    a.href = url
    a.download = filename
    a.textContent = "Download export!"
    a.style.color = "#ccc"
    a.style.display = "block"
    a.style.padding = "8px"
    a.style.border = "1px solid #15e264"
    a.style.borderRadius = "5px"
    a.style.textAlign = "center"
    a.style.marginBottom = "5px"

    // Revoke the object URL and hide both elements after click
    a.addEventListener("click", async function (e) {
        if (window.showSaveFilePicker) {
            e.preventDefault()
            // Try one more time; this time any SecurityErrors should be solved
            try {
                const handle = await window.showSaveFilePicker({
                    suggestedName: "result.cbor",
                    types: [{
                        description: "CBOR File",
                        accept: { "application/octet-stream": [".cbor"] },
                    }]
                })
                const writable = await handle.createWritable()
                await writable.write(buffer)
                await writable.close()
                console.log("Data export complete!")
                setTimeout(function () {
                    URL.revokeObjectURL(url)
                    parentElement.removeChild(a)
                }, 200)
                return
            } catch (err) {
                if (err.name === "AbortError") {
                    setTimeout(function () {
                        URL.revokeObjectURL(url)
                        parentElement.removeChild(a)
                    }, 200)
                    return
                }
                console.error("Could not save file with File System Access API, falling back to normal download:", err)
            }
            // Save picker failed, save normally
            a.href = url
            a.download = filename
            a.click()
            return
        }

        setTimeout(function () {
            URL.revokeObjectURL(url)
            parentElement.removeChild(a)
        }, 200)
    })

    parentElement.appendChild(a)
}

// Derives a cryptographic key from a password using PBKDF2 (600k iterations is decent; this is meant for lower-end devices)
async function deriveKeyFromPassword(password, salt, iterations = 600000) {
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
        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt)

        for (const path in files) {
            const file = files[path]
            const iv = crypto.getRandomValues(new Uint8Array(12))
            const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, file.buffer)
            file.buffer = concatBuffers(iv.buffer, encryptedBuffer)
        }
        files[".metadata"] = { buffer: new Blob([salt.buffer]), type: "application/octet-stream" }

        await processAndStoreFolder(name, files, "pdf")

        console.log(`Folder "${name}" encrypted and stored successfully.`)
        folderNameInput.value = ""
    } catch (err) {
        if (err.name !== "AbortError") {
            console.error("Password encryption error:", err)
            alert("An error occurred during encryption: " + err.message)
        }
    } finally {
        setUiBusy(false)
    }
}

async function encryptAndSaveFolderWithPassword() {
    const password = prompt("After entering a password, first select the folder you want to encrypt, then another folder (ideally empty) to encrypt the data to. Enter a secure password:")
    if (!password) return

    try {
        setUiBusy(true)
        const sourceDirHandle = await window.showDirectoryPicker({ mode: "read" })
        const destDirHandle = await window.showDirectoryPicker({ mode: "readwrite" })

        // Derive the master key from the password.
        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt) // Your existing helper is perfect.

        const fileMap = await scanFilesRecursively(sourceDirHandle)
        const pathManifest = {}

        // Encrypt each file and save it with a UUID name.
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

        // Create and encrypt the manifest payload.
        const manifestString = JSON.stringify(pathManifest)
        const manifestBuffer = new TextEncoder().encode(manifestString)
        const manifestIv = crypto.getRandomValues(new Uint8Array(12))
        const encryptedManifestPayload = await crypto.subtle.encrypt({ name: "AES-GCM", iv: manifestIv }, key, manifestBuffer)

        // Create the final manifest.enc file content.
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

function initializeApp() {
    document.getElementById("folderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || uploadFolder()))
    document.getElementById("openFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || openFile()))
    document.getElementById("fileName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || openFile()))
    document.getElementById("deleteFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), currentlyBusy || deleteFolder()))
    document.getElementById("folderUploadFallbackInput").addEventListener("change", uploadFolderFallback)
    document.getElementById("folderUploadFallbackInput").addEventListener("cancel", () => setUiBusy(false))
    document.body.addEventListener("dragover", e => { e.preventDefault(), document.body.style.backgroundColor = "#385b7e" })
    document.body.addEventListener("dragleave", () => { document.body.style.backgroundColor = "" })
    document.body.addEventListener("drop", async e => {
        e.preventDefault()
        document.body.style.backgroundColor = ""
        const files = e.dataTransfer.files
        if (!files || files.length === 0) return alert("No files were dropped.")
        let defaultFolderName = ""
        if (files[0].webkitRelativePath) {
            defaultFolderName = files[0].webkitRelativePath.split("/")[0]
        } else {
            return alert("Please drop a folder, not individual files.")
        }
        const name = prompt("Please enter a name for the folder:", defaultFolderName)
        if (name === null) return
        setUiBusy(true)
        try {
            await processFileListAndStore(name.trim(), files)
        } catch (err) {
            console.error("Drag-and-drop error:", err)
            alert("An error occurred during drop: " + err.message)
        } finally {
            setUiBusy(false)
        }
    })

    // Initial folder list load
    getDb().then(() => listFolders())
}

document.addEventListener("DOMContentLoaded", () => {
    initializeApp()

    if ("serviceWorker" in navigator) {
        let refreshing = false
        // This listener handles reloading the page when a new service worker takes control
        navigator.serviceWorker.addEventListener("controllerchange", () => {
            if (refreshing) return
            refreshing = true
            window.location.reload()
        })

        navigator.serviceWorker.register("./sw.js").then(reg => {
            // This event fires when a new version of the service worker is found
            reg.addEventListener("updatefound", () => {
                const newWorker = reg.installing
                newWorker.addEventListener("statechange", () => {
                    if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                        console.log("A new version is available! The page will reload automatically.")
                    }
                })
            })

            // Check if a service worker is active but not controlling the page
            // This is the state after a force reload (Shift+Refresh)
            navigator.serviceWorker.ready.then(registration => {
                if (!navigator.serviceWorker.controller && registration.active) {
                    console.log("Service worker is active but not controlling the page. Reloading to fix...")
                    window.location.reload()
                }
            })

        }).catch(err => {
            console.error("Service Worker registration failed:", err)
            alert("The application could not start correctly. Please try reloading the page.")
        })
    } else {
        alert("Service Workers are not supported in this browser. The application will not work.")
        console.error("Service Workers not supported.")
    }

    const regexTextarea = document.getElementById("regex")
    const headersTextarea = document.getElementById("headers")

    // Load saved values on startup
    try {
        regexTextarea.value = localStorage.getItem("fsRegex") || ""
        headersTextarea.value = localStorage.getItem("fsHeaders") || ""
    } catch (e) {
        console.warn(e)
    }

    setTimeout(() => {
        try {
            // Save values on input
            regexTextarea.addEventListener("input", () => {
                localStorage.setItem("fsRegex", regexTextarea.value)
            })
            headersTextarea.addEventListener("input", () => {
                localStorage.setItem("fsHeaders", headersTextarea.value)
            })
        } catch (e) {
            console.warn("Could not load saved rules from localStorage:", e)
        }
    }, 0)
})