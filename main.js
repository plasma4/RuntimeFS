// Constants for IndexedDB database names and version.
const DBN = "FileCacheDB"
const SN = "Folders"
const META_SN = "Metadata"
const DB_VERSION = 1

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

function setUiBusy(isBusy) {
    Array.from(document.getElementsByTagName("button")).forEach(button => button.disabled = isBusy)
}

// Request persistent storage to prevent the browser from clearing data automatically.
navigator.storage.persist().then(persistent => {
    if (persistent) {
        console.log("Storage will not be cleared except by explicit user action.")
    } else {
        console.log("Storage may be cleared by the browser.")
    }
})

// A promise that resolves with the IndexedDB database connection.
const dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DBN, DB_VERSION)
    // This event is triggered if the database version is new or the database doesn't exist.
    request.onupgradeneeded = function (event) {
        const db = event.target.result
        // Create the necessary object stores if they don't already exist.
        if (!db.objectStoreNames.contains(SN)) {
            db.createObjectStore(SN, { keyPath: "id" })
        }
        if (!db.objectStoreNames.contains(META_SN)) {
            db.createObjectStore(META_SN, { keyPath: "id" })
        }
    }
    request.onsuccess = (event) => resolve(event.target.result)
    request.onerror = (event) => reject(event.target.errorCode)
})

// Once the database is ready, populate the list of existing folders.
dbPromise.then(() => listFolders())

// Add a click listener to the "Generate New Key Pair" button.
document.getElementById("generateBtn").addEventListener("click", async () => {
    const keyPair = await generateAndStoreKeyPair()
    await c(keyPair.publicKey)
    alert("Copied Public Key!")
})

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
            if (e.name === 'NotFoundError') {
                files = await getFilesRecursively(localDirHandle)
                if (observer) {
                    observer.disconnect()
                }

                // Create and start the new observer to watch the local folder for changes.
                observer = new FileSystemObserver((records) => {
                    console.log(`${records.length} file system change(s) detected.`)
                    changes.push(...records)
                })
                try {
                    observer.observe(dirHandle, { recursive: true })
                } catch (e) {
                    if (e.name === "NotSupportedError") {
                        // Older browser/implementation perhaps? Can't observe then.
                        console.error("Cannot observe directories for modifications.")
                        console.warn(e)
                    } else {
                        // Re-throw any other unexpected errors.
                        throw e
                    }
                }

                changes.length = 0
            } else {
                throw e
            }
        }

        const db = await dbPromise
        const transaction = db.transaction([SN], "readwrite")
        const folderStore = transaction.objectStore(SN)
        const folderObject = { id: name, files: files }
        folderStore.delete(name)
        folderStore.put(folderObject)

        await promisifyTransaction(transaction)

        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
        }
        console.log(`Folder "${name}" stored successfully.`)
        folderNameInput.value = ""
        document.getElementById("openFolderName").value = name
        await listFolders()
    } catch (err) {
        if (err.name !== "AbortError") {
            console.error("Upload error:", err)
            alert("An error occurred during upload: " + err.message)
        }
    } finally {
        setUiBusy(false)
    }
}

async function decryptAndLoadFolder(dirHandle, manifestHandle) {
    const manifestFile = await manifestHandle.getFile()
    const manifestContent = await manifestFile.text()
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
            files[newPath] = {
                buffer: await file.arrayBuffer(),
                type: getMimeType(newPath) || file.type
            }
        } else if (entry.kind === "directory") {
            // If the entry is a directory, recurse into it.
            Object.assign(files, await getFilesRecursively(entry, newPath))
        }
    }
    return files
}

// Encrypts a source folder using a public key and saves it to a destination folder.
async function useK() {
    const folderName = document.getElementById("encryptFolderName").value.trim()
    const publicKeyBase64 = document.getElementById("k").value.trim()
    if (!folderName || !publicKeyBase64) {
        alert("Folder name and Public Key are required.")
        return
    }
    setUiBusy(true)
    try {
        // Let the user pick a source folder to encrypt and a destination folder to save to.
        const sourceDirHandle = await window.showDirectoryPicker({ mode: "read" })
        const destDirHandle = await window.showDirectoryPicker({ mode: "readwrite" })
        const fileMap = await scanFilesRecursively(sourceDirHandle)

        // The path manifest maps original file paths to UUIDs.
        const pathManifest = {}
        for (const originalPath in fileMap) {
            const file = fileMap[originalPath]
            if (file === null) {
                pathManifest[originalPath] = null
                continue
            }
            // Generate a UUID for the encrypted file name to obscure it.
            const uuid = crypto.randomUUID()
            pathManifest[originalPath] = uuid
            const fileBuffer = await file.arrayBuffer()
            // Encrypt the file content.
            const encryptedContent = await encryptWithPublicKey(publicKeyBase64, fileBuffer)
            // Write the encrypted content to the new file in the destination directory.
            const newFileHandle = await destDirHandle.getFileHandle(uuid, { create: true })
            const writable = await newFileHandle.createWritable()
            await writable.write(encryptedContent)
            await writable.close()
        }
        // Encrypt and save the manifest file itself.
        const manifestString = JSON.stringify(pathManifest)
        const encryptedManifest = await encryptWithPublicKey(publicKeyBase64, new TextEncoder().encode(manifestString))
        const manifestFileHandle = await destDirHandle.getFileHandle("manifest.enc", { create: true })
        const manifestWritable = await manifestFileHandle.createWritable()
        await manifestWritable.write(encryptedManifest)
        await manifestWritable.close()
        alert(`Encryption complete! Folder saved in "${destDirHandle.name}".`)
    } catch (err) {
        if (err.name !== "AbortError") {
            alert("An error occurred during encryption: " + err.message)
        }
    } finally {
        setUiBusy(false)
    }
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

    const db = await dbPromise
    const folderData = await db.transaction(SN).objectStore(SN).get(folderName)

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
            // The salt is stored in a .metadata file within the folder data.
            const salt = new Uint8Array(folderData.files[".metadata"].buffer)
            // Derive the decryption key from the user's password and the salt.
            const key = await deriveKeyFromPassword(password, salt)

            // Generate a unique ID for this request.
            const requestId = crypto.randomUUID()
            // Send the decryption key to the service worker.
            if (navigator.serviceWorker.controller) {
                navigator.serviceWorker.controller.postMessage({
                    type: "DECRYPT_KEY",
                    requestId: requestId,
                    key: key
                })
            }
            // Open the file, passing the request ID.
            openUrl(folderName, fileName, requestId)
        } catch (error) {
            console.error("Decryption failed:", error)
            alert("Decryption failed. Please check the folder name and password.")
        } finally {
            setUiBusy(false)
        }
    } else {
        // If not encrypted, open the file directly.
        openUrl(folderName, fileName, null)
    }
}

// Constructs the URL for a virtual file and opens it in a new tab.
function openUrl(folderName, fileName, decryptionRequestId) {
    const regexRules = document.getElementById("regex").value.trim()
    // Add a cache-busting parameter to the URL.
    const cacheBust = `v=${Date.now()}`
    let url = `/n/${encodeURIComponent(folderName)}/${encodeURIComponent(fileName)}?${cacheBust}`

    // Use the decryption ID if it exists, otherwise create a new one only if regex rules are present.
    const finalRequestId = decryptionRequestId || (regexRules ? crypto.randomUUID() : null)

    if (finalRequestId) {
        url += `&reqId=${finalRequestId}`

        // If regex rules are present, send them to the service worker.
        if (regexRules && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: "REGRULES",
                requestId: finalRequestId,
                rules: regexRules
            })
        }
    }

    window.open(url, "_blank")
}

// Button 1: Sync Only
async function syncFiles() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")
    if (changes.length === 0) return alert("No changes to sync.")

    setUiBusy(true)
    try {
        // 1. Do the DB work
        const count = await performSyncToDb()
        // 2. Tell SW to clear cache and WAIT for confirmation
        await invalidateCacheAndWait(folderName)
        alert(`Synced ${count} changes.`)
    } catch (e) {
        console.error(e)
        alert("Sync failed: " + e.message)
    } finally {
        setUiBusy(false)
    }
}

// Button 2: Sync & Open
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
    // 1. If there are no changes, do nothing.
    if (changes.length === 0) {
        return 0
    }

    console.log(`Processing ${changes.length} changes for "${folderName}"...`)

    // 2. Convert the raw 'changes' array into a structured list of updates.
    const updates = []
    for (const change of changes) {
        const type = change.type
        switch (type) {
            case "created":
            case "modified": {
                const path = change.relativePathComponents.join("/")
                const fileHandle = await getHandleFromPath(dirHandle, path)
                if (fileHandle && fileHandle.kind === 'file') {
                    const file = await fileHandle.getFile()
                    updates.push({ type: "update", path: path, data: { buffer: await file.arrayBuffer(), type: getMimeType(path) || file.type } })
                }
                break
            }
            case "deleted": {
                const path = change.relativePathComponents.join("/")
                updates.push({ type: "delete", path: path })
                break
            }
            case "moved": {
                const oldPath = change.relativePathMovedFrom.join("/")
                const newPath = change.relativePathComponents.join("/")
                // A 'move' is treated as deleting the old file and creating/updating the new one.
                updates.push({ type: "delete", path: oldPath })
                const fileHandle = await getHandleFromPath(dirHandle, newPath)
                if (fileHandle && fileHandle.kind === 'file') {
                    const file = await fileHandle.getFile()
                    updates.push({ type: "update", path: newPath, data: { buffer: await file.arrayBuffer(), type: getMimeType(newPath) || file.type } })
                }
                break
            }
        }
    }
    // 3. Clear the global changes array now that they've been processed.
    changes.length = 0

    // 4. Start the database transaction.
    const db = await dbPromise
    const transaction = db.transaction([SN], "readwrite")
    const folderStore = transaction.objectStore(SN)
    const folderData = await promisifyRequest(folderStore.get(folderName))

    if (!folderData) {
        throw new Error(`Cannot sync: Folder "${folderName}" not found in DB.`)
    }

    // 5. Apply the structured updates to the folder object in memory.
    for (const update of updates) {
        if (update.type === "update") {
            folderData.files[update.path] = update.data
        } else if (update.type === "delete") {
            delete folderData.files[update.path]
        }
    }

    // 6. Write the modified folder object back to the database.
    folderStore.put(folderData)
    await promisifyTransaction(transaction)
    console.log("DB Update complete.")

    // 7. Return the number of changes that were processed.
    return updates.length
}

// Fetches all folder names from IndexedDB and displays them in the UI.
async function listFolders() {
    const db = await dbPromise
    const transaction = db.transaction(db.objectStoreNames, "readonly")
    const folderStore = transaction.objectStore(SN)
    const allFolders = await promisifyRequest(folderStore.getAll())
    const folderList = document.getElementById("folderList")
    folderList.innerHTML = "" // Clear the current list.
    allFolders.sort((a, b) => a.id.localeCompare(b.id)).forEach(folder => {
        const li = document.createElement("li")
        // Add a visual indicator for encrypted folders.
        li.textContent = folder.encryptionType === "pdf" ? `[Locked] ${folder.id}` : folder.id
        folderList.appendChild(li)
    })
}

// Deletes a folder from IndexedDB.
async function deleteFolder() {
    const folderName = document.getElementById("deleteFolderName").value.trim()
    if (!folderName) {
        alert("Please enter the name of the folder to delete.")
        return
    }
    if (!confirm(`Are you sure you want to remove the folder "${folderName}"?`)) return
    setUiBusy(true)
    try {
        const db = await dbPromise
        const transaction = db.transaction([SN, META_SN], "readwrite")
        const folderStore = transaction.objectStore(SN)
        await promisifyRequest(folderStore.delete(folderName))
        console.log(`Folder "${folderName}" deleted successfully.`)
        document.getElementById("deleteFolderName").value = ""
        // Refresh the folder list in the UI.
        await listFolders()
    } catch (error) {
        console.error("Transaction error:", error)
    } finally {
        setUiBusy(false)
    }
}

// Generates an RSA key pair for public key encryption.
async function generateAndStoreKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"])
    // Note: Storing the private key in localStorage is convenient but not highly secure.
    // For production applications, consider more secure storage mechanisms.
    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey)
    localStorage.setItem("pk", JSON.stringify(privateKeyJwk))
    return keyPair
}

// Copies the public key to the clipboard in Base64 format.
async function c(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey)
    const base64PublicKey = btoa(String.fromCharCode(...new Uint8Array(exported)))
    navigator.clipboard.writeText(base64PublicKey)
}

// A helper function to concatenate two ArrayBuffers.
function concatBuffers(buffer1, buffer2) {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength)
    tmp.set(new Uint8Array(buffer1), 0)
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength)
    return tmp.buffer
}

// Implements a hybrid encryption scheme (RSA-OAEP + AES-GCM).
async function encryptWithPublicKey(publicKeyBase64, plainBuffer) {
    // 1. Generate a random symmetric AES key.
    const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    // 2. Encrypt the file data with the AES key.
    const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, plainBuffer)
    const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey)

    // 3. Encrypt the AES key with the provided public RSA key.
    const keyData = atob(publicKeyBase64)
    const keyBuffer = new Uint8Array(keyData.length)
    for (let i = 0; i < keyData.length; i++) keyBuffer[i] = keyData.charCodeAt(i)
    const importedRsaKey = await window.crypto.subtle.importKey("spki", keyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"])
    const encryptedAesKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedRsaKey, exportedAesKey)

    // 4. Combine the encrypted AES key, IV, and encrypted file data into a single buffer.
    const combinedBuffer = concatBuffers(encryptedAesKey, iv.buffer)
    return concatBuffers(combinedBuffer, encryptedFileBuffer)
}

// Decrypts a single buffer using the hybrid encryption private key.
async function decryptBufferWithPrivateKey(privateKey, encryptedBuffer) {
    // 1. Extract the encrypted AES key, IV, and file data from the combined buffer.
    const encryptedAesKey = encryptedBuffer.slice(0, 256)
    const iv = encryptedBuffer.slice(256, 256 + 12)
    const encryptedFileBuffer = encryptedBuffer.slice(256 + 12)
    // 2. Decrypt the AES key with the private RSA key.
    const decryptedAesKeyBuffer = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedAesKey)
    // 3. Import the decrypted AES key.
    const aesKey = await window.crypto.subtle.importKey("raw", decryptedAesKeyBuffer, { name: "AES-GCM" }, true, ["decrypt"])
    // 4. Decrypt the file data with the AES key.
    return await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encryptedFileBuffer)
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

        // 1. Set a timeout so we don't hang forever
        const timeout = setTimeout(() => {
            controller.removeEventListener('message', messageListener)
            setUiBusy(false)
            reject(new Error("Service worker cache invalidation timed out."))
        }, 4000)

        // 2. Define the listener for the reply
        const messageListener = (event) => {
            if (event.data.type === 'CACHE_INVALIDATED' && event.data.folderName === folderName) {
                clearTimeout(timeout)
                controller.removeEventListener('message', messageListener)
                console.log("Confimation received: Cache invalidated.")
                resolve()
            }
        }

        // 3. Start listening and send the command
        navigator.serviceWorker.addEventListener('message', messageListener)
        controller.postMessage({ type: "INVALIDATE_CACHE", folderName: folderName })
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
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
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

/**
 * Safely converts an ArrayBuffer to a Base64 string, processing in chunks
 * to avoid "Maximum call stack size exceeded" errors with large files.
 * @param {ArrayBuffer} buffer The ArrayBuffer to convert.
 * @returns {string} The Base64 encoded string.
 */
function bufferToBase64Safe(buffer) {
    let binary = ''
    const bytes = new Uint8Array(buffer)
    const len = bytes.byteLength
    // We process the buffer in chunks to avoid passing too many arguments
    // to String.fromCharCode() at once, which would crash the browser's JS engine.
    const chunkSize = 8192 // 8KB chunks are a safe and performant size.

    for (let i = 0; i < len; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize)
        // String.fromCharCode.apply is a memory-safe way to convert a chunk
        // of byte values into a string.
        binary += String.fromCharCode.apply(null, chunk)
    }
    return btoa(binary)
}

/**
 * Gathers all application data (IndexedDB, localStorage, cookies), optionally
 * encrypts it, and presents a download link to the user.
 */
async function exportData() {
    // This prompt remains as it's a useful feature for any kind of data export.
    const password = prompt("Enter an optional password to encrypt the export. Leave blank for a plaintext export.")
    console.log("Starting general data export (excluding RuntimeFS data)...")
    setUiBusy(true)

    try {
        const dataToExport = {}

        if (document.getElementById("c2").checked) {
            dataToExport.localStorage = {}
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i)
                if (key !== "pk") {
                    dataToExport.localStorage[key] = localStorage.getItem(key)
                }
            }
        }

        if (document.getElementById("c3").checked) {
            const allDbs = await indexedDB.databases()
            for (const dbInfo of allDbs) {
                const dbName = dbInfo.name
                if (dbName === DBN) {
                    console.log(`Skipping RuntimeFS database: '${dbName}'`)
                    continue // Go to the next database in the list.
                }

                console.log(`Exporting from database: '${dbName}'`)

                // Open a NEW connection specifically to this other database.
                // We DO NOT use the global dbPromise here.
                const db = await new Promise((resolve, reject) => {
                    const request = indexedDB.open(dbName)
                    request.onsuccess = () => resolve(request.result)
                    request.onerror = () => reject(request.error)
                })

                // Prepare the JSON structure: dataToExport.indexedDB.UnityCache = {}
                dataToExport.indexedDB[dbName] = {}
                const transaction = db.transaction(db.objectStoreNames, "readonly")

                // Now, loop through all the object stores within THIS database.
                for (const storeName of db.objectStoreNames) {
                    const store = transaction.objectStore(storeName)
                    const records = await promisifyRequest(store.getAll())

                    // The Base64 conversion is kept in case other DBs store binary data.
                    records.forEach(record => {
                        // This is a simple check; a more robust exporter might
                        // need to recursively scan objects for ArrayBuffers.
                        if (record && record.buffer instanceof ArrayBuffer) {
                            record.buffer = bufferToBase64Safe(record.buffer)
                        }
                    })

                    // Store the records under the correct database and store name.
                    dataToExport.indexedDB[dbName][storeName] = records
                }
                // It's good practice to close the connection when we're done.
                db.close()
            }
        }

        if (document.getElementById("c1").checked) {
            dataToExport.cookies = document.cookie
        }

        let finalObjectToExport
        if (password) {
            const salt = crypto.getRandomValues(new Uint8Array(16))
            const iv = crypto.getRandomValues(new Uint8Array(12))
            const key = await deriveKeyFromPassword(password, salt)
            const dataString = JSON.stringify(dataToExport)
            const dataBuffer = new TextEncoder().encode(dataString)
            const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, dataBuffer)

            finalObjectToExport = {
                type: "FS-EE",
                s: bufferToBase64Safe(salt.buffer),
                iv: bufferToBase64Safe(iv.buffer),
                p: bufferToBase64Safe(encryptedBuffer)
            }
        } else {
            finalObjectToExport = {
                type: "FS-PE",
                p: dataToExport
            }
        }

        const jsonString = JSON.stringify(finalObjectToExport)
        const importExportContainer = document.querySelector("#c3").parentElement
        createAndDisplayDownloadLink(jsonString, importExportContainer)

        console.log("General data export prepared. Awaiting user download.")

    } catch (error) {
        console.error("General export failed:", error)
        alert("An error occurred during export: " + error.message)
    } finally {
        setUiBusy(false)
    }
}

/**
 * Imports application data from a user-selected JSON file,
 * handling both plaintext and encrypted exports.
 */
async function importData() {
    // The file picker logic remains the same.
    try {
        const input = document.createElement("input")
        input.type = "file"
        input.accept = ".json, .txt"
        input.onchange = async (event) => {
            setUiBusy(true)
            const file = event.target.files[0]
            if (!file) {
                setUiBusy(false)
                return
            }

            try {
                // The decryption logic also remains the same.
                const content = await file.text()
                const wrapper = JSON.parse(content)
                let data

                if (wrapper.type === "FS-EE") {
                    const password = prompt("This file is encrypted. Please enter the password:")
                    if (!password) {
                        alert("Password required to import this file.")
                        setUiBusy(false)
                        return
                    }

                    const salt = base64ToBuffer(wrapper.s)
                    const iv = base64ToBuffer(wrapper.iv)
                    const payload = base64ToBuffer(wrapper.p)
                    const key = await deriveKeyFromPassword(password, salt)

                    const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, payload)
                    const decryptedString = new TextDecoder().decode(decryptedBuffer)
                    data = JSON.parse(decryptedString)
                } else if (wrapper.type === "FS-PE") {
                    data = wrapper.p
                } else {
                    data = wrapper
                }

                // Restore localStorage, filtering out the RuntimeFS private key
                if (data.localStorage) {
                    for (const key in data.localStorage) {
                        if (key === "pk") {
                            console.warn("Skipping import of 'pk' from localStorage to protect existing key.")
                            continue // Move to the next key
                        }
                        localStorage.setItem(key, data.localStorage[key])
                    }
                }

                if (data.indexedDB) {
                    for (const dbName in data.indexedDB) {
                        // Explicitly refuse to import into the RuntimeFS database.
                        if (dbName === DBN) {
                            console.warn(`Skipping import of data for '${DBN}' to protect RuntimeFS folders.`)
                            continue // Go to the next database in the file.
                        }

                        console.log(`Importing data into database: '${dbName}'`)

                        // Open a connection to the target database.
                        const db = await new Promise((resolve, reject) => {
                            const request = indexedDB.open(dbName)
                            request.onsuccess = () => resolve(request.result)
                            request.onerror = () => reject(request.error)
                        })

                        const storeNames = Object.keys(data.indexedDB[dbName])
                        const transaction = db.transaction(storeNames, "readwrite")

                        // Restore each store within this database.
                        for (const storeName of storeNames) {
                            const store = transaction.objectStore(storeName)
                            store.clear() // Clear existing data before importing.
                            const records = data.indexedDB[dbName][storeName]
                            for (const record of records) {
                                // Convert Base64 back to buffer if needed.
                                if (record && typeof record.buffer === "string") {
                                    record.buffer = base64ToBuffer(record.buffer)
                                }
                                store.put(record)
                            }
                        }
                        db.close()
                    }
                }

                alert("General data import successful!")
                await listFolders()
            } catch (error) {
                console.error("Import failed:", error)
                // A common error is a bad password during decryption, which throws a DOMException.
                if (error instanceof DOMException && error.name === "OperationError") {
                    alert("Import failed. The password may be incorrect.")
                } else {
                    alert("An error occurred during import: " + error.message)
                }
            } finally {
                // Always re-enable the UI after the process is finished.
                setUiBusy(false)
            }
        }
        input.click()
    } catch (error) {
        // This outer catch handles errors in creating the input element itself.
        console.error("Failed to initialize import:", error)
    }
}

function createAndDisplayDownloadLink(jsonString, parentElement) {
    // Clean up any old links that might still be there from a previous export.
    const oldLink = document.getElementById("download-link")
    if (oldLink) {
        oldLink.remove()
    }

    // Create a Data URI, which embeds the file content directly in the URL.
    const dataURI = `data:text/plain;charset=utf-8,${encodeURIComponent(jsonString)}`

    const a = document.createElement("a")
    a.id = "download-link" // Give it an ID for easy removal later.
    a.href = dataURI
    a.download = "result.txt" // The default filename for the user.
    a.textContent = "Click here to download export!"

    // Add some basic styling to make it visible and user-friendly.
    a.style.display = "block"
    a.style.marginTop = "10px"
    a.style.padding = "8px"
    a.style.border = "1px solid #15e264"
    a.style.borderRadius = "5px"
    a.style.textAlign = "center"

    // When the user clicks the link, remove it from the page to keep the UI clean.
    a.onclick = () => {
        setTimeout(() => a.remove(), 200) // Small delay to ensure download has time to start.
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
    const passwordInput = document.getElementById("password")
    const name = folderNameInput.value.trim()
    const password = passwordInput.value
    if (!name || !password) {
        alert("Please provide both a folder name and a password.")
        return
    }
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
        const db = await dbPromise
        const transaction = db.transaction([SN], "readwrite")
        const folderStore = transaction.objectStore(SN)
        // Add the 'encryptionType' property to the folder object.
        const folderObject = { id: name, files: files, encryptionType: "pdf" }
        folderStore.put(folderObject)
        await promisifyTransaction(transaction)
        console.log(`Folder "${name}" encrypted and stored successfully.`)
        folderNameInput.value = ""
        passwordInput.value = ""
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
    const password = prompt("Enter a strong password for encryption:")
    if (!password) return

    try {
        setUiBusy(true)
        const sourceDirHandle = await window.showDirectoryPicker({ mode: "read" })
        const destDirHandle = await window.showDirectoryPicker({ mode: "readwrite" })

        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt)
        const fileMap = await scanFilesRecursively(sourceDirHandle)
        const pathManifest = {}

        // Encrypt each file and save it with a UUID name
        for (const originalPath in fileMap) {
            if (fileMap[originalPath] === null) continue // Skip directories
            const uuid = crypto.randomUUID()
            pathManifest[originalPath] = uuid
            const fileBuffer = await fileMap[originalPath].arrayBuffer()

            const iv = crypto.getRandomValues(new Uint8Array(12))
            const encryptedContent = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer)

            // Prepend IV to the encrypted buffer for storage
            const finalBuffer = concatBuffers(iv.buffer, encryptedContent)

            const newFileHandle = await destDirHandle.getFileHandle(uuid, { create: true })
            const writable = await newFileHandle.createWritable()
            await writable.write(finalBuffer)
            await writable.close()
        }

        // Create and encrypt the manifest payload
        const manifestString = JSON.stringify(pathManifest)
        const manifestBuffer = new TextEncoder().encode(manifestString)
        const manifestIv = crypto.getRandomValues(new Uint8Array(12))
        const encryptedManifestPayload = await crypto.subtle.encrypt({ name: "AES-GCM", iv: manifestIv }, key, manifestBuffer)

        // Create the final manifest.enc file content
        const manifestFileObject = {
            encryptionType: "password",
            salt: bufferToBase64(salt),
            iv: bufferToBase64(manifestIv),
            payload: bufferToBase64(new Uint8Array(encryptedManifestPayload))
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
document.getElementById("folderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), uploadFolder()))
document.getElementById("openFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), openFile()))
document.getElementById("fileName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), openFile()))
document.getElementById("deleteFolderName").addEventListener("keydown", e => e.key === "Enter" && (e.preventDefault(), deleteFolder()))