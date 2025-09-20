const DBN = "FileCacheDB"
const SN = "Folders"
const META_SN = "Metadata"
const DB_VERSION = 1 // Increment DB version for schema change

// Helper to simplify IndexedDB requests by converting them to Promises
function promisifyRequest(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error)
    })
}

navigator.storage.persist().then(persistent => {
    if (persistent) {
        console.log("Storage will not be cleared except by explicit user action.")
    } else {
        console.log("Storage may be cleared by the browser.")
    }
})

const dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DBN, DB_VERSION)

    request.onupgradeneeded = function (event) {
        const db = event.target.result
        if (!db.objectStoreNames.contains(SN)) {
            db.createObjectStore(SN, { keyPath: "id" })
        }
        if (!db.objectStoreNames.contains(META_SN)) {
            db.createObjectStore(META_SN, { keyPath: "id" })
        }
    }

    request.onsuccess = function (event) {
        resolve(event.target.result)
    }

    request.onerror = function (event) {
        console.error("Database error: " + event.target.errorCode)
        reject(event.target.errorCode)
    }
})

// Immediately list folders once the DB is ready.
dbPromise.then(() => listFolders())

document.getElementById('generateBtn').addEventListener('click', async () => {
    const keyPair = await generateAndStoreKeyPair()
    await c(keyPair.publicKey)
    alert('Copied!')
})

async function uploadFolder(isSecureUpload) {
    const folderNameInput = document.getElementById("folderName")
    const name = folderNameInput.value.trim()
    if (!name) {
        alert("Please enter a name for the folder.")
        return
    }

    setUiBusy(true) // Lock the UI
    try {
        const dirHandle = await window.showDirectoryPicker({ mode: "read" })
        let files = {}
        if (isSecureUpload) {
            files = await decryptFolder(dirHandle)
        } else {
            files = await getFilesRecursively(dirHandle)
        }

        const db = await dbPromise
        const transaction = db.transaction([SN, META_SN], "readwrite")
        const folderStore = transaction.objectStore(SN)
        const metaStore = transaction.objectStore(META_SN)

        let folderIdToStore = name
        if (isSecureUpload) {
            folderIdToStore = crypto.randomUUID()
            const manifestRecord = await promisifyRequest(metaStore.get('folderManifest')).catch(() => null)
            const manifest = manifestRecord?.data || {}
            manifest[name] = folderIdToStore
            metaStore.put({ id: 'folderManifest', data: manifest })
        }

        folderStore.put({ id: folderIdToStore, files: files })

        await new Promise((resolve, reject) => {
            transaction.oncomplete = resolve
            transaction.onerror = (event) => reject(event.target.error)
        })

        console.log(`Folder "${name}" stored successfully.`)
        folderNameInput.value = ""
        await listFolders() // Refresh the list on success

    } catch (err) {
        if (err.name !== 'AbortError') {
            console.error("Upload error:", err)
            alert("An error occurred during upload: " + err.message)
        }
    } finally {
        setUiBusy(false) // Always unlock the UI
    }
}

async function getFilesRecursively(dirHandle, path = '') {
    const files = {}
    for await (const entry of dirHandle.values()) {
        const newPath = path ? `${path}/${entry.name}` : entry.name
        if (entry.kind === "file") {
            const file = await entry.getFile()
            files[newPath] = {
                buffer: await file.arrayBuffer(),
                type: file.type
            }
        } else if (entry.kind === "directory") {
            Object.assign(files, await getFilesRecursively(entry, newPath))
        }
    }
    return files
}

async function decryptFolder(dirHandle) {
    const decryptedFiles = {}
    const manifestFileHandle = await dirHandle.getFileHandle('manifest.enc')
    const manifestFile = await manifestFileHandle.getFile()
    const encryptedManifestBuffer = await manifestFile.arrayBuffer()
    const decryptedManifestBuffer = await decryptWithPrivateKey(encryptedManifestBuffer)
    const manifest = JSON.parse(new TextDecoder().decode(decryptedManifestBuffer))

    for (const originalPath in manifest) {
        const uuid = manifest[originalPath]
        if (uuid === null) continue

        try {
            const fileHandle = await dirHandle.getFileHandle(uuid)
            const file = await fileHandle.getFile()
            const encryptedBuffer = await file.arrayBuffer()
            const decryptedBuffer = await decryptWithPrivateKey(encryptedBuffer)

            decryptedFiles[originalPath] = {
                buffer: decryptedBuffer,
                type: file.type
            }
        } catch (e) {
            throw new Error(`Failed to find or decrypt file for path: ${originalPath}`)
        }
    }
    return decryptedFiles
}

async function useK() {
    const publicKeyBase64 = document.getElementById('k').value.trim()
    if (!publicKeyBase64) {
        alert("Key is required to encrypt.")
        return
    }

    try {
        const sourceDirHandle = await window.showDirectoryPicker({ mode: "read" })
        const destDirHandle = await window.showDirectoryPicker({ mode: "readwrite" })

        const fileMap = await scanFilesRecursively(sourceDirHandle)
        const pathManifest = {}

        for (const originalPath in fileMap) {
            const file = fileMap[originalPath]
            if (file === null) {
                pathManifest[originalPath] = null
                continue
            }
            // Make a random file UUID; file names are also encrypted
            const uuid = crypto.randomUUID()
            pathManifest[originalPath] = uuid
            const fileBuffer = await file.arrayBuffer()
            const encryptedContent = await encryptWithPublicKey(publicKeyBase64, fileBuffer)
            const newFileHandle = await destDirHandle.getFileHandle(uuid, { create: true })
            const writable = await newFileHandle.createWritable()
            await writable.write(encryptedContent)
            await writable.close()
        }

        const manifestString = JSON.stringify(pathManifest)
        const encryptedManifest = await encryptWithPublicKey(publicKeyBase64, new TextEncoder().encode(manifestString))
        const manifestFileHandle = await destDirHandle.getFileHandle('manifest.enc', { create: true })
        const manifestWritable = await manifestFileHandle.createWritable()
        await manifestWritable.write(encryptedManifest)
        await manifestWritable.close()
        alert(`Encryption complete! Folder saved in "${destDirHandle.name}".`)
    } catch (err) {
        console.error("Error during encryption process:", err)
        if (err.name !== 'AbortError') {
            alert("An error occurred during encryption: " + err.message)
        }
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

function openFile() {
    const folderName = document.getElementById("openFolderName").value.trim()
    const fileName = document.getElementById("fileName").value.trim()
    if (!folderName || !fileName) {
        alert("Please provide both folder and file name.")
        return
    }

    const regexRules = document.getElementById("regex").value
    // Generate a unique ID for this request
    const requestId = crypto.randomUUID()
    let url = `/n/${encodeURIComponent(folderName)}/${encodeURIComponent(fileName)}?reqId=${requestId}`

    // If there are rules, post them to the service worker
    if (regexRules.trim() && navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({
            type: 'REGRULES',
            requestId: requestId,
            rules: regexRules
        })
    }
    
    window.open(url, "_blank")
}

async function listFolders() {
    const db = await dbPromise
    const transaction = db.transaction([SN, META_SN], "readonly")
    const folderStore = transaction.objectStore(SN)
    const metaStore = transaction.objectStore(META_SN)
    const folderList = document.getElementById("folderList")
    folderList.innerHTML = "" // Clear the list before repopulating

    try {
        const allFolderKeys = await promisifyRequest(folderStore.getAllKeys())
        const manifestRecord = await promisifyRequest(metaStore.get('folderManifest'))
        const manifest = manifestRecord?.data || {}

        // Get the definitive list of secure folder names and their corresponding IDs
        const secureFolderNames = Object.keys(manifest)
        const secureFolderIds = new Set(Object.values(manifest))

        // Non-secure folders are any keys in the folder store that are NOT a secure ID
        const nonSecureFolderNames = allFolderKeys.filter(key => !secureFolderIds.has(key))

        // Combine both lists and remove any potential duplicates
        const allDisplayNames = Array.from(new Set([...secureFolderNames, ...nonSecureFolderNames]))

        allDisplayNames.sort().forEach(name => {
            const li = document.createElement("li")
            li.textContent = name
            folderList.appendChild(li)
        })
    } catch (error) {
        console.error("Error listing folders:", error)
    }
}

function setUiBusy(isBusy) {
    // Find all buttons that perform major actions
    const buttons = document.querySelectorAll('button[onclick*="uploadFolder"], button[onclick*="deleteFolder"], button[onclick*="useK"]')
    buttons.forEach(button => {
        button.disabled = isBusy
    })
}

async function deleteFolder() {
    const folderName = document.getElementById("deleteFolderName").value.trim()
    if (!folderName) {
        alert("Please enter the name of the folder to delete.")
        return
    }

    setUiBusy(true) // Lock the UI
    try {
        const db = await dbPromise
        const transaction = db.transaction([SN, META_SN], "readwrite")
        const folderStore = transaction.objectStore(SN)
        const metaStore = transaction.objectStore(META_SN)
        const manifestRecord = await promisifyRequest(metaStore.get('folderManifest')).catch(() => null)
        const manifest = manifestRecord?.data || {}
        const folderId = manifest[folderName]

        if (folderId) {
            delete manifest[folderName]
            metaStore.put({ id: 'folderManifest', data: manifest })
            folderStore.delete(folderId)
        } else {
            folderStore.delete(folderName)
        }

        await new Promise((resolve, reject) => {
            transaction.oncomplete = resolve
            transaction.onerror = reject
        })

        console.log(`Folder "${folderName}" deleted successfully.`)
        document.getElementById("deleteFolderName").value = ""
        listFolders() // Refresh the list on success
    } catch (error) {
        console.error("Transaction error:", error)
        alert("An error occurred during deletion: " + error.message)
    } finally {
        setUiBusy(false) // Always unlock the UI
    }
}

async function generateAndStoreKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"])
    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey)
    localStorage.setItem("pk", JSON.stringify(privateKeyJwk))
    return keyPair
}

async function c(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey)
    const buffer = new Uint8Array(exported)
    const base64PublicKey = btoa(String.fromCharCode(...buffer))
    navigator.clipboard.writeText(base64PublicKey)
}

function concatBuffers(buffer1, buffer2) {
    const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength)
    tmp.set(new Uint8Array(buffer1), 0)
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength)
    return tmp.buffer
}

// Use encryption algorithms to encrypt/decrype
async function encryptWithPublicKey(publicKeyBase64, plainBuffer) {
    const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const encryptedFileBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, plainBuffer)
    const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey)
    const keyData = atob(publicKeyBase64)
    const keyBuffer = new Uint8Array(keyData.length)
    for (let i = 0; i < keyData.length; i++) keyBuffer[i] = keyData.charCodeAt(i)
    const importedRsaKey = await window.crypto.subtle.importKey("spki", keyBuffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"])
    const encryptedAesKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedRsaKey, exportedAesKey)
    const combinedBuffer = concatBuffers(encryptedAesKey, iv.buffer)
    return concatBuffers(combinedBuffer, encryptedFileBuffer)
}

async function decryptWithPrivateKey(encryptedBuffer) {
    const encryptedAesKey = encryptedBuffer.slice(0, 256)
    const iv = encryptedBuffer.slice(256, 256 + 12)
    const encryptedFileBuffer = encryptedBuffer.slice(256 + 12)
    const privateKeyJwkString = localStorage.getItem("pk")
    if (!privateKeyJwkString) throw new Error("Private key not found.")
    const privateKeyJwk = JSON.parse(privateKeyJwkString)
    const importedRsaKey = await window.crypto.subtle.importKey("jwk", privateKeyJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"])
    const decryptedAesKeyBuffer = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, importedRsaKey, encryptedAesKey)
    const aesKey = await window.crypto.subtle.importKey("raw", decryptedAesKeyBuffer, { name: "AES-GCM" }, true, ["decrypt"])
    return await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, encryptedFileBuffer)
}

if ('serviceWorker' in navigator) {
    let refreshing
    navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (refreshing) return
        refreshing = true
        window.location.reload()
    })
    navigator.serviceWorker.register('/sw.js').then(reg => {
        reg.addEventListener('updatefound', () => {
            const newWorker = reg.installing
            newWorker.addEventListener('statechange', () => {
                console.log('A new service worker is installing.', newWorker.state)
            })
        })
        console.log('Service worker registered.', reg)
    }).catch(err => console.log('Service worker not registered.', err))
}