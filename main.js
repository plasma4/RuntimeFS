const RFS_PREFIX = "rfs"
const SYSTEM_FILE = "rfs_system.json"
const CHUNK_SIZE = 1024 * 1024 * 4

let isListingFolders = false
let currentlyBusy = false
let folderName, dirHandle, observer
let changes = []

let _opfsRoot = null
async function getOpfsRoot() {
    if (!_opfsRoot) _opfsRoot = await navigator.storage.getDirectory()
    return _opfsRoot
}

function setUiBusy(isBusy) {
    currentlyBusy = isBusy
    Array.from(document.getElementsByTagName("button")).forEach(button => button.disabled = currentlyBusy)
}

navigator.storage.persist().then(p => console.log(p ? "Storage persisted." : "Storage not persisted."))

async function waitForController() {
    if (navigator.serviceWorker.controller) return navigator.serviceWorker.controller
    await navigator.serviceWorker.register("./sw.js")
    const reg = await navigator.serviceWorker.ready
    return navigator.serviceWorker.controller || reg.active
}

async function getRegistry() {
    try {
        const root = await getOpfsRoot()
        const handle = await root.getFileHandle(SYSTEM_FILE)
        const file = await handle.getFile()
        return JSON.parse(await file.text())
    } catch (e) {
        return {} // Default empty registry
    }
}

async function saveRegistry(registry) {
    const root = await getOpfsRoot()
    const handle = await root.getFileHandle(SYSTEM_FILE, { create: true })
    const writable = await handle.createWritable()
    await writable.write(JSON.stringify(registry))
    await writable.close()
}

async function updateRegistryEntry(name, data) {
    const reg = await getRegistry()
    if (data === null) {
        delete reg[name]
    } else {
        reg[name] = { ...reg[name], ...data, lastModified: Date.now() }
    }
    await saveRegistry(reg)
    // Notify SW to invalidate its memory cache
    if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: "INVALIDATE_CACHE", folderName: name })
    }
}

async function uploadFolder() {
    const folderNameInput = document.getElementById("folderName")
    const name = folderNameInput.value.trim()
    if (!name) return alert("Please enter a name.")

    setUiBusy(true)
    try {
        if (window.showDirectoryPicker) {
            const localDirHandle = await window.showDirectoryPicker({ mode: "read" })
            await processFolderSelection(name, localDirHandle)
        } else {
            document.getElementById("folderUploadFallbackInput").click()
        }
    } catch (e) {
        if (e.name !== "AbortError") alert("Upload error: " + e.message)
    } finally {
        setUiBusy(false)
    }
}

async function processFolderSelection(name, handle) {
    dirHandle = handle
    folderName = name

    try {
        const encManifest = await handle.getFileHandle("manifest.enc")
        console.log("Encrypted folder detected.")
        const root = await getOpfsRoot()
        const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true })
        try { await rfs.removeEntry(name, { recursive: true }) } catch (e) { }

        await decryptAndLoadFolderToOpfs(handle, encManifest, await rfs.getDirectoryHandle(name, { create: true }))
        await updateRegistryEntry(name, { encryptionType: null })
    } catch (e) {
        await processAndStoreFolderStreaming(name, handle)
    }

    if (observer) {
        try { observer.disconnect() } catch (e) { }
        observer = null
    }

    if ("FileSystemObserver" in window) {
        try {
            observer = new FileSystemObserver(recs => changes.push(...recs))
            observer.observe(dirHandle, { recursive: true })
        } catch (e) { console.warn("Observer failed:", e) }
    }

    changes.length = 0

    document.getElementById("folderName").value = ""
    document.getElementById("openFolderName").value = name
    await listFolders()
}

async function decryptAndLoadFolderToOpfs(srcHandle, manifestHandle, destDir) {
    const password = prompt("Enter password to decrypt this folder:")
    if (!password) throw new Error("Password required for decryption.")

    const manifestFile = await manifestHandle.getFile()
    const saltBase64 = await manifestFile.text()

    // Check if valid base64, otherwise might be json
    let salt
    try {
        salt = base64ToBuffer(saltBase64.trim())
    } catch (e) {
        throw new Error("Invalid manifest format")
    }

    const key = await deriveKeyFromPassword(password, salt)
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)

    async function process(src, dst) {
        for await (const entry of src.values()) {
            if (entry.name === "manifest.enc") continue // Skip manifest

            if (entry.kind === "file") {
                updateProgress(`Decrypting: ${entry.name}`)
                const file = await entry.getFile()
                const data = await file.arrayBuffer()

                // Extract IV (first 12 bytes) and Content
                const iv = data.slice(0, 12)
                const ciphertext = data.slice(12)

                try {
                    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)
                    const fh = await dst.getFileHandle(entry.name, { create: true })
                    const w = await fh.createWritable()
                    await w.write(decrypted)
                    await w.close()
                } catch (e) {
                    console.error(`Failed to decrypt ${entry.name}`, e)
                }
            } else if (entry.kind === "directory") {
                const newDst = await dst.getDirectoryHandle(entry.name, { create: true })
                await process(entry, newDst)
            }
        }
    }

    await process(srcHandle, destDir)
    progressElem.textContent = ""
}

async function processFileListAndStore(name, fileList) {
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)

    try {
        if (!fileList.length) return
        const root = await getOpfsRoot()
        const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true })

        try {
            await rfsRoot.removeEntry(name, { recursive: true })
            // Yield to ensure the handle deletion propagates
            await new Promise(r => setTimeout(r, 50))
        } catch (e) {
            if (e.name !== "NotFoundError") console.warn("RemoveEntry warning:", e)
        }

        const folderHandle = await rfsRoot.getDirectoryHandle(name, { create: true })

        let basePath = ""
        if (fileList.length > 0 && fileList[0].webkitRelativePath && fileList[0].webkitRelativePath.includes("/")) {
            basePath = fileList[0].webkitRelativePath.split("/")[0] + "/"
        }

        let lastYieldTime = Date.now()

        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i]
            let path = file.webkitRelativePath || file.name
            if (basePath && path.startsWith(basePath)) path = path.substring(basePath.length)
            if (!path) continue

            updateProgress(`Processing ${path}`)

            if (Date.now() - lastYieldTime > 100) {
                await new Promise(r => setTimeout(r, 0))
                lastYieldTime = Date.now()
            }

            await writeStreamToOpfs(folderHandle, path, file.stream())
        }

        await updateRegistryEntry(name, { encryptionType: null })

        document.getElementById("folderName").value = ""
        document.getElementById("openFolderName").value = name
        await listFolders()
    } catch (e) {
        console.error(e)
        alert("Error: " + e.message)
    } finally {
        progressElem.textContent = ""
    }
}

async function processAndStoreFolderStreaming(name, srcHandle) {
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)

    const root = await getOpfsRoot()
    const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true })
    try { await rfs.removeEntry(name, { recursive: true }) } catch (e) { }
    const destRoot = await rfs.getDirectoryHandle(name, { create: true })

    updateProgress("Scanning files...")
    const files = [] // { entry, pathParts }
    const dirs = [] // pathParts (array of strings)

    async function scan(dir, pathParts) {
        for await (const entry of dir.values()) {
            if (entry.kind === "file") {
                files.push({ entry, pathParts })
            } else if (entry.kind === "directory") {
                const newPath = [...pathParts, entry.name]
                dirs.push(newPath)
                await scan(entry, newPath)
            }
        }
    }
    await scan(srcHandle, [])

    updateProgress(`Creating ${dirs.length} folders...`)
    for (const parts of dirs) {
        let curr = destRoot
        for (const p of parts) curr = await curr.getDirectoryHandle(p, { create: true })
    }

    updateProgress(`Uploading ${files.length} files...`)
    let completed = 0
    const total = files.length

    // The worker function picks the next file from the index
    let fileIdx = 0
    async function worker() {
        while (fileIdx < total) {
            const i = fileIdx++
            const { entry, pathParts } = files[i]

            // Navigate to folder (should exist now)
            let dir = destRoot
            for (const p of pathParts) dir = await dir.getDirectoryHandle(p)

            const file = await entry.getFile()
            const dstFile = await dir.getFileHandle(entry.name, { create: true })
            const w = await dstFile.createWritable()
            await file.stream().pipeTo(w)

            if (++completed % 10 === 0) updateProgress(`Uploading: ${Math.round((completed / total) * 100)}%`)
        }
    }

    // Run 6 concurrent workers
    await Promise.all(Array(6).fill(null).map(worker))

    await updateRegistryEntry(name, { encryptionType: null })
    progressElem.textContent = ""

    // UI Cleanup
    document.getElementById("folderName").value = ""
    document.getElementById("openFolderName").value = name
    await listFolders()
}

async function writeStreamToOpfs(parentHandle, path, stream) {
    const parts = path.split("/")
    const fileName = parts.pop()

    try {
        let currentDir = parentHandle
        // Traverse/Create subdirectories
        for (const part of parts) {
            currentDir = await currentDir.getDirectoryHandle(part, { create: true })
        }

        const fileHandle = await currentDir.getFileHandle(fileName, { create: true })
        const writable = await fileHandle.createWritable()
        await stream.pipeTo(writable)
    } catch (e) {
        // Retry once for InvalidStateError (Stale handle)
        if (e.name === "InvalidStateError") {
            console.warn("Retrying write due to stale handle:", path)
            await new Promise(r => setTimeout(r, 50)) // Wait for state to settle

            // Re-traverse from parent
            let retryDir = parentHandle
            for (const part of parts) {
                retryDir = await retryDir.getDirectoryHandle(part, { create: true })
            }
            const retryFile = await retryDir.getFileHandle(fileName, { create: true })
            const retryWritable = await retryFile.createWritable()
            await stream.pipeTo(retryWritable)
            return
        }
        throw e
    }
}

async function listFolders() {
    if (isListingFolders) return
    isListingFolders = true
    const folderList = document.getElementById("folderList")

    try {
        const registry = await getRegistry()
        folderList.textContent = ""
        const fragment = document.createDocumentFragment()

        const names = Object.keys(registry).sort()
        names.forEach(name => {
            const meta = registry[name]
            const li = document.createElement("li")
            li.textContent = meta.encryptionType === "password" ? `[Locked] ${name}` : name
            fragment.appendChild(li)
        })
        folderList.appendChild(fragment)
    } catch (e) {
        console.error("List failed:", e)
    } finally {
        isListingFolders = false
    }
}

async function deleteFolder(folderNameToDelete, skipConfirm = false) {
    const folderName = folderNameToDelete || document.getElementById("deleteFolderName").value.trim()
    if (!folderName) return alert("Enter folder name!")
    if (!skipConfirm && !confirm(`Remove "${folderName}"?`)) return

    const progressElem = document.getElementById("progress")
    progressElem.textContent = "Deleting..."
    setUiBusy(true)
    try {
        const root = await getOpfsRoot()
        try {
            const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX)
            await rfsRoot.removeEntry(folderName, { recursive: true })
        } catch (e) { }

        await updateRegistryEntry(folderName, null)
        if (!folderNameToDelete) document.getElementById("deleteFolderName").value = ""
        await listFolders()
    } catch (e) {
        alert("Delete failed: " + e.message)
    } finally {
        progressElem.textContent = ""
        if (!skipConfirm) setUiBusy(false)
    }
}

async function openFile(overrideFolderName) {
    const folderName = overrideFolderName || document.getElementById("openFolderName").value.trim()
    const fileName = document.getElementById("fileName").value.trim()
    if (!folderName) return alert("Provide a folder name.")

    setUiBusy(true)
    try {
        const registry = await getRegistry()
        const meta = registry[folderName]
        if (!meta) return alert("Folder not found.")

        const rules = document.getElementById("regex").value.trim()
        const headers = document.getElementById("headers").value.trim()

        if (meta.rules !== rules || meta.headers !== headers) {
            await updateRegistryEntry(folderName, { rules, headers })
        }

        let key = null
        if (meta.encryptionType === "password") {
            const password = prompt(`Enter password for "${folderName}":`)
            if (!password) return setUiBusy(false)
            key = await deriveKeyFromPassword(password, base64ToBuffer(meta.salt))
        }

        const sw = await waitForController()

        await new Promise(resolve => {
            const channel = new MessageChannel()
            channel.port1.onmessage = () => resolve()

            sw.postMessage({
                type: "SET_RULES",
                rules,
                headers,
                key
            }, [channel.port2])
        })

        window.open(`n/${encodeURIComponent(folderName)}/${fileName.split("/").map(encodeURIComponent).join("/")}`, "_blank")

    } catch (e) {
        alert("Error: " + e)
    } finally {
        setUiBusy(false)
    }
}

async function createDownloadStream(filename) {
    if (window.showSaveFilePicker) {
        try {
            const handle = await window.showSaveFilePicker({ suggestedName: filename })
            return await handle.createWritable()
        } catch (err) {
            if (err.name === "AbortError") return
            console.warn("Native File System API failed, falling back to memory buffer:", err)
        }
    }

    const chunks = []
    let totalSize = 0
    return new WritableStream({
        write(chunk) {
            // chunk is usually Uint8Array, String, or Blob
            chunks.push(chunk)

            // Optional: Track size for debugging or limits
            if (chunk.byteLength) totalSize += chunk.byteLength
        },
        close() {
            if (chunks.length === 0) return

            // Combine all chunks into a single Blob
            const blob = new Blob(chunks, { type: "application/octet-stream" })
            const url = URL.createObjectURL(blob)

            // Create invisible link and trigger download
            const a = document.createElement("a")
            a.style.display = "none"
            a.href = url
            a.download = filename

            document.body.appendChild(a)
            a.click()

            // Cleanup
            // We use a small timeout to ensure the download starts before revoking
            setTimeout(() => {
                document.body.removeChild(a)
                window.URL.revokeObjectURL(url)
                chunks.length = 0 // Free memory explicitly
            }, 500)
        },
        abort(reason) {
            console.error("Stream download aborted:", reason)
            chunks.length = 0
        }
    })
}

async function exportData() {
    if (!window.CBOR) return alert("cbor-x is missing!")

    let key, salt
    let encrypt = true
    const pass = prompt("Enter a password (or leave blank for no encryption):").trim()
    if (pass.length === 0) encrypt = false

    salt = crypto.getRandomValues(new Uint8Array(16))
    key = await deriveKeyFromPassword(pass, salt)

    setUiBusy(true)
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)

    try {
        const fileWritable = await createDownloadStream(encrypt ? "result.enc" : "result.tar.gz")
        let outputStream

        if (encrypt) {
            const fileWriter = fileWritable.getWriter()

            // Write Header
            await fileWriter.write(new TextEncoder().encode("RFS_ENC\0"))
            await fileWriter.write(salt)
            outputStream = new ChunkedEncryptionStream(fileWriter, key)
        } else {
            outputStream = fileWritable
        }

        const gzip = new CompressionStream("gzip")
        const gzipPromise = gzip.readable.pipeTo(outputStream)
        const tarWriter = gzip.writable.getWriter()
        const write = async (d) => await tarWriter.write(d)

        const writeTarEntry = async (name, dataBytes) => {
            await write(createTarHeader(name, dataBytes.byteLength))
            await write(dataBytes)
            const remainder = dataBytes.byteLength % 512
            if (remainder > 0) await write(new Uint8Array(512 - remainder))
        }

        const writeTarStream = async (name, size, readableStream) => {
            await write(createTarHeader(name, size))
            let bytesWritten = 0
            const reader = readableStream.getReader()
            while (true) {
                const { done, value } = await reader.read()
                if (done) break
                await write(value)
                bytesWritten += value.byteLength
            }
            const remainder = bytesWritten % 512
            if (remainder > 0) await write(new Uint8Array(512 - remainder))
        }

        updateProgress("Exporting Metadata...")

        const metadata = {
            ls: document.getElementById("c2").checked ? { ...localStorage } : {},
            ss: document.getElementById("c7").checked ? getSessionStorageExport() : {},
            cookies: typeof getCookiesAsObject === "function" && document.getElementById("c1").checked ? getCookiesAsObject() : {},
            reg: document.getElementById("c4").checked ? await getRegistry() : {},
        }

        await writeTarEntry("runtimefs_system/metadata.json", new TextEncoder().encode(JSON.stringify(metadata, null, 2)))
        if (document.getElementById("c3").checked) await streamIndexedDBToWriter(updateProgress, writeTarEntry)
        if (document.getElementById("c6").checked) await streamCacheStorageToWriter(updateProgress, writeTarEntry)
        if (document.getElementById("c5").checked) {
            const root = await getOpfsRoot()
            const processDir = async (handle, prefix) => {
                for await (const entry of handle.values()) {
                    if (entry.name === SYSTEM_FILE) continue
                    const path = prefix ? `${prefix}/${entry.name}` : entry.name
                    if (entry.kind === "file") {
                        updateProgress(path)
                        const file = await entry.getFile()
                        await writeTarStream(path, file.size, file.stream())
                    } else {
                        await processDir(entry, path)
                    }
                }
            }
            await processDir(root, "")
        }

        await write(new Uint8Array(1024)) // Write Tar Footer
        await tarWriter.close() // Close GZIP input
        await gzipPromise // Wait for GZIP -> Output pipe to finish

    } catch (e) {
        console.error(e)
        alert("Export error: " + e.message)
    } finally {
        setUiBusy(false)
        progressElem.textContent = ""
    }
}

async function streamIndexedDBToWriter(updateProgress, writeFunc) {
    if (!window.indexedDB || !indexedDB.databases) return
    const dbs = await indexedDB.databases()

    // Helper to process Blobs for CBOR
    const prepareForCbor = async (item) => {
        if (item instanceof Blob) {
            return { __rfs_blob: true, type: item.type, data: new Uint8Array(await item.arrayBuffer()) }
        }
        if (ArrayBuffer.isView(item) || item instanceof ArrayBuffer) return item
        if (Array.isArray(item)) return Promise.all(item.map(prepareForCbor))
        if (item && typeof item === "object" && item.constructor === Object) {
            const newItem = {}
            for (const k in item) newItem[k] = await prepareForCbor(item[k])
            return newItem
        }
        return item
    }

    for (const { name: dbName } of dbs) {
        if (!dbName) continue
        if (dbName === "FileCacheDB") continue // Skip internal browser DBs
        updateProgress(`Exporting DB: ${dbName}`)

        try {
            const db = await new Promise((res, rej) => {
                const r = indexedDB.open(dbName)
                r.onsuccess = () => res(r.result)
                r.onerror = () => rej(r.error)
            })

            const storeNames = Array.from(db.objectStoreNames)

            const schema = {
                dbName,
                version: db.version,
                stores: storeNames.map(name => {
                    const store = db.transaction(name).objectStore(name)
                    const indexes = Array.from(store.indexNames).map(idxName => {
                        const idx = store.index(idxName)
                        return { name: idx.name, keyPath: idx.keyPath, unique: idx.unique, multiEntry: idx.multiEntry }
                    })
                    return { name, keyPath: store.keyPath, autoIncrement: store.autoIncrement, indexes }
                })
            }
            await writeFunc(`__IDB_SCHEMA__/${dbName}`, CBOR.encode(schema))

            // Actually export with snapshots!
            for (const storeName of storeNames) {
                let lastKey = null
                let hasMore = true
                let chunkId = 0

                while (hasMore) {
                    // Open a short-lived transaction just to grab a batch
                    const { batch, nextKey, completed } = await new Promise((resolve, reject) => {
                        const tx = db.transaction(storeName, "readonly")
                        const store = tx.objectStore(storeName)
                        // Resume from lastKey if we have one
                        const range = lastKey !== null ? IDBKeyRange.lowerBound(lastKey, true) : null
                        const req = store.openCursor(range)

                        const currentBatch = []

                        req.onsuccess = (e) => {
                            const cursor = e.target.result
                            if (cursor) {
                                currentBatch.push({ k: cursor.key, v: cursor.value })
                                // Limit batch to 200 items to prevent memory issues
                                if (currentBatch.length >= 200) {
                                    resolve({ batch: currentBatch, nextKey: cursor.key, completed: false })
                                    return
                                }
                                cursor.continue()
                            } else {
                                // End of store
                                resolve({ batch: currentBatch, nextKey: null, completed: true })
                            }
                        }
                        req.onerror = () => reject(req.error)
                    })

                    // Process and write the batch asynchronously
                    // The transaction is already closed here, so awaiting is safe.
                    if (batch.length > 0) {
                        const processedBatch = await Promise.all(batch.map(async (r) => {
                            return { k: r.k, v: await prepareForCbor(r.v) }
                        }))

                        const chunkData = CBOR.encode({ db: dbName, st: storeName, d: processedBatch })
                        // Virtual filename: __IDB_DATA__/dbName/storeName/chunkId
                        await writeFunc(`__IDB_DATA__/${dbName}/${storeName}/${chunkId++}`, chunkData)
                    }

                    lastKey = nextKey
                    hasMore = !completed
                }
            }
            db.close()

        } catch (e) {
            console.warn(`Failed to export DB ${dbName}`, e)
        }
    }
}

function getCookiesAsObject() {
    return document.cookie.split(";").reduce((res, c) => {
        const [key, val] = c.trim().split("=").map(decodeURIComponent)
        if (key) res[key] = val
        return res
    }, {})
}

function restoreCookies(cookieObj) {
    if (!cookieObj) return
    const expires = new Date(Date.now() + 86400 * 365 * 1000).toUTCString()
    for (const [key, value] of Object.entries(cookieObj)) {
        document.cookie = `${key}=${value}; expires=${expires}; path=/; SameSite=Lax`
    }
}

async function importData() {
    const input = document.createElement("input")
    input.type = "file"
    input.addEventListener("cancel", () => setUiBusy(false))
    input.addEventListener("change", e => { if (e.target.files[0]) startImport(e.target.files[0]) })
    setUiBusy(true)
    input.click()
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

async function prepareForCbor(item) {
    if (item instanceof Blob) {
        return {
            __rfs_blob: true,
            type: item.type,
            data: normalizeToArrayBuffers(new Uint8Array(await item.arrayBuffer())) // memory stuff
        }
    }
    // Deep normalization for existing arrays/views
    return normalizeToArrayBuffers(item)
}

function getSessionStorageExport() {
    return { ...sessionStorage }
}

function restoreSessionStorage(data) {
    if (!data) return
    sessionStorage.clear()
    for (const [k, v] of Object.entries(data)) {
        sessionStorage.setItem(k, v)
    }
}

// CACHE STORAGE (Async & Heavy)
async function streamCacheStorageToWriter(updateProgress, writeFunc) {
    if (!window.caches) return
    const keys = await caches.keys()

    for (const cacheName of keys) {
        if (cacheName === "fc") continue // Don't export the app itself

        updateProgress(`Exporting Cache: ${cacheName}`)
        const cache = await caches.open(cacheName)
        const requests = await cache.keys()

        for (const req of requests) {
            const res = await cache.match(req)
            if (!res) continue

            const blob = await res.blob()
            const headers = {}
            res.headers.forEach((v, k) => headers[k] = v)

            const meta = {
                url: req.url,
                status: res.status,
                statusText: res.statusText,
                headers: headers,
                type: blob.type
            }

            // Use CBOR to pack metadata + binary body
            const safeName = encodeURIComponent(cacheName)
            const safeUrlHash = btoa(req.url).slice(0, 50).replace(/\//g, "_")

            const entryData = CBOR.encode({
                meta,
                data: normalizeToArrayBuffers(new Uint8Array(await blob.arrayBuffer()))
            })

            await writeFunc(`__CACHE__/${safeName}/${safeUrlHash}`, entryData)
        }
    }
}

async function restoreCacheStorage(cacheName, cborData) {
    const { meta, data } = cborData
    const cache = await caches.open(decodeURIComponent(cacheName))

    const init = {
        status: meta.status,
        statusText: meta.statusText,
        headers: meta.headers
    }

    const blob = new Blob([data], { type: meta.type })
    await cache.put(meta.url, new Response(blob, init))
}

async function startImport(file) {
    if (!window.CBOR) return alert("cbor-x is missing!")
    setUiBusy(true)
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)
    if (navigator.serviceWorker.controller) navigator.serviceWorker.controller.postMessage({ type: "PREPARE_FOR_IMPORT" })

    const restoreFromCbor = (item) => {
        if (!item || typeof item !== "object") return item
        if (item.__rfs_blob && item.data) return new Blob([item.data], { type: item.type })
        if (ArrayBuffer.isView(item) || item instanceof ArrayBuffer) return item
        if (Array.isArray(item)) return item.map(restoreFromCbor)
        if (item.constructor === Object) {
            const newItem = {}
            for (const k in item) newItem[k] = restoreFromCbor(item[k])
            return newItem
        }
        return item
    }

    try {
        // Read header signature
        const headerBuffer = await file.slice(0, 8).arrayBuffer()
        const headerBytes = new Uint8Array(headerBuffer)

        const isEncrypted = headerBytes[0] === 0x52 && headerBytes[1] === 0x46 &&
            headerBytes[2] === 0x53 && headerBytes[3] === 0x5F

        let inputStream

        if (isEncrypted) {
            const pass = prompt("This backup is encrypted. Enter password:")
            if (!pass) throw new Error("Password required")

            const salt = await file.slice(8, 24).arrayBuffer()
            const key = await deriveKeyFromPassword(pass, salt)

            const rawReader = file.slice(24).stream().getReader()
            let leftover = new Uint8Array(0)

            const readExact = async (n) => {
                while (leftover.length < n) {
                    const { done, value } = await rawReader.read()
                    if (done) return null
                    const t = new Uint8Array(leftover.length + value.length)
                    t.set(leftover)
                    t.set(value, leftover.length)
                    leftover = t
                }
                const res = leftover.slice(0, n)
                leftover = leftover.slice(n)
                return res
            }

            const decryptStream = new ReadableStream({
                async pull(controller) {
                    try {
                        const header = await readExact(16)
                        if (!header) return controller.close()
                        const iv = header.slice(0, 12)
                        const len = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(12, true)
                        const cipher = await readExact(len)
                        if (!cipher) return controller.error("Unexpected EOF")

                        try {
                            const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
                            controller.enqueue(new Uint8Array(plain))
                        } catch (e) {
                            controller.error("Decryption failed (wrong password?)")
                        }
                    } catch (e) { controller.error(e) }
                }
            })

            inputStream = decryptStream.pipeThrough(new DecompressionStream("gzip"))

        } else if (headerBytes[0] === 0x1F && headerBytes[1] === 0x8B) {
            inputStream = file.stream().pipeThrough(new DecompressionStream("gzip"))
        } else {
            inputStream = file.stream()
        }

        const reader = inputStream.getReader()
        let buffer = new Uint8Array(0)

        // Helper: Ensure buffer has at least N bytes
        async function ensureBuffer(n) {
            while (buffer.length < n) {
                const { done, value } = await reader.read()
                if (done) return false
                // Optimization: Don't just concat, check if we can avoid alloc
                const t = new Uint8Array(buffer.length + value.length)
                t.set(buffer)
                t.set(value, buffer.length)
                buffer = t
            }
            return true
        }

        // Helper: consume N bytes from front of buffer
        function consume(n) {
            const res = buffer.slice(0, n)
            buffer = buffer.slice(n)
            return res
        }

        const root = await getOpfsRoot()
        const dbCache = {}

        updateProgress("Reading Archive...")

        while (true) {
            if (!(await ensureBuffer(512))) break // End of stream or partial block

            const headerBlock = consume(512)
            const header = parseTarHeader(headerBlock)

            // If invalid header (or zero block), stop
            if (!header) break

            const size = header.size
            const padding = (512 - (size % 512)) % 512

            let path = header.name
            if (path.startsWith("./")) path = path.slice(2)
            while (path.startsWith("/")) path = path.slice(1)

            const isSystemFile = path === "runtimefs_system/metadata.json" ||
                path.startsWith("__CACHE__/") ||
                path.startsWith("__IDB_SCHEMA__/") ||
                path.startsWith("__IDB_DATA__/")

            if (isSystemFile) {
                // For system files, we MUST read into memory to parse
                if (!(await ensureBuffer(size))) throw new Error("Unexpected EOF in system file")
                const chunkData = consume(size)

                if (path === "runtimefs_system/metadata.json") {
                    try {
                        const metadata = JSON.parse(new TextDecoder().decode(chunkData))
                        if (metadata.ls) Object.assign(localStorage, metadata.ls)
                        if (metadata.ss) restoreSessionStorage(metadata.ss)
                        if (metadata.cookies) restoreCookies(metadata.cookies)
                        if (metadata.reg) await saveRegistry(metadata.reg)
                    } catch (e) { console.warn("Metadata corruption!", e) }
                }
                else if (path.startsWith("__CACHE__/")) {
                    const parts = path.split("/")
                    if (parts.length >= 3) {
                        const cacheName = parts[1]
                        const cbor = CBOR.decode(chunkData)
                        updateProgress(`Restoring Cache: ${decodeURIComponent(cacheName)}`)
                        await restoreCacheStorage(cacheName, cbor)
                    }
                }
                else if (path.startsWith("__IDB_SCHEMA__/")) {
                    const schema = CBOR.decode(chunkData)
                    updateProgress(`Restoring Schema: ${schema.dbName}`)
                    try {
                        await new Promise(r => { const q = indexedDB.deleteDatabase(schema.dbName); q.onsuccess = r; q.onerror = r })
                        await new Promise((resolve, reject) => {
                            const openReq = indexedDB.open(schema.dbName, schema.version)
                            openReq.onupgradeneeded = (e) => {
                                const db = e.target.result
                                for (const s of schema.stores) {
                                    if (!db.objectStoreNames.contains(s.name)) {
                                        const store = db.createObjectStore(s.name, { keyPath: s.keyPath, autoIncrement: s.autoIncrement })
                                        s.indexes.forEach(idx => store.createIndex(idx.name, idx.keyPath, { unique: idx.unique, multiEntry: idx.multiEntry }))
                                    }
                                }
                            }
                            openReq.onsuccess = (e) => { e.target.result.close(); resolve() }
                            openReq.onerror = reject
                        })
                    } catch (e) { console.warn("Schema restore failed", e) }
                }
                else if (path.startsWith("__IDB_DATA__/")) {
                    const dataObj = restoreFromCbor(CBOR.decode(chunkData))
                    const { db: dbName, st: storeName, d: records } = dataObj
                    try {
                        if (!dbCache[dbName]) {
                            dbCache[dbName] = await new Promise((res, rej) => {
                                const r = indexedDB.open(dbName)
                                r.onsuccess = () => res(r.result); r.onerror = rej
                            })
                        }
                        const db = dbCache[dbName]
                        const tx = db.transaction(storeName, "readwrite")
                        const store = tx.objectStore(storeName)
                        await Promise.all(records.map(r => {
                            return new Promise((res) => {
                                try {
                                    const req = store.put(r.v, store.keyPath ? undefined : r.k)
                                    req.onsuccess = res; req.onerror = res
                                } catch (e) { res() }
                            })
                        }))
                    } catch (e) { console.warn("IDB Data write failed", e) }
                }

            } else if (header.type === "0" || header.type === "\0") {
                // Standard File: Stream DIRECTLY to OPFS
                updateProgress(path)
                const parts = path.split("/").map(p => p.trim()).filter(p => p && p !== "." && p !== "..")

                if (parts.length > 0) {
                    const name = parts.pop()
                    try {
                        let dir = root
                        for (const p of parts) dir = await dir.getDirectoryHandle(p, { create: true })
                        const fh = await dir.getFileHandle(name, { create: true })
                        const writable = await fh.createWritable()

                        let remaining = size

                        // Flush existing buffer
                        if (buffer.length > 0) {
                            const toWrite = Math.min(buffer.length, remaining)
                            await writable.write(buffer.slice(0, toWrite))
                            buffer = buffer.slice(toWrite)
                            remaining -= toWrite
                        }

                        // Pipe directly from reader if more needed
                        while (remaining > 0) {
                            const { done, value } = await reader.read()
                            if (done) throw new Error("Unexpected EOF writing file")

                            if (value.byteLength <= remaining) {
                                await writable.write(value)
                                remaining -= value.byteLength
                            } else {
                                // Chunk is larger than file remaining; split it
                                await writable.write(value.slice(0, remaining))
                                // Put remainder back into buffer
                                buffer = value.slice(remaining)
                                remaining = 0
                            }
                        }
                        await writable.close()
                    } catch (e) { console.error(`Failed to write ${path}`, e) }
                } else {
                    // Consuming without writing (unknown file)
                    let remaining = size
                    while (remaining > 0) {
                        if (buffer.length > 0) {
                            const take = Math.min(buffer.length, remaining)
                            buffer = buffer.slice(take)
                            remaining -= take
                        } else {
                            const { done, value } = await reader.read()
                            if (done) break
                            // Add to buffer, let loop handle slicing
                            buffer = value
                        }
                    }
                }
            }

            if (padding > 0) {
                await ensureBuffer(padding)
                consume(padding)
            }
        }

        Object.values(dbCache).forEach(db => db.close())
        alert("Import complete!")
        await listFolders()
    } catch (e) {
        console.error(e)
        alert("Import failed: " + e.message)
    } finally {
        setUiBusy(false)
        progressElem.textContent = ""
    }
}

// AAAAAAAHH
/**
 * Creates a 512-byte USTAR tar header.
 */
function createTarHeader(filename, size, isDir = false) {
    const buffer = new Uint8Array(512)
    const enc = new TextEncoder()

    let prefix = "", name = filename
    if (filename.length > 100) {
        const minSplitIndex = Math.max(0, filename.length - 101)
        const maxSplitIndex = Math.min(filename.length, 155)
        const splitIndex = filename.lastIndexOf("/", maxSplitIndex)
        if (splitIndex >= minSplitIndex) {
            prefix = filename.substring(0, splitIndex)
            name = filename.substring(splitIndex + 1)
        } else {
            name = filename.substring(filename.length - 100)
        }
    }

    const writeStr = (str, offset, len) => {
        let bytes = enc.encode(str)
        if (bytes.length > len) bytes = bytes.subarray(0, len)
        buffer.set(bytes, offset)
    }

    // Write Standard Fields
    writeStr(name, 0, 100)
    writeOctal(buffer, 0o664, 100, 8)
    writeOctal(buffer, 0, 108, 8)
    writeOctal(buffer, 0, 116, 8)
    writeOctal(buffer, size, 124, 12)
    writeOctal(buffer, Math.floor(Date.now() / 1000), 136, 12)

    buffer[156] = isDir ? 53 : 48
    writeStr("ustar\0", 257, 6)
    writeStr("00", 263, 2)
    if (prefix) writeStr(prefix, 345, 155)

    for (let i = 148; i < 156; i++) buffer[i] = 32

    let checksum = 0
    for (let i = 0; i < 512; i++) checksum += buffer[i]

    // Write Checksum: 6 octal digits + Null + Space
    const checksumStr = checksum.toString(8).padStart(6, "0")
    writeStr(checksumStr, 148, 6)
    buffer[154] = 0 // Null
    buffer[155] = 32 // Space

    return buffer
}

function parseTarHeader(buffer) {
    const dec = new TextDecoder()

    // Helper to read null-terminated string
    const readStr = (offset, len) => {
        let idx = -1
        // Scan for null terminator first
        for (let i = 0; i < len; i++) {
            if (buffer[offset + i] === 0) {
                idx = i
                break
            }
        }
        const end = (idx === -1) ? len : idx
        return dec.decode(buffer.subarray(offset, offset + end)).trim()
    }

    const name = readStr(0, 100)
    const prefix = readStr(345, 155)
    const sizeStr = readStr(124, 12)
    const size = parseInt(sizeStr, 8)
    const type = String.fromCharCode(buffer[156])

    // Check for empty block
    if (!name && isNaN(size) && buffer[0] === 0) return null

    let fullPath = prefix ? `${prefix}/${name}` : name
    return { name: fullPath, size: isNaN(size) ? 0 : size, type }
}

/**
 * Writes a number as an octal string to the buffer.
 * Standard behavior: Zero-padded, terminated by Space or Null (we use Null).
 */
function writeOctal(buffer, value, offset, len) {
    const str = value.toString(8).padStart(len - 1, "0")
    const enc = new TextEncoder()
    buffer.set(enc.encode(str), offset)
}

function createProgressThrottle(element) {
    let lastTime = 0
    return async function (text) {
        const now = Date.now()
        if (now - lastTime > 100) {
            lastTime = now
            element.textContent = text
            await new Promise(r => setTimeout(r, 0))
        }
    }
}

function base64ToBuffer(base64) {
    const bin = atob(base64)
    const len = bin.length
    const bytes = new Uint8Array(len)
    for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i)
    return bytes.buffer
}

function bufferToBase64(buffer) {
    let binary = ""
    const bytes = new Uint8Array(buffer)
    const len = bytes.byteLength
    for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i])
    return btoa(binary)
}

async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder()
    const base = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"])
    return await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
}

async function writeEncryptedChunk(writer, key, chunk) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, chunk)

    // Write IV
    await writer.write(iv)

    // Write Length of Ciphertext (uint32)
    const lenBuf = new ArrayBuffer(4)
    new DataView(lenBuf).setUint32(0, ciphertext.byteLength, true) // Little endian
    await writer.write(new Uint8Array(lenBuf))

    // Write Ciphertext
    await writer.write(new Uint8Array(ciphertext))
}

// Chunks data into ~4MB blocks to keep memory low during encryption
class ChunkedEncryptionStream extends WritableStream {
    constructor(underlyingWriter, key) {
        let buffer = new Uint8Array(0)

        super({
            async write(chunk) {
                // Append new chunk to buffer
                const newBuffer = new Uint8Array(buffer.length + chunk.length)
                newBuffer.set(buffer)
                newBuffer.set(chunk, buffer.length)
                buffer = newBuffer

                // Flush full chunks
                while (buffer.length >= CHUNK_SIZE) {
                    const slice = buffer.slice(0, CHUNK_SIZE)
                    buffer = buffer.slice(CHUNK_SIZE)
                    await writeEncryptedChunk(underlyingWriter, key, slice)
                }
            },
            async close() {
                // Flush remaining
                if (buffer.length > 0) {
                    await writeEncryptedChunk(underlyingWriter, key, buffer)
                }
                await underlyingWriter.close()
            }
        })
    }
}

// Fallback upload (manual selection)
async function uploadFolderFallback(event) {
    const name = document.getElementById("folderName").value.trim()
    const input = event.target
    if (!input.files.length) {
        setUiBusy(false)
        return
    }
    await processFileListAndStore(name, input.files)
    input.value = ""
    setUiBusy(false)
}

// Sync Logic
async function syncFiles() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")
    setUiBusy(true)
    if (changes.length > 0) {
        await performSyncToOpfs()
        alert("Sync complete.")
    } else {
        alert("No changes detected.")
    }
    setUiBusy(false)
}

async function syncAndOpenFile() {
    if (!folderName || !dirHandle) return alert("Upload a folder first.")
    setUiBusy(true)
    if (changes.length > 0) await performSyncToOpfs()
    openFile(folderName)
}

async function performSyncToOpfs() {
    console.log(`Syncing ${changes.length} changes...`)
    const root = await getOpfsRoot()
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX)
    const folderHandle = await rfsRoot.getDirectoryHandle(folderName)

    for (const change of changes) {
        const pathArr = change.relativePathComponents
        if (!pathArr) continue

        const fileName = pathArr[pathArr.length - 1]
        const dirPath = pathArr.slice(0, -1)
        const pathStr = pathArr.join("/")

        try {
            if (change.type === "deleted") {
                let cur = folderHandle
                try {
                    for (const p of dirPath) cur = await cur.getDirectoryHandle(p)
                    await cur.removeEntry(fileName)
                } catch (e) {
                    // Ignore if already gone
                }
            } else if (change.type === "modified" || change.type === "created") {
                let srcHandle = dirHandle
                try {
                    for (const p of pathArr) {
                        if (p === fileName && p === pathArr[pathArr.length - 1]) {
                            srcHandle = await srcHandle.getFileHandle(p)
                        } else {
                            srcHandle = await srcHandle.getDirectoryHandle(p)
                        }
                    }
                } catch (e) {
                    console.warn(`Could not find source file for sync: ${pathStr}`)
                    continue
                }

                if (srcHandle.kind === "file") {
                    const f = await srcHandle.getFile()
                    await writeStreamToOpfs(folderHandle, pathStr, f.stream())
                }
            }
        } catch (e) {
            console.warn(`Sync failed for ${pathStr}`, e)
        }
    }
    changes.length = 0
}

// Encrypt Folder Logic
async function uploadAndEncryptWithPassword() {
    const name = document.getElementById("encryptFolderName").value.trim()
    const password = prompt("Password:")
    if (!name || !password) return

    setUiBusy(true)
    const progressElem = document.getElementById("progress")
    const updateProgress = createProgressThrottle(progressElem)

    try {
        const localDir = await window.showDirectoryPicker({ mode: "read" })
        const root = await getOpfsRoot()
        const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true })

        // Clean old folder
        try { await rfsRoot.removeEntry(name, { recursive: true }) } catch (e) { }
        const destDir = await rfsRoot.getDirectoryHandle(name, { create: true })
        // Create a "content" subfolder for the obfuscated blobs
        const contentDir = await destDir.getDirectoryHandle("content", { create: true })

        const salt = crypto.getRandomValues(new Uint8Array(16))
        const key = await deriveKeyFromPassword(password, salt)

        // Metadata Store: Maps virtual paths to { id, size, type }
        const manifestData = {}

        async function processHandle(src, relativePath) {
            for await (const entry of src.values()) {
                const entryPath = relativePath ? `${relativePath}/${entry.name}` : entry.name

                if (entry.kind === "file") {
                    updateProgress(`Encrypting: ${entryPath}`)

                    const fileId = crypto.randomUUID()
                    const file = await entry.getFile()
                    const size = file.size

                    // Store metadata entry
                    manifestData[entryPath] = {
                        id: fileId,
                        size: size,
                        type: file.type
                    }

                    // Encrypt Content in Chunks
                    const destFileHandle = await contentDir.getFileHandle(fileId, { create: true })
                    const writable = await destFileHandle.createWritable()

                    const buffer = await file.arrayBuffer()
                    const totalChunks = Math.ceil(size / CHUNK_SIZE)

                    for (let i = 0; i < totalChunks; i++) {
                        const start = i * CHUNK_SIZE
                        const end = Math.min(start + CHUNK_SIZE, size)
                        const chunk = buffer.slice(start, end)

                        const iv = crypto.getRandomValues(new Uint8Array(12))
                        const encryptedChunk = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, chunk)

                        // Format: [IV (12)][Ciphertext]
                        await writable.write(iv)
                        await writable.write(new Uint8Array(encryptedChunk))
                    }
                    await writable.close()

                } else {
                    await processHandle(entry, entryPath)
                }
            }
        }

        await processHandle(localDir, "")

        // Encrypt and Save Manifest
        updateProgress("Saving Manifest...")
        const manifestJson = JSON.stringify(manifestData)
        const manifestBuffer = new TextEncoder().encode(manifestJson)
        const manifestIv = crypto.getRandomValues(new Uint8Array(12))
        const encManifest = await crypto.subtle.encrypt({ name: "AES-GCM", iv: manifestIv }, key, manifestBuffer)

        const manifestHandle = await destDir.getFileHandle("manifest.enc", { create: true })
        const mw = await manifestHandle.createWritable()
        // Format: [Salt (16)][IV (12)][EncryptedManifest]
        await mw.write(salt)
        await mw.write(manifestIv)
        await mw.write(new Uint8Array(encManifest))
        await mw.close()

        await updateRegistryEntry(name, { encryptionType: "password", salt: bufferToBase64(salt) })
        document.getElementById("encryptFolderName").value = ""
        await listFolders()

    } catch (e) {
        alert("Error: " + e.message)
        console.error(e)
    } finally {
        setUiBusy(false)
        progressElem.textContent = ""
    }
}

// Initialize
document.addEventListener("DOMContentLoaded", () => {
    function setupServiceWorkerListeners() {
        if (!("serviceWorker" in navigator)) return

        navigator.serviceWorker.register("./sw.js").then(reg => {
            // Check for updates
            reg.addEventListener("updatefound", () => {
                const newWorker = reg.installing
                newWorker.addEventListener("statechange", () => {
                    if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
                        // New version installed, reload to activate it
                        console.log("New version available. Reloading...")
                        location.reload()
                    }
                })
            })

            if (reg.active && !navigator.serviceWorker.controller) {
                console.log("SW active but not controlling. Waiting for claim...")
            }
        }).catch(console.error)

        navigator.serviceWorker.addEventListener("message", async (event) => {
            if (event.data && event.data.type === "SW_READY") {
                console.log("SW: Ready signal received.")
                await listFolders()
            }
            if (event.data && event.data.type === "INVALIDATE_CACHE") {
                await listFolders()
            }
        })
    }

    // Event Listeners
    document.getElementById("folderName").addEventListener("keydown", e => e.key === "Enter" && !currentlyBusy && uploadFolder())
    document.getElementById("openFolderName").addEventListener("keydown", e => e.key === "Enter" && !currentlyBusy && openFile())
    document.getElementById("fileName").addEventListener("keydown", e => e.key === "Enter" && !currentlyBusy && openFile())
    document.getElementById("deleteFolderName").addEventListener("keydown", e => e.key === "Enter" && !currentlyBusy && deleteFolder())
    document.getElementById("folderUploadFallbackInput").addEventListener("change", uploadFolderFallback)

    const dragZone = document.body
    dragZone.addEventListener("dragover", e => { e.preventDefault(); dragZone.style.backgroundColor = "#385b7e" })
    dragZone.addEventListener("dragleave", () => { dragZone.style.backgroundColor = "" })
    dragZone.addEventListener("drop", async e => {
        e.preventDefault(); dragZone.style.backgroundColor = ""
        const items = [...e.dataTransfer.items].filter(i => i.kind === "file")
        if (!items.length) return

        const first = items[0].getAsFile()
        if (items.length === 1 && first) {
            if (confirm(`Import "${first.name}"?`)) startImport(first)
            return
        }

        const entry = items[0].webkitGetAsEntry()
        if (entry.isDirectory) {
            const name = prompt("Please choose a folder name:", entry.name)
            if (name) {
                setUiBusy(true)
                // Need manual scan for DnD entry
                const scan = async (ent, p) => {
                    if (ent.isFile) {
                        const f = await new Promise((res, rej) => ent.file(res, rej))
                        Object.defineProperty(f, "webkitRelativePath", { value: p + f.name })
                        return [f]
                    } else if (ent.isDirectory) {
                        const r = ent.createReader()
                        let files = []
                        let batch
                        do {
                            batch = await new Promise((res, rej) => r.readEntries(res, rej))
                            for (const c of batch) files.push(...await scan(c, p + ent.name + "/"))
                        } while (batch.length > 0)
                        return files
                    }
                }
                const files = await scan(entry, "")
                await processFileListAndStore(name, files)
            }
        }
    })

    setupServiceWorkerListeners()
    listFolders()

    // Restore textareas
    const rT = document.getElementById("regex")
    const hT = document.getElementById("headers")
    if (rT) {
        rT.value = localStorage.getItem("fsRegex") || ""
        rT.addEventListener("input", () => localStorage.setItem("fsRegex", rT.value))
    }
    if (hT) {
        hT.value = localStorage.getItem("fsHeaders") || ""
        hT.addEventListener("input", () => localStorage.setItem("fsHeaders", hT.value))
    }
})