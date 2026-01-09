const SW_LINK = "./sw.min.js"; // Change if needed!
const RFS_PREFIX = "rfs"; // OPFS prefix
const SYSTEM_FILE = "rfs_system.json"; // File with a little bit of extra data
const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB
const CONCURRENCY = 4; // Number of "workers" for folder uploading stuff

let isListingFolders = false;
let currentlyBusy = false;
let folderName, dirHandle, observer;
let changes = [];

let _opfsRoot = null;
async function getOpfsRoot() {
  if (!_opfsRoot) _opfsRoot = await navigator.storage.getDirectory();
  return _opfsRoot;
}

function setUiBusy(isBusy) {
  currentlyBusy = isBusy;
  Array.from(document.getElementsByTagName("button")).forEach(
    (button) => (button.disabled = currentlyBusy)
  );
}

function createProgressLogger(domElement) {
  let lastUpdate = 0;
  return async (msg, force = false) => {
    const now = Date.now();
    if (force || now - lastUpdate > 50) {
      if (domElement) domElement.textContent = msg;
      lastUpdate = now;
      // Yield to main thread to allow UI paint
      await new Promise((r) => setTimeout(r, 0));
    }
  };
}

window.addEventListener("beforeunload", function checkUnsavedChanges(event) {
  if (currentlyBusy) {
    return "Changes you made may not be saved.";
  }
});

const yieldToMain = () => new Promise((r) => setTimeout(r, 0));

async function pumpStream(reader, writer, totalSize, onProgress) {
  let processed = 0;
  let lastLogTime = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      await writer.write(value);
      processed += value.length;

      const now = Date.now();
      if (onProgress && now - lastLogTime > 100) {
        // Force yield here to ensure UI paints
        await new Promise((r) => setTimeout(r, 0));
        await onProgress(processed, totalSize);
        lastLogTime = now;
      }
    }
    if (onProgress) await onProgress(processed, totalSize);
  } finally {
    try {
      writer.close();
    } catch (e) {}
    try {
      reader.releaseLock();
    } catch (e) {}
  }
}

navigator.storage
  .persist()
  .then((p) =>
    console.log(p ? "Storage persisted." : "Storage not persisted.")
  );

async function waitForController() {
  if (navigator.serviceWorker.controller)
    return navigator.serviceWorker.controller;
  await navigator.serviceWorker.register(SW_LINK);
  const reg = await navigator.serviceWorker.ready;
  return navigator.serviceWorker.controller || reg.active;
}

async function getRegistry() {
  try {
    const root = await getOpfsRoot();
    const handle = await root.getFileHandle(SYSTEM_FILE);
    const file = await handle.getFile();
    return JSON.parse(await file.text());
  } catch (e) {
    return {};
  }
}

async function saveRegistry(registry) {
  const root = await getOpfsRoot();
  const handle = await root.getFileHandle(SYSTEM_FILE, { create: true });
  const writable = await handle.createWritable();
  await writable.write(JSON.stringify(registry));
  await writable.close();
}

async function updateRegistryEntry(name, data) {
  await navigator.locks.request("rfs_registry_lock", async () => {
    const reg = await getRegistry();
    if (data === null) {
      delete reg[name];
    } else {
      reg[name] = { ...reg[name], ...data, lastModified: Date.now() };
    }
    await saveRegistry(reg);
  });

  if (navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage({
      type: "INVALIDATE_CACHE",
      folderName: name,
    });
  }
}

async function uploadFolder() {
  const folderNameInput = document.getElementById("folderName");
  const name = folderNameInput.value.trim();
  if (!name) return alert("Please enter a name.");

  setUiBusy(true);
  try {
    if (window.showDirectoryPicker) {
      const localDirHandle = await window.showDirectoryPicker({ mode: "read" });
      await processFolderSelection(name, localDirHandle);
    } else {
      document.getElementById("folderUploadFallbackInput").click();
    }
  } catch (e) {
    if (e.name !== "AbortError") alert("Upload error: " + e.message);
  } finally {
    setUiBusy(false);
  }
}

async function processFolderSelection(name, handle) {
  dirHandle = handle;
  folderName = name;

  try {
    const encManifest = await handle.getFileHandle("manifest.enc");
    console.log("Encrypted folder detected.");
    const root = await getOpfsRoot();
    const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
    try {
      await rfs.removeEntry(name, { recursive: true });
    } catch (e) {}

    await decryptAndLoadFolderToOpfs(
      handle,
      encManifest,
      await rfs.getDirectoryHandle(name, { create: true })
    );
    await updateRegistryEntry(name, { encryptionType: null });
  } catch (e) {
    await processAndStoreFolderStreaming(name, handle);
  }

  if (observer) {
    try {
      observer.disconnect();
    } catch (e) {}
    observer = null;
  }

  if ("FileSystemObserver" in window) {
    try {
      observer = new FileSystemObserver((recs) => changes.push(...recs));
      observer.observe(dirHandle, { recursive: true });
    } catch (e) {
      console.warn("Observer failed:", e);
    }
  }

  changes.length = 0;
  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await listFolders();
}

async function decryptAndLoadFolderToOpfs(srcHandle, manifestHandle, destDir) {
  const password = prompt("Enter the password to decrypt this folder:");
  if (!password) throw new Error("Password required.");

  const manifestFile = await manifestHandle.getFile();
  const manifestBuf = await manifestFile.arrayBuffer();

  const salt = manifestBuf.slice(0, 16);
  const iv = manifestBuf.slice(16, 28);
  const encData = manifestBuf.slice(28);

  const key = await deriveKeyFromPassword(password, salt);

  let manifestData;
  try {
    const decryptedManifestBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encData
    );
    manifestData = JSON.parse(new TextDecoder().decode(decryptedManifestBytes));
  } catch (e) {
    throw new Error("Decryption failed. Wrong password?");
  }

  const logProgress = createProgressLogger(document.getElementById("progress"));
  const contentDir = await srcHandle.getDirectoryHandle("content");
  const ENCRYPTED_CHUNK_OVERHEAD = 12 + 16;

  const entries = Object.entries(manifestData);
  let processedFiles = 0;
  const totalFiles = entries.length;

  for (const [originalPath, meta] of entries) {
    // This will yield automatically if >100ms has passed
    await logProgress(
      `Decrypting (${processedFiles}/${totalFiles}): ${originalPath}`
    );

    const pathParts = originalPath.split("/");
    const fileName = pathParts.pop();
    let currentDir = destDir;
    for (const part of pathParts) {
      currentDir = await currentDir.getDirectoryHandle(part, { create: true });
    }

    let srcFile;
    try {
      const handle = await contentDir.getFileHandle(meta.id);
      srcFile = await handle.getFile();
    } catch (e) {
      console.warn(`Missing: ${originalPath}`);
      continue;
    }

    const destFileHandle = await currentDir.getFileHandle(fileName, {
      create: true,
    });
    const writable = await destFileHandle.createWritable();

    if (meta.size > 0) {
      const reader = srcFile.stream().getReader();
      const totalEncChunks = Math.ceil(meta.size / CHUNK_SIZE);
      let buffer = new Uint8Array(0);
      let chunkIndex = 0;

      try {
        while (chunkIndex < totalEncChunks) {
          const isLast = chunkIndex === totalEncChunks - 1;
          const plainSize = isLast
            ? meta.size % CHUNK_SIZE || CHUNK_SIZE
            : CHUNK_SIZE;
          const encSize = plainSize + ENCRYPTED_CHUNK_OVERHEAD;

          while (buffer.length < encSize) {
            const { done, value } = await reader.read();
            if (done) break;
            const newBuf = new Uint8Array(buffer.length + value.length);
            newBuf.set(buffer);
            newBuf.set(value, buffer.length);
            buffer = newBuf;
          }

          if (buffer.length < encSize) break;

          const chunkData = buffer.slice(0, encSize);
          buffer = buffer.slice(encSize);

          const chunkIv = chunkData.slice(0, 12);
          const chunkCipher = chunkData.slice(12);

          try {
            const plainChunk = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: chunkIv },
              key,
              chunkCipher
            );
            await writable.write(new Uint8Array(plainChunk));
          } catch (e) {
            console.error(
              `Decryption error at chunk ${chunkIndex} for ${originalPath}`
            );
          }
          chunkIndex++;
        }
      } finally {
        reader.releaseLock();
      }
    }
    await writable.close();
    processedFiles++;
  }
  await logProgress("", true); // Clear
}

async function processFileListAndStore(name, fileList) {
  const logProgress = createProgressLogger(document.getElementById("progress"));

  try {
    if (!fileList.length) return;
    const root = await getOpfsRoot();
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
    try {
      await rfsRoot.removeEntry(name, { recursive: true });
      await yieldToMain();
    } catch (e) {}

    const folderHandle = await rfsRoot.getDirectoryHandle(name, {
      create: true,
    });

    let basePath = "";
    if (
      fileList.length > 0 &&
      fileList[0].webkitRelativePath &&
      fileList[0].webkitRelativePath.includes("/")
    ) {
      basePath = fileList[0].webkitRelativePath.split("/")[0] + "/";
    }

    const totalFiles = fileList.length;
    let processedCount = 0;

    // Convert FileList to Array for easier processing
    const files = Array.from(fileList);
    async function worker() {
      while (files.length > 0) {
        const file = files.shift();
        if (!file) break;

        let path = file.webkitRelativePath || file.name;
        if (basePath && path.startsWith(basePath))
          path = path.substring(basePath.length);
        if (!path) continue;

        // Pass the FILE object, not file.stream()
        // We pass null for individual progress to reduce overhead on many small files
        await writeStreamToOpfs(folderHandle, path, file, file.size, null);

        processedCount++;
        // Centralized rate-limited logging
        await logProgress(
          `Uploading ${processedCount}/${totalFiles}: ${path} (${Math.round(
            file.size / 1024
          )} KB)`
        );
      }
    }

    await Promise.all(Array(CONCURRENCY).fill(null).map(worker));

    await updateRegistryEntry(name, { encryptionType: null });
    await logProgress("", true);
    document.getElementById("folderName").value = "";
    document.getElementById("openFolderName").value = name;
    await listFolders();
  } catch (e) {
    console.error(e);
    alert("Error: " + e.message);
  } finally {
    await logProgress("", true);
  }
}

async function processAndStoreFolderStreaming(name, srcHandle) {
  const logProgress = createProgressLogger(document.getElementById("progress"));

  const root = await getOpfsRoot();
  const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
  try {
    await rfs.removeEntry(name, { recursive: true });
  } catch (e) {}
  const destRoot = await rfs.getDirectoryHandle(name, { create: true });
  await logProgress("Starting stream upload...", true);

  const queue = [
    {
      source: srcHandle,
      dest: destRoot,
      path: "",
    },
  ];

  const pendingUploads = [];
  let completedFiles = 0;
  let activeWorkers = 0;

  // Helper to run the upload queue
  async function flushUploads() {
    while (pendingUploads.length > 0 && activeWorkers < CONCURRENCY) {
      const task = pendingUploads.shift();
      activeWorkers++;

      writeStreamToOpfs(task.dest, task.name, task.file, task.file.size)
        .then(() => {
          completedFiles++;
          logProgress(`Processed ${completedFiles} files...`);
        })
        .catch((e) => console.error(`Failed ${task.name}:`, e))
        .finally(() => {
          activeWorkers--;
          // Chain the next flush
          flushUploads();
        });
    }
  }

  // Iterative scan
  while (queue.length > 0) {
    const { source, dest, path } = queue.shift();

    for await (const entry of source.values()) {
      if (entry.kind === "file") {
        const file = await entry.getFile();
        // Push to upload queue immediately
        pendingUploads.push({
          dest: dest, // We already have the parent dest handle!
          name: entry.name,
          file: file,
        });

        // Keep the workers fed
        if (pendingUploads.length >= CONCURRENCY) flushUploads();
      } else if (entry.kind === "directory") {
        const newDest = await dest.getDirectoryHandle(entry.name, {
          create: true,
        });
        queue.push({
          source: entry,
          dest: newDest,
          path: path + "/" + entry.name,
        });
      }
    }
    // Yield occasionally during scanning
    await new Promise((r) => setTimeout(r, 0));
  }

  // Wait for remaining uploads
  while (pendingUploads.length > 0 || activeWorkers > 0) {
    flushUploads();
    await new Promise((r) => setTimeout(r, 100));
  }

  await updateRegistryEntry(name, { encryptionType: null });
  await logProgress("", true);
  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await listFolders();
}

async function writeStreamToOpfs(
  parentHandle,
  path,
  fileObj,
  totalSize,
  onProgress
) {
  const parts = path.split("/");
  const fileName = parts.pop();

  // Fresh stream for each attempt
  const attemptUpload = async (dirHandle) => {
    const fileHandle = await dirHandle.getFileHandle(fileName, {
      create: true,
    });
    const writable = await fileHandle.createWritable();
    // Get a fresh stream reader from the File object
    if (!onProgress) {
      await fileObj.stream().pipeTo(writable);
    } else {
      // Keep manual pumping only when we absolutely need granular progress
      await pumpStream(
        fileObj.stream().getReader(),
        writable,
        totalSize,
        onProgress
      );
    }
  };

  try {
    let currentDir = parentHandle;
    for (const part of parts) {
      currentDir = await currentDir.getDirectoryHandle(part, { create: true });
    }
    await attemptUpload(currentDir);
  } catch (e) {
    if (e.name === "InvalidStateError") {
      console.warn(`Retrying write for ${fileName}...`);
      await yieldToMain();
      let retryDir = parentHandle;
      for (const part of parts)
        retryDir = await retryDir.getDirectoryHandle(part, { create: true });

      await attemptUpload(retryDir);
      return;
    }
    throw e;
  }
}

async function listFolders() {
  if (isListingFolders) return;
  isListingFolders = true;
  const folderList = document.getElementById("folderList");

  try {
    const registry = await getRegistry();
    folderList.textContent = "";
    const fragment = document.createDocumentFragment();

    const names = Object.keys(registry).sort();
    names.forEach((name) => {
      const meta = registry[name];
      const li = document.createElement("li");
      li.textContent =
        meta.encryptionType === "password" ? `[Locked] ${name}` : name;
      fragment.appendChild(li);
    });
    folderList.appendChild(fragment);
  } catch (e) {
    console.error("List failed:", e);
  } finally {
    isListingFolders = false;
  }
}

async function deleteFolder(folderNameToDelete, skipConfirm = false) {
  const folderName =
    folderNameToDelete ||
    document.getElementById("deleteFolderName").value.trim();
  if (!folderName) return alert("Enter folder name!");
  if (!skipConfirm && !confirm(`Remove "${folderName}"?`)) return;

  const progressElem = document.getElementById("progress");
  progressElem.textContent = "Deleting...";
  setUiBusy(true);
  try {
    const root = await getOpfsRoot();
    try {
      const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX);
      await rfsRoot.removeEntry(folderName, { recursive: true });
    } catch (e) {}

    await updateRegistryEntry(folderName, null);
    if (!folderNameToDelete)
      document.getElementById("deleteFolderName").value = "";
    await listFolders();
  } catch (e) {
    alert("Delete failed: " + e.message);
  } finally {
    progressElem.textContent = "";
    if (!skipConfirm) setUiBusy(false);
  }
}

async function openFile(overrideFolderName) {
  const folderName =
    overrideFolderName ||
    document.getElementById("openFolderName").value.trim();
  const fileName = document.getElementById("fileName").value.trim();
  if (!folderName) return alert("Provide a folder name.");

  setUiBusy(true);
  try {
    const registry = await getRegistry();
    const meta = registry[folderName];
    if (!meta) return alert("Folder not found.");

    const rules = document.getElementById("regex").value.trim();
    const headers = document.getElementById("headers").value.trim();

    if (meta.rules !== rules || meta.headers !== headers) {
      await updateRegistryEntry(folderName, { rules, headers });
    }

    let key = null;
    if (meta.encryptionType === "password") {
      const password = prompt(`Enter password for "${folderName}":`);
      if (!password) return setUiBusy(false);
      key = await deriveKeyFromPassword(password, base64ToBuffer(meta.salt));
    }

    const sw = await waitForController();
    await new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => resolve();
      sw.postMessage({ type: "SET_RULES", rules, headers, key, folderName }, [
        channel.port2,
      ]);
    });

    const encodedPath = fileName.split("/").map(encodeURIComponent).join("/");
    window.open(`n/${encodeURIComponent(folderName)}/${encodedPath}`, "_blank");
  } catch (e) {
    alert("Error: " + e);
  } finally {
    setUiBusy(false);
  }
}

async function startImport(file) {
  setUiBusy(true);
  const progressElem = document.getElementById("progress");
  const TEMP_BLOB_DIR = ".rfs_temp_blobs"; // Must match LittleExport

  try {
    const root = await navigator.storage.getDirectory();

    // Safety check before nuking
    try {
      await root.removeEntry(RFS_PREFIX, { recursive: true });
    } catch (e) {}
    try {
      await root.removeEntry(SYSTEM_FILE);
    } catch (e) {}
    try {
      await root.removeEntry(TEMP_BLOB_DIR, { recursive: true });
    } catch (e) {}

    // Yield to main thread to ensure file system operations flush
    await new Promise((resolve) => setTimeout(resolve, 50));

    await LittleExport.importData(file, {
      logger: (msg) => {
        if (progressElem) progressElem.textContent = msg;
        console.log(msg);
      },
      onCustomItem: async (path, data) => {
        if (path === SYSTEM_FILE) {
          const decoder = new TextDecoder();
          const registry = JSON.parse(decoder.decode(data));
          await saveRegistry(registry);
        }
      },
    });

    if (navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({
        type: "INVALIDATE_CACHE",
      });
    }

    alert("Import complete!");
    location.reload();
  } catch (e) {
    console.error(e);
    alert("Import failed: " + e.message);
  } finally {
    setUiBusy(false);
    if (progressElem) progressElem.textContent = "";
  }
}

async function exportData() {
  setUiBusy(true);
  const progressElem = document.getElementById("progress");
  const updateProgress = (msg) => (progressElem.textContent = msg);
  let password = prompt("Enter a password (or leave blank for no encryption):");

  try {
    const registry = await getRegistry();
    await LittleExport.exportData({
      fileName: "result",
      password: password,
      cookies: document.getElementById("c1").checked,
      localStorage: document.getElementById("c2").checked,
      idb: document.getElementById("c3").checked,
      opfs: document.getElementById("c5").checked,
      cache: document.getElementById("c6").checked,
      session: document.getElementById("c7").checked,

      customItems: [{ path: SYSTEM_FILE, data: JSON.stringify(registry) }],
      exclude: { opfs: [SYSTEM_FILE] },
      logger: updateProgress,
    });
  } catch (e) {
    alert("Export failed: " + e.message);
  } finally {
    setUiBusy(false);
    updateProgress("");
  }
}

async function importData() {
  const input = document.createElement("input");
  input.type = "file";
  input.onchange = (e) => {
    if (e.target.files[0]) startImport(e.target.files[0]);
  };
  input.click();
}

function base64ToBuffer(base64) {
  const bin = atob(base64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function uploadFolderFallback(event) {
  const name = document.getElementById("folderName").value.trim();
  const input = event.target;
  if (!input.files.length) {
    setUiBusy(false);
    return;
  }
  await processFileListAndStore(name, input.files);
  input.value = "";
  setUiBusy(false);
}

var syncTimeout = -1;
async function syncFiles() {
  if (!folderName || !dirHandle)
    return alert("Upload a folder to sync changes (not always supported).");
  setUiBusy(true);
  if (changes.length > 0) {
    await performSyncToOpfs();
    document.getElementById("syncInfo").textContent = "Sync complete found.";
  } else {
    document.getElementById("syncInfo").textContent = "No sync changes.";
  }
  clearTimeout(syncTimeout);
  syncTimeout = setTimeout(
    () => (document.getElementById("syncInfo").textContent = ""),
    1000
  );
  setUiBusy(false);
}

async function syncAndOpenFile() {
  if (!folderName || !dirHandle)
    return alert("Upload a folder to sync changes (not always supported).");
  setUiBusy(true);
  if (changes.length > 0) {
    await performSyncToOpfs();
    document.getElementById("syncInfo").textContent = "Sync complete found.";
  } else {
    document.getElementById("syncInfo").textContent = "No sync changes.";
  }
  clearTimeout(syncTimeout);
  syncTimeout = setTimeout(
    () => (document.getElementById("syncInfo").textContent = ""),
    1000
  );
  openFile(folderName);
}

async function performSyncToOpfs() {
  console.log(`Syncing ${changes.length} changes...`);
  const root = await getOpfsRoot();
  const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX);
  const folderHandle = await rfsRoot.getDirectoryHandle(folderName);

  for (const change of changes) {
    const pathArr = change.relativePathComponents;
    if (!pathArr) continue;
    const fileName = pathArr[pathArr.length - 1];
    const dirPath = pathArr.slice(0, -1);
    const pathStr = pathArr.join("/");

    try {
      if (change.type === "deleted") {
        let cur = folderHandle;
        try {
          for (const p of dirPath) cur = await cur.getDirectoryHandle(p);
          await cur.removeEntry(fileName, { recursive: true });
        } catch (e) {}
      } else if (change.type === "modified" || change.type === "created") {
        let srcHandle = dirHandle;
        try {
          for (const p of pathArr) {
            if (p === fileName && p === pathArr[pathArr.length - 1]) {
              srcHandle = await srcHandle.getFileHandle(p);
            } else {
              srcHandle = await srcHandle.getDirectoryHandle(p);
            }
          }
        } catch (e) {
          continue;
        }

        if (srcHandle.kind === "file") {
          const f = await srcHandle.getFile();
          await writeStreamToOpfs(folderHandle, pathStr, f, f.size);
        }
      }
    } catch (e) {
      console.warn(`Sync failed for ${pathStr}`, e);
    }
  }
  changes.length = 0;
}

async function uploadAndEncryptWithPassword() {
  const name = document.getElementById("encryptFolderName").value.trim();
  const password = prompt("Password:");
  if (!name || !password) return;

  setUiBusy(true);
  const progressElem = document.getElementById("progress");

  try {
    const localDir = await window.showDirectoryPicker({ mode: "read" });
    const root = await getOpfsRoot();
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
    try {
      await rfsRoot.removeEntry(name, { recursive: true });
    } catch (e) {}

    const destDir = await rfsRoot.getDirectoryHandle(name, { create: true });
    const contentDir = await destDir.getDirectoryHandle("content", {
      create: true,
    });

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyFromPassword(password, salt);
    const manifestData = {};

    async function processHandle(src, relativePath) {
      for await (const entry of src.values()) {
        const entryPath = relativePath
          ? `${relativePath}/${entry.name}`
          : entry.name;
        if (entry.kind === "file") {
          progressElem.textContent = `Encrypting: ${entryPath}`;
          await yieldToMain();

          const fileId = crypto.randomUUID();
          const file = await entry.getFile();
          manifestData[entryPath] = {
            id: fileId,
            size: file.size,
            type: file.type,
          };

          const destFileHandle = await contentDir.getFileHandle(fileId, {
            create: true,
          });
          const writable = await destFileHandle.createWritable();

          if (file.size > 0) {
            const reader = file.stream().getReader();
            let totalProcessed = 0;

            var lastYield = Date.now();
            while (true) {
              let buffer = new Uint8Array(0);
              while (buffer.length < CHUNK_SIZE) {
                const { done, value } = await reader.read();
                if (done) break;
                const temp = new Uint8Array(buffer.length + value.length);
                temp.set(buffer);
                temp.set(value, buffer.length);
                buffer = temp;
              }

              if (buffer.length === 0) break;
              if (Date.now() - lastYield > 200) {
                await new Promise((r) => setTimeout(r, 0));
                lastYield = Date.now();
              }

              const iv = crypto.getRandomValues(new Uint8Array(12));
              const encryptedChunk = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                buffer
              );

              await writable.write(iv);
              await writable.write(new Uint8Array(encryptedChunk));

              totalProcessed += buffer.length;
              if (totalProcessed >= file.size) break;
            }
          }
          await writable.close();
        } else {
          await processHandle(entry, entryPath);
        }
      }
    }

    await processHandle(localDir, "");

    progressElem.textContent = "Saving manifest...";
    const manifestJson = JSON.stringify(manifestData);
    const manifestBuffer = new TextEncoder().encode(manifestJson);
    const manifestIv = crypto.getRandomValues(new Uint8Array(12));
    const encManifest = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: manifestIv },
      key,
      manifestBuffer
    );

    const manifestHandle = await destDir.getFileHandle("manifest.enc", {
      create: true,
    });
    const mw = await manifestHandle.createWritable();
    await mw.write(salt);
    await mw.write(manifestIv);
    await mw.write(new Uint8Array(encManifest));
    await mw.close();

    await updateRegistryEntry(name, {
      encryptionType: "password",
      salt: bufferToBase64(salt),
    });

    document.getElementById("encryptFolderName").value = "";
    await listFolders();
  } catch (e) {
    alert("Error: " + e.message);
    console.error(e);
  } finally {
    setUiBusy(false);
    progressElem.textContent = "";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  function setupServiceWorkerListeners() {
    if (!("serviceWorker" in navigator)) return;
    navigator.serviceWorker
      .register(SW_LINK)
      .then((reg) => {
        reg.addEventListener("updatefound", () => {
          const newWorker = reg.installing;
          newWorker.addEventListener("statechange", () => {
            if (
              newWorker.state === "installed" &&
              navigator.serviceWorker.controller
            ) {
              location.reload();
            }
          });
        });
      })
      .catch(console.error);
    navigator.serviceWorker.addEventListener("message", async (event) => {
      if (event.data && event.data.type === "SW_READY") await listFolders();
      if (event.data && event.data.type === "INVALIDATE_CACHE")
        await listFolders();
    });
  }

  document.getElementById("folderName").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !currentlyBusy) {
      uploadFolder();
    }
  });
  document.getElementById("openFolderName").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !currentlyBusy) {
      if (e.shiftKey) {
        openFileInPlace();
      } else if (e.ctrlKey || e.metaKey) {
        syncAndOpenFile();
      } else {
        openFile();
      }
    }
  });
  document.getElementById("fileName").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !currentlyBusy) {
      if (e.shiftKey) {
        openFileInPlace();
      } else if (e.ctrlKey || e.metaKey) {
        syncAndOpenFile();
      } else {
        openFile();
      }
    }
  });
  document
    .getElementById("deleteFolderName")
    .addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !currentlyBusy) {
        deleteFolder();
      }
    });
  document
    .getElementById("folderUploadFallbackInput")
    .addEventListener("change", uploadFolderFallback);

  const dragZone = document.body;
  dragZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dragZone.style.backgroundColor = "#385b7e";
  });
  dragZone.addEventListener("dragleave", () => {
    dragZone.style.backgroundColor = "";
  });
  dragZone.addEventListener("drop", async (e) => {
    e.preventDefault();
    dragZone.style.backgroundColor = "";
    if (currentlyBusy) return;
    const items = [...e.dataTransfer.items].filter((i) => i.kind === "file");
    if (!items.length) return;

    const first = items[0].getAsFile();
    if (items.length === 1 && first) {
      if (confirm(`Import "${first.name}"?`)) startImport(first);
      return;
    }

    const entry = items[0].webkitGetAsEntry();
    if (entry.isDirectory) {
      const name = prompt("Please choose a folder name:", entry.name);
      if (name) {
        setUiBusy(true);
        const progressElem = document.getElementById("progress");
        const logProgress = createProgressLogger(progressElem);

        try {
          // Scan iteratively
          const files = [];
          const queue = [{ entry, path: "" }];

          let scannedCount = 0;
          while (queue.length > 0) {
            const { entry: curr, path } = queue.shift();

            if (curr.isFile) {
              const f = await new Promise((res, rej) => curr.file(res, rej));
              Object.defineProperty(f, "webkitRelativePath", {
                value: path + f.name,
              });
              files.push(f);
              scannedCount++;
            } else if (curr.isDirectory) {
              const reader = curr.createReader();
              let batch;
              do {
                batch = await new Promise((res, rej) =>
                  reader.readEntries(res, rej)
                );
                for (const child of batch) {
                  queue.push({ entry: child, path: path + curr.name + "/" });
                }
              } while (batch.length > 0);
            }

            if (scannedCount % 50 === 0) {
              await logProgress(`Scanning... ${scannedCount} files found`);
            }
          }

          await logProgress(`Processed ${files.length} files...`);
          await processFileListAndStore(name, files);
        } catch (err) {
          alert("Scan failed: " + err.message);
          setUiBusy(false);
          if (progressElem) progressElem.textContent = "";
        }
      }
    }
  });

  setupServiceWorkerListeners();
  listFolders();

  const rT = document.getElementById("regex");
  const hT = document.getElementById("headers");
  if (rT) {
    rT.value = localStorage.getItem("fsRegex") || "";
    rT.addEventListener("input", () =>
      localStorage.setItem("fsRegex", rT.value)
    );
  }
  if (hT) {
    hT.value = localStorage.getItem("fsHeaders") || "";
    hT.addEventListener("input", () =>
      localStorage.setItem("fsHeaders", hT.value)
    );
  }

  if (!window.showDirectoryPicker) {
    Array.from(document.body.getElementsByClassName("supportCheck")).forEach(
      (elem) => (elem.style.display = "none")
    );
  }
});

async function openFileInPlace() {
  const folderName = document.getElementById("openFolderName").value.trim();
  const fileName = document.getElementById("fileName").value.trim();
  if (!folderName) return alert("Provide a folder name.");

  setUiBusy(true);
  try {
    const registry = await getRegistry();
    const meta = registry[folderName];
    if (!meta) return alert("Folder not found.");

    const rules = document.getElementById("regex").value.trim();
    const headers = document.getElementById("headers").value.trim();

    if (meta.rules !== rules || meta.headers !== headers) {
      await updateRegistryEntry(folderName, { rules, headers });
    }

    let key = null;
    if (meta.encryptionType === "password") {
      const password = prompt(`Enter password for "${folderName}":`);
      if (!password) return;
      key = await deriveKeyFromPassword(password, base64ToBuffer(meta.salt));
    }

    const sw = await waitForController();
    if (!navigator.serviceWorker.controller) {
      alert(
        "Service Worker is not controlling the page. Please reload and try again."
      );
      return;
    }

    await new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => resolve();
      sw.postMessage({ type: "SET_RULES", rules, headers, key, folderName }, [
        channel.port2,
      ]);
    });

    const encodedPath = fileName
      ? fileName.split("/").map(encodeURIComponent).join("/")
      : "index.html";
    const virtualUrl = `n/${encodeURIComponent(folderName)}/${encodedPath}`;

    const resp = await fetch(virtualUrl, {
      headers: { Accept: "text/html" },
    });

    if (!resp.ok) {
      if (resp.status === 403) return alert("Session authentication failed.");
      throw new Error(`Failed to load app: ${resp.status} ${resp.statusText}`);
    }
    let html = await resp.text();

    const basePath = virtualUrl.substring(0, virtualUrl.lastIndexOf("/") + 1);
    const baseTag = `<base href="${basePath}">`;

    let metaTags = "";
    resp.headers.forEach((val, name) => {
      metaTags += `<meta http-equiv="${val.replace(
        /"/g,
        "&quot;"
      )}" content="${safeVal}">\n`;
    });

    if (/<head\b[^>]*>/i.test(html)) {
      html = html.replace(/(<head\b[^>]*>)/i, `$1${baseTag}${metaTags}`);
    } else if (/<html\b[^>]*>/i.test(html)) {
      html = html.replace(
        /(<html\b[^>]*>)/i,
        `$1<head>${baseTag}${metaTags}</head>`
      );
    } else {
      html = `<head>${baseTag}${metaTags}</head>${html}`;
    }

    document.open();
    document.write(html);
    document.close();
  } catch (e) {
    alert("Error opening in-place: " + e.message);
  } finally {
    setUiBusy(false);
  }
}
