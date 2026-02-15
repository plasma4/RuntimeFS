const SW_URL = "./sw.min.js"; // Change if needed!
const RFS_PREFIX = "rfs"; // OPFS prefix
const SYSTEM_FILE = "rfs_system.json"; // File with a little bit of extra data
const CHUNK_SIZE = 4194304; // 4MB, for encrypted chunks
const CONCURRENCY = 4; // Number of "workers" for folder uploading stuff
const YIELD_TIME = 50; // Amount of ms before yielding; used for logging and pauses so UI can update.

let isListingFolders = false;
let currentlyBusy = false;
let folderName, dirHandle, observer;
let changes = [];

let showingSync = false;
let _registryCache = null;
let _opfsRoot = null;
async function getOpfsRoot() {
  if (!_opfsRoot) _opfsRoot = await navigator.storage.getDirectory();
  return _opfsRoot;
}

function setUiBusy(isBusy) {
  if (currentlyBusy !== isBusy) {
    currentlyBusy = isBusy;
    Array.from(document.getElementsByTagName("button")).forEach(
      (button) => (button.disabled = currentlyBusy),
    );
  }
}

function createLogger(elem, yielder) {
  let lastMsg = null;
  let lastDomUpdate = 0;
  // Returns Promise | null
  return function (msg, force = false) {
    const now = Date.now();
    if (msg !== lastMsg && msg !== null) {
      lastMsg = msg;
      if (force || now - lastDomUpdate > YIELD_TIME) {
        elem.textContent = msg;
        lastDomUpdate = now;
      }
    }
    return yielder(force);
  };
}

const checkYield = (function () {
  let lastYield = 0;
  const pendingResolvers = [];
  const channel = new MessageChannel();

  channel.port1.onmessage = () => {
    const resolver = pendingResolvers.shift();
    if (resolver) resolver();
  };

  const yieldToMain = () =>
    new Promise((res) => {
      pendingResolvers.push(res);
      channel.port2.postMessage(null);
    });

  return function (force = false) {
    if (force || Date.now() - lastYield > YIELD_TIME) {
      lastYield = Date.now();
      return (async () => {
        if ("scheduler" in window && "yield" in scheduler) {
          await scheduler.yield();
        } else {
          await yieldToMain();
        }
      })();
    }
    return null;
  };
})();

const logProgress = createLogger(
  document.getElementById("progress"),
  checkYield,
);

window.addEventListener("beforeunload", function (e) {
  if (currentlyBusy) {
    e.preventDefault();
    return "Changes you made may not be saved."; // not that the string text matters
  }
});

navigator.storage
  .persist()
  .then((p) =>
    console.log(p ? "Storage persisted." : "Storage not persisted."),
  );

async function waitForController() {
  if (navigator.serviceWorker.controller)
    return navigator.serviceWorker.controller;
  await navigator.serviceWorker.register(SW_URL);
  const reg = await navigator.serviceWorker.ready;
  return navigator.serviceWorker.controller || reg.active;
}

async function getRegistry() {
  if (_registryCache) return _registryCache;

  // Shared to allow concurrent reads but block if writing is active.
  return await navigator.locks.request(
    "rfs_registry_lock",
    { mode: "shared" },
    async () => {
      // Double check cache after acquiring lock
      if (_registryCache) return _registryCache;
      try {
        const root = await getOpfsRoot();
        const handle = await root.getFileHandle(SYSTEM_FILE);
        const file = await handle.getFile();
        const text = await file.text();
        _registryCache = text ? JSON.parse(text) : {};
      } catch (e) {
        // If file doesn't exist or is empty
        _registryCache = {};
      }
      return _registryCache;
    },
  );
}

async function saveRegistry(registry) {
  // Update local cache immediately
  _registryCache = registry;
  await navigator.locks.request(
    "rfs_registry_lock",
    { mode: "exclusive" },
    async () => {
      const root = await getOpfsRoot();
      const handle = await root.getFileHandle(SYSTEM_FILE, { create: true });
      const writable = await handle.createWritable();
      await writable.write(JSON.stringify(registry));
      await writable.close();
    },
  );
}

async function updateRegistryEntry(name, data) {
  return navigator.locks.request(
    "rfs_registry_lock",
    { mode: "exclusive" },
    async () => {
      const root = await getOpfsRoot();
      let registry = {};

      try {
        const handle = await root.getFileHandle(SYSTEM_FILE);
        const file = await handle.getFile();
        registry = JSON.parse(await file.text());
      } catch (e) {
        registry = {};
      }

      if (data === null) {
        delete registry[name];
      } else {
        registry[name] = {
          ...(registry[name] || {}),
          ...data,
          lastModified: Date.now(),
        };
      }

      _registryCache = registry;
      const handle = await root.getFileHandle(SYSTEM_FILE, { create: true });
      const writable = await handle.createWritable();
      await writable.write(JSON.stringify(registry));
      await writable.close();

      if (navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({
          type: "INVALIDATE_CACHE",
          folderName: name,
        });
      }
    },
  );
}

async function analyzeAndImportFolder(handleOrEntry, filesArray = null) {
  setUiBusy(true);
  try {
    let isEncrypted = false;
    let isSystemExport = false;
    let pathPrefix = "";

    async function checkFile(pathParts) {
      try {
        if (filesArray) {
          const targetPath = pathParts.join("/");
          return filesArray.some(
            (f) =>
              f.webkitRelativePath.endsWith(`/${targetPath}`) ||
              f.webkitRelativePath === targetPath,
          );
        } else if (handleOrEntry.kind === "directory") {
          let cur = handleOrEntry;
          for (let i = 0; i < pathParts.length - 1; i++) {
            cur = await cur.getDirectoryHandle(pathParts[i]);
          }
          await cur.getFileHandle(pathParts[pathParts.length - 1]);
          return true;
        } else if (handleOrEntry.isDirectory) {
          return new Promise((resolve) => {
            handleOrEntry.getFile(
              pathParts.join("/"),
              { create: false },
              () => resolve(true),
              () => resolve(false),
            );
          });
        }
      } catch (e) {
        return false;
      }
    }

    if (await checkFile(["manifest.enc"])) isEncrypted = true;
    if (!isEncrypted) {
      if (await checkFile(["data", "custom", SYSTEM_FILE])) {
        isSystemExport = true;
      } else if (await checkFile(["opfs", "rfs", SYSTEM_FILE])) {
        isSystemExport = true;
      } else if (await checkFile(["custom", SYSTEM_FILE])) {
        isSystemExport = true;
        pathPrefix = "data";
      } else if (await checkFile(["rfs", SYSTEM_FILE])) {
        isSystemExport = true;
        pathPrefix = "opfs";
      } else if (await checkFile(["ls.json"])) {
        isSystemExport = true;
        pathPrefix = "data";
      }
    }

    if (isEncrypted) {
      const encName = prompt(
        `"${handleOrEntry.name || "Folder"}" appears to be an encrypted folder. Enter a name to mount it as:`,
        handleOrEntry.name,
      );
      if (!encName) return;

      if (filesArray) {
        alert(
          "Encrypted folder import via file input not supported yet. Use drag-and-drop or the directory picker.",
        );
      } else {
        if (handleOrEntry.kind === "directory") {
          await processFolderSelection(encName, handleOrEntry);
        } else {
          alert("Please use Upload Folder for encrypted folders.");
        }
      }
      return;
    }

    if (isSystemExport) {
      if (
        confirm(
          "Found system configuration folder. Import? (This may overwrite multiple folders and already existing data.)",
        )
      ) {
        let stream;
        if (filesArray) {
          stream = LittleExport.folderToTarStream(filesArray, checkYield, {
            pathPrefix,
          });
        } else {
          stream = LittleExport.folderToTarStream(handleOrEntry, checkYield, {
            pathPrefix,
          });
        }
        await startImport({ stream: () => stream });
      }
      return;
    }

    const name =
      document.getElementById("folderName").value.trim() ||
      prompt("Enter a name for the folder:", handleOrEntry.name || "");

    if (!name) return;

    if (filesArray) {
      await processFilesAndStore(name, filesArray);
    } else if (handleOrEntry.kind === "directory") {
      await processFolderSelection(name, handleOrEntry);
    } else {
      alert("Please use drag-and-drop for this folder.");
    }
  } catch (e) {
    console.error("Import error:", e);
    alert("An error occurred during import: " + e.message);
  } finally {
    setUiBusy(false); // Guarantees UI unlocks in all browsers
  }
}

async function uploadFolder() {
  try {
    if (window.showDirectoryPicker) {
      setUiBusy(true);
      const handle = await window.showDirectoryPicker({ mode: "read" });
      await analyzeAndImportFolder(handle);
    } else {
      document.getElementById("folderUploadFallbackInput").click();
    }
  } catch (e) {
    if (e.name !== "AbortError") {
      console.error(e);
      alert("Error accessing folder: " + e.message);
    }
  } finally {
    setUiBusy(false);
  }
}

async function uploadFolderFallback(e) {
  const input = e.target;
  if (!input.files.length) {
    setUiBusy(false);
    return;
  }
  await analyzeAndImportFolder({}, Array.from(input.files));
  input.value = "";
}

async function processFolderSelection(name, handle) {
  dirHandle = handle;
  folderName = name;

  try {
    const encManifest = await handle.getFileHandle("manifest.enc");
    const root = await getOpfsRoot();
    const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
    try {
      await rfs.removeEntry(name, { recursive: true });
    } catch (e) {
      if (e.name !== "NotFoundError")
        alert(
          "RuntimeFS cannot currently remove this folder; try closing other open RuntimeFS tabs.",
        );
      return;
    }

    await decryptAndLoadFolderToOpfs(
      handle,
      encManifest,
      await rfs.getDirectoryHandle(name, { create: true }),
    );
    await updateRegistryEntry(name, { encryptionType: null });
  } catch (e) {
    await processFolderStreaming(name, handle);
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
      if (!showingSync) {
        Array.from(
          document.body.getElementsByClassName("supportCheck"),
        ).forEach((elem) => (elem.style.display = "revert"));
        showingSync = true;
      }
    } catch (e) {
      console.warn("Observer failed:", e);
    }
  }

  changes.length = 0;
  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await updateRegistryEntry(name, { encryptionType: null });
  await logProgress("", true);
  setUiBusy(false);
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
      encData,
    );
    manifestData = JSON.parse(new TextDecoder().decode(decryptedManifestBytes));
  } catch (e) {
    throw new Error("Decryption failed. Wrong password?");
  }

  const contentDir = await srcHandle.getDirectoryHandle("content");
  const ENCRYPTED_CHUNK_OVERHEAD = 12 + 16;

  const entries = Object.entries(manifestData);
  const totalFiles = entries.length;
  let processedFiles = 0;

  const dirCache = new Map();
  dirCache.set(".", destDir);

  const worker = async () => {
    while (entries.length > 0) {
      const entryTask = entries.shift();
      if (!entryTask) break;
      const [originalPath, meta] = entryTask;

      const p = logProgress(
        `Decrypting (${processedFiles}/${totalFiles}): ${originalPath}`,
      );
      if (p) await p;

      const pathParts = originalPath.split("/");
      const fileName = pathParts.pop();
      let currentDir = destDir;

      if (pathParts.length > 0) {
        let pathAcc = ".";
        currentDir = await dirCache.get(".");

        for (const part of pathParts) {
          const parentPath = pathAcc;
          pathAcc += "/" + part;

          if (!dirCache.has(pathAcc)) {
            const parentDirPromise = dirCache.get(parentPath);
            const newDirPromise = parentDirPromise.then((parent) =>
              parent.getDirectoryHandle(part, { create: true }),
            );
            dirCache.set(pathAcc, newDirPromise);
          }

          // Await the promise in the cache
          currentDir = await dirCache.get(pathAcc);
        }
      }

      let srcFile;
      try {
        const handle = await contentDir.getFileHandle(meta.id);
        srcFile = await handle.getFile();
      } catch (e) {
        console.warn(`Missing file: ${originalPath}`);
        processedFiles++;
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
            const pY = checkYield();
            if (pY) await pY;

            const isLast = chunkIndex === totalEncChunks - 1;
            const plainSize = isLast
              ? meta.size % CHUNK_SIZE || CHUNK_SIZE
              : CHUNK_SIZE;
            const encSize = plainSize + ENCRYPTED_CHUNK_OVERHEAD;

            // Collect enough data for a full encrypted chunk
            while (buffer.length < encSize) {
              const { done, value } = await reader.read();
              if (done) break;
              const newBuf = new Uint8Array(buffer.length + value.length);
              newBuf.set(buffer);
              newBuf.set(value, buffer.length);
              buffer = newBuf;
            }

            if (buffer.length < encSize) break;

            const chunkData = buffer.subarray(0, encSize);
            buffer = buffer.subarray(encSize);

            const chunkIv = chunkData.subarray(0, 12);
            const chunkCipher = chunkData.subarray(12);

            const plainChunk = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: chunkIv },
              key,
              chunkCipher,
            );
            await writable.write(new Uint8Array(plainChunk));
            chunkIndex++;
          }
        } finally {
          reader.releaseLock();
        }
      }

      try {
        await writable.close();
      } catch (e) {
        if (e.name !== "TypeError") throw e;
      }
      processedFiles++;
    }
  };

  // Run in parallel
  await Promise.all(Array(CONCURRENCY).fill(null).map(worker));
  await logProgress("", true);
}

async function processFilesAndStore(name, fileList) {
  const root = await getOpfsRoot();
  const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
  try {
    await rfsRoot.removeEntry(name, { recursive: true });
  } catch (e) {}

  const destRoot = await rfsRoot.getDirectoryHandle(name, { create: true });

  let totalBytes = 0;
  for (const file of fileList) totalBytes += file.size;

  let bytesUploaded = 0;
  const queue = Array.from(fileList);

  const updateUI = () => {
    const mb = (bytesUploaded / 1e6).toFixed(2);
    const totalMb = (totalBytes / 1e6).toFixed(2);
    const pct =
      totalBytes > 0
        ? ((bytesUploaded / totalBytes) * 100).toFixed(2)
        : "100.00";

    return logProgress(`Uploading: ${pct}% (${mb} / ${totalMb} MB)`);
  };

  const worker = async () => {
    const dirCache = new Map();

    while (queue.length > 0) {
      const file = queue.shift();
      if (!file) break;

      let relativePath = file.webkitRelativePath || file.name;
      const pathParts = relativePath.split("/");
      if (pathParts.length > 1) pathParts.shift();
      relativePath = pathParts.join("/");

      // Throttle progress updates to avoid saturating the yield check
      let bytesSinceLastUI = 0;

      await writeStreamToOpfs(destRoot, relativePath, file, {
        dirCache,
        onProgress: async (delta) => {
          bytesUploaded += delta;
          bytesSinceLastUI += delta;
          if (bytesSinceLastUI > 1048576) {
            let p = updateUI();
            if (p) await p;
            bytesSinceLastUI = 0;
          }
        },
      });

      // Always check yield after a full file completion
      const p = checkYield();
      if (p) await p;
    }
  };

  const workers = Array(CONCURRENCY).fill(null).map(worker);
  await Promise.all(workers);

  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await updateRegistryEntry(name, { encryptionType: null });
  await logProgress("", true);
  await listFolders();
}

async function processFolderStreaming(name, srcHandle) {
  const root = await getOpfsRoot();
  const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true });

  try {
    await rfs.removeEntry(name, { recursive: true });
  } catch (e) {
    if (e.name !== "NotFoundError") {
      alert(
        "RuntimeFS cannot currently remove this folder; try closing other open RuntimeFS tabs.",
      );
      return;
    }
  }

  const destRoot = await rfs.getDirectoryHandle(name, { create: true });

  const uploadQueue = [];
  let scanComplete = false;
  let totalBytesDiscovered = 0;
  let bytesUploaded = 0;

  const updateUI = () => {
    const uploadedMB = (bytesUploaded / 1e6).toFixed(2);
    const totalFoundMB = (totalBytesDiscovered / 1e6).toFixed(2);

    let msg = scanComplete
      ? `Finishing: ${uploadedMB} MB / ${totalFoundMB} MB`
      : `Scanning: ${uploadedMB} MB / ${totalFoundMB} MB`;

    return logProgress(msg);
  };

  const worker = async () => {
    const dirCache = new Map();
    while (true) {
      const task = uploadQueue.shift();
      if (!task) {
        if (scanComplete) break;
        await new Promise((res) => setTimeout(res, 50));
        continue;
      }

      // Optimization: Use the file discovered by the scanner to avoid redundant getFile()
      const file = task.fileOverride;
      let bytesSinceLastUI = 0;

      await writeStreamToOpfs(task.dest, task.entry.name, file, {
        dirCache,
        onProgress: async (delta) => {
          bytesUploaded += delta;
          bytesSinceLastUI += delta;
          if (bytesSinceLastUI > 1048576) {
            let p = updateUI();
            if (p) await p;
            bytesSinceLastUI = 0;
          }
        },
      });

      const p = checkYield();
      if (p) await p;
    }
  };

  const workerPromises = Array(CONCURRENCY).fill(null).map(worker);
  const scanStack = [{ source: srcHandle, dest: destRoot }];

  while (scanStack.length > 0) {
    const { source, dest } = scanStack.shift();

    try {
      for await (const entry of source.values()) {
        if (entry.kind === "file") {
          // Scanner does the heavy lifting of opening the file
          const file = await entry.getFile();
          totalBytesDiscovered += file.size;

          uploadQueue.push({ dest, entry, fileOverride: file });
          let p = updateUI();
          if (p) await p;

          // Backpressure loop: prevent the scan from eating all RAM if I/O is slow
          while (uploadQueue.length > 500) {
            await new Promise((res) => setTimeout(res, 50));
            const p = checkYield();
            if (p) await p; // Yield while waiting!
          }
        } else if (entry.kind === "directory") {
          const nextDest = await dest.getDirectoryHandle(entry.name, {
            create: true,
          });
          scanStack.push({ source: entry, dest: nextDest });
        }
        const p = checkYield();
        if (p) await p;
      }
    } catch (e) {
      console.warn("Error reading directory stream:", e);
    }
  }

  scanComplete = true;
  await Promise.all(workerPromises);

  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await updateRegistryEntry(name, { encryptionType: null });
  await logProgress("", true);
  await listFolders();
  setUiBusy(false);
}

async function writeStreamToOpfs(parentHandle, path, fileObj, options = {}) {
  const { dirCache = null, onProgress = null } = options;
  const parts = path.split("/");
  const fileName = parts.pop();
  let currentDir = parentHandle;

  if (parts.length > 0) {
    let pathAcc = "";
    for (const part of parts) {
      pathAcc += (pathAcc ? "/" : "") + part;
      if (dirCache && dirCache.has(pathAcc)) {
        currentDir = dirCache.get(pathAcc);
      } else {
        currentDir = await currentDir.getDirectoryHandle(part, {
          create: true,
        });
        if (dirCache) dirCache.set(pathAcc, currentDir);
      }
    }
  }

  const fileHandle = await currentDir.getFileHandle(fileName, { create: true });
  const writable = await fileHandle.createWritable({ keepExistingData: false });

  try {
    if (!onProgress) {
      await writable.write(fileObj);
    } else {
      const meter = new TransformStream({
        async transform(chunk, controller) {
          controller.enqueue(chunk);
          const p = onProgress(chunk.byteLength);
          if (p) await p;
        },
      });
      await fileObj
        .stream()
        .pipeThrough(meter)
        .pipeTo(writable, { preventClose: true });
    }
  } finally {
    try {
      await writable.close();
    } catch (e) {}
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
  } finally {
    isListingFolders = false;
  }
}

async function deleteFolder(folderNameToDelete, skipConfirm = false) {
  const folderName =
    folderNameToDelete ||
    document.getElementById("deleteFolderName").value.trim();
  if (!folderName) return alert("Enter a folder name first.");
  // skipConfirm no longer used but whatever
  if (!skipConfirm && !confirm(`Remove "${folderName}"?`)) return;

  setUiBusy(true);
  logProgress("Deleting...", true);
  const root = await getOpfsRoot();
  try {
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX);
    await rfsRoot.removeEntry(folderName, { recursive: true });
  } catch (e) {
    if (e.name !== "NotFoundError") {
      alert(
        "RuntimeFS cannot currently remove this folder; try closing other open RuntimeFS tabs.",
      );
      return;
    }
  }

  await updateRegistryEntry(folderName, null);
  if (!folderNameToDelete)
    document.getElementById("deleteFolderName").value = "";
  await listFolders();
  logProgress("", true);
  if (!skipConfirm) setUiBusy(false);
}

async function openFile(overrideFolderName) {
  const folderName = (
    overrideFolderName || document.getElementById("openFolderName").value.trim()
  ).trim();
  const fileName = document.getElementById("fileName").value.trim();
  if (!folderName) return alert("Provide a folder name.");

  setUiBusy(true);
  const registry = await getRegistry();
  const meta = registry[folderName];
  if (!meta) {
    setUiBusy(false);
    return alert("Folder not found.");
  }

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
  setUiBusy(false);
}

async function exportData() {
  setUiBusy(true);

  try {
    let password = prompt(
      "Enter a password (or leave blank for no encryption):",
    );
    if (password === null) {
      // User cancelled prompt
      setUiBusy(false);
      return;
    }
    password = password || undefined; // Convert empty string to undefined

    const exportCookies = document.getElementById("c1").checked;
    const exportLS = document.getElementById("c2").checked;
    const exportIDB = document.getElementById("c3").checked;
    const exportRFS = document.getElementById("c4").checked;
    const exportOPFS = document.getElementById("c5").checked;
    const exportCache = document.getElementById("c6").checked;
    const exportSession = document.getElementById("c7").checked;

    const customItems = [];
    if (exportRFS || exportOPFS) {
      const registry = await getRegistry();
      const sanitizedRegistry = {};
      for (const [folderName, meta] of Object.entries(registry)) {
        sanitizedRegistry[folderName] = { ...meta };
      }

      customItems.push({
        path: SYSTEM_FILE,
        data: JSON.stringify(sanitizedRegistry),
      });
    }

    const exclude = { opfs: [SYSTEM_FILE, ".rfs_temp_blobs"] };
    const include = { opfs: [] };

    if (exportRFS && !exportOPFS) {
      include.opfs.push(RFS_PREFIX);
    } else if (!exportRFS && exportOPFS) {
      exclude.opfs.push(RFS_PREFIX);
    }

    let status = 2; // successful
    await LittleExport.exportData({
      fileName: "result",
      // download implied to be true
      password: password,
      cookies: exportCookies,
      localStorage: exportLS,
      idb: exportIDB,
      opfs: exportRFS || exportOPFS,
      cache: exportCache,
      session: exportSession,
      customItems: customItems,
      include: include.opfs.length > 0 ? include : {},
      exclude: exclude,
      graceful: true, // Continue on non-fatal errors
      logger: function (arg) {
        if (arg === "Export cancelled.") {
          status = 1;
        } else {
          logProgress(arg);
        }
      },
      onerror: (e) => {
        status = 0;
        console.error("Error while exporting:", e);
        alert("Error while exporting: " + e);
      },
    });
    if (status !== 1)
      alert(
        status === 2
          ? "Export complete!"
          : "Export may have failed or been incomplete.",
      );
  } catch (e) {
    console.error("Export failed:", e);
    alert("Export failed: " + e.message);
  } finally {
    setUiBusy(false);
    logProgress("", true);
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

async function startImport(sourceInput) {
  setUiBusy(true);
  _registryCache = null;
  localStorage.setItem("rfs_partial", "1"); // flag for incomplete import

  try {
    let registryInImport;
    logProgress("Starting import...", true);

    const importConfig = {
      graceful: true,
      logger: logProgress,
      onCustomItem: async (path, data) => {
        if (path === SYSTEM_FILE) {
          // Store the imported registry in memory for merging later
          registryInImport = JSON.parse(new TextDecoder().decode(data));
        }
      },
      onerror: (e) => {
        if (e.message === "A password is required to decrypt this data.") {
          alert("A password is required to decrypt this data.");
          status = 1; // user error
        } else {
          console.error(e);
          status = 0; // non-user error
          alert("Import encountered an error: " + e.message);
        }
      },
    };

    let status = 2; // successful
    importConfig.source = sourceInput;
    await LittleExport.importData(importConfig);

    logProgress("Merging metadata...", true);
    const existingRegistry = await getRegistry();
    const mergedRegistry = {
      ...existingRegistry,
      ...(registryInImport || {}),
    };

    await saveRegistry(mergedRegistry);
    await validateAndRepairRegistry();
    localStorage.removeItem("rfs_partial");
    await listFolders();
    if (status !== 1)
      alert(
        status === 2
          ? "Import complete! Reload to fix any issues."
          : "Import may have failed or been incomplete; reload to fix any issues.",
      );
  } catch (e) {
    console.error("Import failed:", e);
    alert("Import failed:", e);
  } finally {
    setUiBusy(false);
    logProgress("", true);
  }
}

async function validateAndRepairRegistry() {
  const root = await getOpfsRoot();
  const registry = await getRegistry();
  let changed = false;

  try {
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
    const diskFolderNames = [];
    for await (const name of rfsRoot.keys()) {
      diskFolderNames.push(name);
    }

    diskFolderNames.forEach((name) => {
      if (!registry[name]) {
        registry[name] = {
          created: Date.now(),
          headers: localStorage.getItem("fsHeaders") || "",
          rules: localStorage.getItem("fsRegex") || "",
        };
        changed = true;
      }
    });

    const registryNames = Object.keys(registry);
    await Promise.all(
      registryNames.map(async (name) => {
        try {
          await rfsRoot.getDirectoryHandle(name);
        } catch (e) {
          delete registry[name];
          changed = true;
        }
      }),
    );

    if (changed) await saveRegistry(registry);
  } catch (e) {
    console.warn("Repair failed:", e);
  }
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
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

let syncTimeout = -1;
async function syncFiles() {
  if (!folderName || !dirHandle)
    return alert("It seems that syncing isn't supported for your browser.");
  setUiBusy(true);
  if (changes.length > 0) {
    await performSyncToOpfs();
    document.getElementById("syncInfo").textContent = "Sync complete.";
  } else {
    document.getElementById("syncInfo").textContent = "No changes to sync.";
  }
  clearTimeout(syncTimeout);
  syncTimeout = setTimeout(
    () => (document.getElementById("syncInfo").textContent = ""),
    1000,
  );
  setUiBusy(false);
}

async function syncAndOpenFile() {
  if (!folderName || !dirHandle)
    return alert("It seems that syncing isn't supported for your browser.");
  setUiBusy(true);
  clearTimeout(syncTimeout);
  if (changes.length > 0) {
    await performSyncToOpfs();
    document.getElementById("syncInfo").textContent = "Sync complete.";
  } else {
    document.getElementById("syncInfo").textContent = "No changes to sync.";
  }
  syncTimeout = setTimeout(
    () => (document.getElementById("syncInfo").textContent = ""),
    1000,
  );
  openFile(folderName);
}

async function performSyncToOpfs() {
  console.log(`Syncing ${changes.length} changes...`);

  // Use a lock to prevent UI and SW conflict
  await navigator.locks.request(`lock_rfs_${folderName}`, async () => {
    const root = await getOpfsRoot();
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX);
    const folderHandle = await rfsRoot.getDirectoryHandle(folderName);

    // Create a copy and clear global to prevent race conditions during sync
    const processing = changes.slice(0);
    changes.length = 0;

    for (const change of processing) {
      const pathArr = change.relativePathComponents;
      if (!pathArr) continue;

      const pathStr = pathArr.join("/");
      try {
        if (change.type === "deleted") {
          let cur = folderHandle;
          const dirPath = pathArr.slice(0, -1);
          const fileName = pathArr[pathArr.length - 1];
          for (const p of dirPath) cur = await cur.getDirectoryHandle(p);
          await cur.removeEntry(fileName, { recursive: true });
        } else {
          let src = dirHandle;
          for (let i = 0; i < pathArr.length - 1; i++) {
            src = await src.getDirectoryHandle(pathArr[i]);
          }
          const fileEntry = await src.getFileHandle(
            pathArr[pathArr.length - 1],
          );
          const f = await fileEntry.getFile();
          await writeStreamToOpfs(folderHandle, pathStr, f, {
            totalSize: f.size,
          });
        }
      } catch (e) {
        console.warn(`Sync failed for ${pathStr}:`, e);
      }
    }
  });
}

async function uploadAndEncryptWithPassword() {
  const name = document.getElementById("encryptFolderName").value.trim();
  const password = prompt("Password:");
  if (!name || !password) return;

  setUiBusy(true);

  let localDir;
  try {
    localDir = await window.showDirectoryPicker({ mode: "read" });
  } catch (e) {
    if (e.name !== "AbortError") throw e;
  } finally {
    setUiBusy(false);
  }

  const root = await getOpfsRoot();
  const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });

  try {
    await rfsRoot.removeEntry(name, { recursive: true });
  } catch (e) {
    if (e.name !== "NotFoundError") {
      alert(
        "RuntimeFS cannot currently remove this folder; try closing other open RuntimeFS tabs.",
      );
      return;
    }
  }

  const destDir = await rfsRoot.getDirectoryHandle(name, { create: true });
  const contentDir = await destDir.getDirectoryHandle("content", {
    create: true,
  });

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, salt);
  const manifestData = {};

  const queue = [];
  const scanQueue = [{ dir: localDir, path: "" }];
  let scanning = true;
  let totalBytesProcessed = 0;

  const scanner = async () => {
    while (scanQueue.length > 0) {
      const { dir, path } = scanQueue.shift();
      for await (const entry of dir.values()) {
        const entryPath = path ? `${path}/${entry.name}` : entry.name;
        if (entry.kind === "file") {
          const fileId = crypto.randomUUID();
          queue.push({ entry, entryPath, fileId });
          while (queue.length > 500) {
            // handle backpressure
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
        } else {
          scanQueue.push({ dir: entry, path: entryPath });
        }
      }
    }
    scanning = false;
  };

  const worker = async () => {
    while (true) {
      if (queue.length === 0) {
        if (!scanning) break;
        const p = checkYield();
        if (p) await p;
        continue;
      }

      const task = queue.shift();
      const { entry, entryPath, fileId } = task;

      // Check yield first, then construct string
      const p = checkYield();
      if (p) {
        const mb = (totalBytesProcessed / 1e6).toFixed(2);
        await logProgress(`Encrypting: ${mb} MB (${task.entryPath})`);
        await p;
      }

      const file = await entry.getFile();
      totalBytesProcessed += file.size; // Update tracker

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
        let pendingChunks = [];
        let pendingSize = 0;

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (value) {
              pendingChunks.push(value);
              pendingSize += value.byteLength;
            }

            if (done || pendingSize >= CHUNK_SIZE) {
              if (pendingSize > 0) {
                const buffer = new Uint8Array(pendingSize);
                let offset = 0;
                for (const c of pendingChunks) {
                  buffer.set(c, offset);
                  offset += c.byteLength;
                }

                let cursor = 0;
                while (cursor < pendingSize) {
                  const remaining = pendingSize - cursor;
                  if (!done && remaining < CHUNK_SIZE) {
                    const leftover = buffer.slice(cursor);
                    pendingChunks = [leftover];
                    pendingSize = leftover.byteLength;
                    break;
                  }

                  const pSub = checkYield();
                  if (pSub) await pSub;

                  const sizeToEncrypt = Math.min(CHUNK_SIZE, remaining);
                  const chunkToEncrypt = buffer.subarray(
                    cursor,
                    cursor + sizeToEncrypt,
                  );

                  const iv = crypto.getRandomValues(new Uint8Array(12));
                  const encryptedChunk = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv },
                    key,
                    chunkToEncrypt,
                  );

                  cursor += sizeToEncrypt;
                  await writable.write(iv);
                  await writable.write(new Uint8Array(encryptedChunk));
                }

                if (cursor >= pendingSize) {
                  pendingChunks = [];
                  pendingSize = 0;
                }
              }
            }
            if (done) break;
          }
        } finally {
          reader.releaseLock();
          try {
            await writable.close();
          } catch (e) {}
        }
      } else {
        await writable.close();
      }
    }
  };

  const scanPromise = scanner();
  const workers = Array(CONCURRENCY).fill(null).map(worker);

  await scanPromise;
  await Promise.all(workers);

  await logProgress("Saving manifest...", true);

  const manifestJson = JSON.stringify(manifestData);
  const manifestBuffer = new TextEncoder().encode(manifestJson);
  const manifestIv = crypto.getRandomValues(new Uint8Array(12));
  const encManifest = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: manifestIv },
    key,
    manifestBuffer,
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
  setUiBusy(false);
  await logProgress("", true);
}

document.addEventListener("DOMContentLoaded", () => {
  if (window.location.protocol === "file:") {
    alert(
      "RuntimeFS cannot run from a local file:// context; use an online version or test from localhost instead.",
    );
    return;
  }
  if (!window.isSecureContext) {
    alert("RuntimeFS cannot run in a non-secure context.");
    return;
  } else if (!("serviceWorker" in navigator)) {
    alert("RuntimeFS cannot run without ServiceWorkers enabled.");
    return;
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

  if (window.showSaveFilePicker) {
    document.getElementById("encryptionSection").style.display = "revert";
  }

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

    const items = Array.from(e.dataTransfer.items);
    if (!items.length) return;

    if (items[0].kind === "file" && window.FileSystemDirectoryHandle) {
      try {
        const handle = await items[0].getAsFileSystemHandle();
        if (handle && handle.kind === "directory") {
          await analyzeAndImportFolder(handle);
          return;
        }
      } catch (e) {
        console.warn(
          "FileSystemHandle access denied, falling back to webkitGetAsEntry",
        );
      }
    }

    const entry = items[0].webkitGetAsEntry
      ? items[0].webkitGetAsEntry()
      : null;

    if (entry && entry.isDirectory) {
      const name = prompt("Please choose a folder name:", entry.name);
      if (name) {
        setUiBusy(true);
        // Scan iteratively
        const files = [];
        const queue = [{ entry, path: "" }];

        let scannedCount = 0;
        let isSystem = false;
        let isEncrypted = false;
        let pathPrefix = "";

        while (queue.length > 0) {
          const { entry: curr, path } = queue.shift();

          if (curr.isFile) {
            const f = await new Promise((res, rej) => curr.file(res, rej));
            Object.defineProperty(f, "webkitRelativePath", {
              value: path + f.name,
            });
            files.push(f);

            // Check during scan
            const rel = f.webkitRelativePath;
            if (rel.endsWith(`data/custom/${SYSTEM_FILE}`)) {
              isSystem = true;
            } else if (rel.endsWith(`custom/${SYSTEM_FILE}`)) {
              isSystem = true;
              pathPrefix = "data";
            } else if (rel === "ls.json" || rel.endsWith("/ls.json")) {
              // Heuristic: if ls.json
              const parts = rel.split("/");
              if (
                parts.length === 1 ||
                (parts.length === 2 && parts[0] === entry.name)
              ) {
                isSystem = true;
                pathPrefix = "data";
              }
            }
            if (rel.endsWith("manifest.enc")) {
              isEncrypted = true;
            }

            scannedCount++;
          } else if (curr.isDirectory) {
            const reader = curr.createReader();
            let batch;
            do {
              batch = await new Promise((res, rej) =>
                reader.readEntries(res, rej),
              );
              for (const child of batch) {
                queue.push({
                  entry: child,
                  path: path + curr.name + "/",
                });
              }
            } while (batch.length > 0);
          }

          let p = logProgress(`Scanned ${scannedCount} files...`);
          if (p) await p;
        }

        if (isEncrypted) {
          alert(
            "Encrypted folder import via drag-and-drop legacy mode is not supported in your browser.",
          );
          setUiBusy(false);
          return;
        }

        if (isSystem) {
          if (
            confirm(
              "Found system configuration folder. Import? (This may overwrite multiple folders and already existing data.)",
            )
          ) {
            const stream = LittleExport.folderToTarStream(files, checkYield, {
              pathPrefix,
            });
            await startImport({ stream: () => stream });
            setUiBusy(false);
            return;
          } else {
            setUiBusy(false);
          }
        }

        await logProgress(`Processed ${files.length} files...`, true);
        await processFilesAndStore(name, files);
        setUiBusy(false);
      }
      return;
    }

    const first = items[0].getAsFile();
    if (items.length === 1 && first) {
      if (confirm(`Import "${first.name}"?`)) startImport(first);
    }
  });

  navigator.serviceWorker
    .register(SW_URL)
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
  navigator.serviceWorker.addEventListener("message", async (e) => {
    if (e.data && e.data.type === "SW_READY") await listFolders();
    if (e.data && e.data.type === "INVALIDATE_CACHE") await listFolders();
  });

  if (localStorage.getItem("rfs_partial")) {
    validateAndRepairRegistry().then(() => {
      localStorage.removeItem("rfs_partial");
      listFolders();
    });
  }

  listFolders();

  const rT = document.getElementById("regex");
  const hT = document.getElementById("headers");
  rT.value = localStorage.getItem("fsRegex") || "";
  hT.value = localStorage.getItem("fsHeaders") || "";
  rT.addEventListener("input", () => localStorage.setItem("fsRegex", rT.value));
  hT.addEventListener("input", () =>
    localStorage.setItem("fsHeaders", hT.value),
  );
});

async function openFileInPlace() {
  if (!navigator.serviceWorker.controller) {
    alert(
      "Service Worker is not controlling the page. Please reload and try again.",
    );
    return;
  }
  const folderName = document.getElementById("openFolderName").value.trim();
  const fileName = document.getElementById("fileName").value.trim();
  if (!folderName) return alert("Provide a folder name.");

  setUiBusy(true);
  const registry = await getRegistry();
  const meta = registry[folderName];
  if (!meta) {
    setUiBusy(false);
    return alert("Folder not found.");
  }

  const rules = document.getElementById("regex").value.trim();
  const headers = document.getElementById("headers").value.trim();

  if (meta.rules !== rules || meta.headers !== headers) {
    await updateRegistryEntry(folderName, { rules, headers });
  }

  let key = null;
  if (meta.encryptionType === "password") {
    const password = prompt(`Enter password for "${folderName}":`);
    if (!password) {
      return setUiBusy(false);
    }
    key = await deriveKeyFromPassword(password, base64ToBuffer(meta.salt));
  }

  const sw = await waitForController();
  // Wrap SW communication in a race to prevent hanging
  await Promise.race([
    new Promise((resolve) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => resolve();
      sw.postMessage({ type: "SET_RULES", rules, headers, key, folderName }, [
        channel.port2,
      ]);
    }),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("Service Worker response timed out.")),
        4000,
      ),
    ),
  ]);

  const encodedPath = fileName
    ? fileName.split("/").map(encodeURIComponent).join("/")
    : "index.html";
  const virtualUrl = `n/${encodeURIComponent(folderName)}/${encodedPath}`;

  const resp = await fetch(virtualUrl, {
    headers: { Accept: "text/html" },
  });

  if (!resp.ok) {
    if (resp.status === 403) {
      setUiBusy(false);
      return alert("Session authentication failed.");
    }
    throw new Error(`Failed to load HTML: ${resp.status} ${resp.statusText}`);
  }
  let html = await resp.text();

  const basePath = virtualUrl.substring(0, virtualUrl.lastIndexOf("/") + 1);
  const baseTag = `<base href="${basePath}">`;

  let metaTags = "";
  resp.headers.forEach((val, key) => {
    metaTags += `<meta http-equiv="${key.replace(
      /"/g,
      "&quot;",
    )}" content="${val.replace(/"/g, "&quot;")}">\n`;
  });

  if (/<head\b[^>]*>/i.test(html)) {
    html = html.replace(/(<head\b[^>]*>)/i, `$1${baseTag}${metaTags}`);
  } else if (/<html\b[^>]*>/i.test(html)) {
    html = html.replace(
      /(<html\b[^>]*>)/i,
      `$1<head>${baseTag}${metaTags}</head>`,
    );
  } else {
    html = `<head>${baseTag}${metaTags}</head>${html}`;
  }

  document.open();
  document.write(html);
  document.close();
  setUiBusy(false);
}
