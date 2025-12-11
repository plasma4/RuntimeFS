const SW_LINK = "./sw.min.js"; // Change if needed!
const RFS_PREFIX = "rfs";
const SYSTEM_FILE = "rfs_system.json";
const CHUNK_SIZE = 4 * 1024 * 1024;

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
    return {}; // Default empty registry
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
  const reg = await getRegistry();
  if (data === null) {
    delete reg[name];
  } else {
    reg[name] = { ...reg[name], ...data, lastModified: Date.now() };
  }
  await saveRegistry(reg);
  // Notify SW to invalidate its memory cache
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
  if (!password) throw new Error("Password required for decryption.");

  const manifestFile = await manifestHandle.getFile();
  const manifestBuf = await manifestFile.arrayBuffer();

  // Format: Salt (16) + IV (12) + EncryptedData
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
    const decoder = new TextDecoder();
    manifestData = JSON.parse(decoder.decode(decryptedManifestBytes));
  } catch (e) {
    throw new Error("Decryption failed. Wrong password?");
  }

  const progressElem = document.getElementById("progress");
  const updateProgress = createProgressThrottle(progressElem);

  let contentDir;
  try {
    contentDir = await srcHandle.getDirectoryHandle("content");
  } catch (e) {
    throw new Error(
      "Invalid encrypted folder structure: 'content' folder missing."
    );
  }

  // Constants must match uploader
  const ENCRYPTED_CHUNK_OVERHEAD = 12 + 16; // IV (12) + Tag (16)

  const entries = Object.entries(manifestData);
  let processed = 0;

  for (const [originalPath, meta] of entries) {
    updateProgress(`Decrypting: ${originalPath}`);

    // Reconstruct directory structure in OPFS
    const pathParts = originalPath.split("/");
    const fileName = pathParts.pop();
    let currentDir = destDir;
    for (const part of pathParts) {
      currentDir = await currentDir.getDirectoryHandle(part, { create: true });
    }

    // Get source encrypted file
    let srcFile;
    try {
      const handle = await contentDir.getFileHandle(meta.id);
      srcFile = await handle.getFile();
    } catch (e) {
      console.warn(`Missing encrypted file for ${originalPath} (${meta.id})`);
      continue;
    }

    const destFileHandle = await currentDir.getFileHandle(fileName, {
      create: true,
    });
    const writable = await destFileHandle.createWritable();

    if (meta.size > 0) {
      const srcBuffer = await srcFile.arrayBuffer();
      const totalEncChunks = Math.ceil(meta.size / CHUNK_SIZE);

      let offset = 0;
      for (let i = 0; i < totalEncChunks; i++) {
        // Calculate expected encrypted chunk size
        const isLast = i === totalEncChunks - 1;
        const plainSize = isLast
          ? meta.size % CHUNK_SIZE || CHUNK_SIZE
          : CHUNK_SIZE;
        const encSize = plainSize + ENCRYPTED_CHUNK_OVERHEAD;

        const chunkData = srcBuffer.slice(offset, offset + encSize);
        offset += encSize;

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
          console.error(`Error decrypting chunk for ${originalPath}`);
        }
      }
    }
    await writable.close();

    processed++;
    if (processed % 10 === 0) await new Promise((r) => setTimeout(r, 0)); // Yield
  }

  progressElem.textContent = "";
}

async function processFileListAndStore(name, fileList) {
  const progressElem = document.getElementById("progress");
  const updateProgress = createProgressThrottle(progressElem);

  try {
    if (!fileList.length) return;
    const root = await getOpfsRoot();
    const rfsRoot = await root.getDirectoryHandle(RFS_PREFIX, { create: true });

    try {
      await rfsRoot.removeEntry(name, { recursive: true });
      // Yield to ensure the handle deletion propagates
      await new Promise((r) => setTimeout(r, 50));
    } catch (e) {
      if (e.name !== "NotFoundError") console.warn("RemoveEntry warning:", e);
    }

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

    let lastYieldTime = Date.now();

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      let path = file.webkitRelativePath || file.name;
      if (basePath && path.startsWith(basePath))
        path = path.substring(basePath.length);
      if (!path) continue;

      updateProgress(`Processing ${path}`);

      if (Date.now() - lastYieldTime > 100) {
        await new Promise((r) => setTimeout(r, 0));
        lastYieldTime = Date.now();
      }

      await writeStreamToOpfs(folderHandle, path, file.stream());
    }

    await updateRegistryEntry(name, { encryptionType: null });

    document.getElementById("folderName").value = "";
    document.getElementById("openFolderName").value = name;
    await listFolders();
  } catch (e) {
    console.error(e);
    alert("Error: " + e.message);
  } finally {
    progressElem.textContent = "";
  }
}

async function processAndStoreFolderStreaming(name, srcHandle) {
  const progressElem = document.getElementById("progress");
  const updateProgress = createProgressThrottle(progressElem);

  const root = await getOpfsRoot();
  const rfs = await root.getDirectoryHandle(RFS_PREFIX, { create: true });
  try {
    await rfs.removeEntry(name, { recursive: true });
  } catch (e) {}
  const destRoot = await rfs.getDirectoryHandle(name, { create: true });

  updateProgress("Scanning files...");
  const files = []; // { entry, pathParts }
  const dirs = []; // pathParts (array of strings)

  async function scan(dir, pathParts) {
    for await (const entry of dir.values()) {
      if (entry.kind === "file") {
        files.push({ entry, pathParts });
      } else if (entry.kind === "directory") {
        const newPath = [...pathParts, entry.name];
        dirs.push(newPath);
        await scan(entry, newPath);
      }
    }
  }
  await scan(srcHandle, []);

  updateProgress(`Creating ${dirs.length} folders...`);
  for (const parts of dirs) {
    let curr = destRoot;
    for (const p of parts)
      curr = await curr.getDirectoryHandle(p, { create: true });
  }

  updateProgress(`Uploading ${files.length} files...`);
  let completed = 0;
  const total = files.length;

  let fileIdx = 0;
  async function worker() {
    let lastPathStr = null;
    let lastDirHandle = null;

    while (fileIdx < total) {
      const i = fileIdx++;
      const { entry, pathParts } = files[i];

      // Re-use handle if in same directory
      const currentPathStr = pathParts.join("/");
      let dir;

      if (lastPathStr === currentPathStr && lastDirHandle) {
        dir = lastDirHandle;
      } else {
        // Traverse only if path changed
        dir = destRoot;
        for (const p of pathParts) dir = await dir.getDirectoryHandle(p);
        lastDirHandle = dir;
        lastPathStr = currentPathStr;
      }

      const file = await entry.getFile();
      const dstFile = await dir.getFileHandle(entry.name, { create: true });
      const w = await dstFile.createWritable();
      await file.stream().pipeTo(w);

      updateProgress(`Uploading: ${Math.round((completed / total) * 100)}%`);
    }
  }

  // Run 4 concurrent workers (arbitrary choice), TODO figure out a better approach
  await Promise.all(Array(4).fill(null).map(worker));

  await updateRegistryEntry(name, { encryptionType: null });
  progressElem.textContent = "";

  // UI cleanup
  document.getElementById("folderName").value = "";
  document.getElementById("openFolderName").value = name;
  await listFolders();
}

async function writeStreamToOpfs(parentHandle, path, stream) {
  const parts = path.split("/");
  const fileName = parts.pop();

  try {
    let currentDir = parentHandle;
    // Traverse/Create subdirectories
    for (const part of parts) {
      currentDir = await currentDir.getDirectoryHandle(part, { create: true });
    }

    const fileHandle = await currentDir.getFileHandle(fileName, {
      create: true,
    });
    const writable = await fileHandle.createWritable();
    await stream.pipeTo(writable);
  } catch (e) {
    // Retry once for InvalidStateError (Stale handle)
    if (e.name === "InvalidStateError") {
      console.warn("Retrying write due to stale handle:", path);
      await new Promise((r) => setTimeout(r, 50)); // Wait for state to settle

      // Re-traverse from parent
      let retryDir = parentHandle;
      for (const part of parts) {
        retryDir = await retryDir.getDirectoryHandle(part, { create: true });
      }
      const retryFile = await retryDir.getFileHandle(fileName, {
        create: true,
      });
      const retryWritable = await retryFile.createWritable();
      await stream.pipeTo(retryWritable);
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

      sw.postMessage(
        {
          type: "SET_RULES",
          rules,
          headers,
          key,
        },
        [channel.port2]
      );
    });

    window.open(
      `n/${encodeURIComponent(folderName)}/${fileName
        .split("/")
        .map(encodeURIComponent)
        .join("/")}`,
      "_blank"
    );
  } catch (e) {
    alert("Error: " + e);
  } finally {
    setUiBusy(false);
  }
}

async function executeRuntimeFSImport(file) {
  setUiBusy(true);
  const progressElem = document.getElementById("progress");

  try {
    const root = await navigator.storage.getDirectory();
    try {
      await root.removeEntry(RFS_PREFIX, { recursive: true });
      await root.removeEntry(SYSTEM_FILE);
    } catch (e) {}

    await LittleExport.importData(file, {
      logger: (msg) => {
        if (progressElem) progressElem.textContent = msg;
        console.log(msg);
      },
      onCustomItem: async (path, data) => {
        // Restore Registry
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
    location.reload(); // Reload to refresh folder lists and state
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

      customItems: [{ path: SYSTEM_FILE, data: JSON.stringify(registry) }],
      exclude: {
        opfs: [SYSTEM_FILE], // Don't export the raw registry file
      },

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
    if (e.target.files[0]) executeRuntimeFSImport(e.target.files[0]);
  };
  input.click();
}

function createProgressThrottle(element) {
  let lastTime = 0;
  return async function (text) {
    const now = Date.now();
    if (now - lastTime > 100) {
      lastTime = now;
      element.textContent = text;
      await new Promise((r) => setTimeout(r, 0));
    }
  };
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

// Fallback upload (manual selection)
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

// Sync Logic
async function syncFiles() {
  if (!folderName || !dirHandle) return alert("Upload a folder first.");
  setUiBusy(true);
  if (changes.length > 0) {
    await performSyncToOpfs();
    alert("Sync complete.");
  } else {
    alert("No changes detected.");
  }
  setUiBusy(false);
}

async function syncAndOpenFile() {
  if (!folderName || !dirHandle) return alert("Upload a folder first.");
  setUiBusy(true);
  if (changes.length > 0) await performSyncToOpfs();
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
        } catch (e) {
          // Ignore if already gone
        }
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
          console.warn(`Could not find source file for sync: ${pathStr}`);
          continue;
        }

        if (srcHandle.kind === "file") {
          const f = await srcHandle.getFile();
          await writeStreamToOpfs(folderHandle, pathStr, f.stream());
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
  const updateProgress = createProgressThrottle(progressElem);

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
          updateProgress(`Encrypting: ${entryPath}`);

          const fileId = crypto.randomUUID();
          const file = await entry.getFile();
          const size = file.size;

          manifestData[entryPath] = { id: fileId, size: size, type: file.type };

          const destFileHandle = await contentDir.getFileHandle(fileId, {
            create: true,
          });
          const writable = await destFileHandle.createWritable();

          // Handle 0-byte files: create file but write no chunks
          if (size > 0) {
            const buffer = await file.arrayBuffer();
            const totalChunks = Math.ceil(size / CHUNK_SIZE);

            for (let i = 0; i < totalChunks; i++) {
              const start = i * CHUNK_SIZE;
              const end = Math.min(start + CHUNK_SIZE, size);
              const chunk = buffer.slice(start, end);

              const iv = crypto.getRandomValues(new Uint8Array(12));
              // AES-GCM tag is appended automatically to ciphertext
              const encryptedChunk = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv },
                key,
                chunk
              );

              // Format: [IV (12)] [Ciphertext + Tag]
              await writable.write(iv);
              await writable.write(new Uint8Array(encryptedChunk));
            }
          }
          await writable.close();
        } else {
          await processHandle(entry, entryPath);
        }
      }
    }

    await processHandle(localDir, "");

    updateProgress("Saving manifest...");
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

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  function setupServiceWorkerListeners() {
    if (!("serviceWorker" in navigator)) return;

    navigator.serviceWorker
      .register(SW_LINK)
      .then((reg) => {
        // Check for updates
        reg.addEventListener("updatefound", () => {
          const newWorker = reg.installing;
          newWorker.addEventListener("statechange", () => {
            if (
              newWorker.state === "installed" &&
              navigator.serviceWorker.controller
            ) {
              // New version installed, reload to activate it
              console.log("New version available. Reloading...");
              location.reload();
            }
          });
        });

        if (reg.active && !navigator.serviceWorker.controller) {
          console.log("SW active but not controlling. Waiting for claim...");
        }
      })
      .catch(console.error);

    navigator.serviceWorker.addEventListener("message", async (event) => {
      if (event.data && event.data.type === "SW_READY") {
        console.log("SW: Ready signal received.");
        await listFolders();
      }
      if (event.data && event.data.type === "INVALIDATE_CACHE") {
        await listFolders();
      }
    });
  }

  // Event Listeners
  document
    .getElementById("folderName")
    .addEventListener(
      "keydown",
      (e) => e.key === "Enter" && !currentlyBusy && uploadFolder()
    );
  document
    .getElementById("openFolderName")
    .addEventListener(
      "keydown",
      (e) => e.key === "Enter" && !currentlyBusy && openFile()
    );
  document
    .getElementById("fileName")
    .addEventListener(
      "keydown",
      (e) => e.key === "Enter" && !currentlyBusy && openFile()
    );
  document
    .getElementById("deleteFolderName")
    .addEventListener(
      "keydown",
      (e) => e.key === "Enter" && !currentlyBusy && deleteFolder()
    );
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
      if (confirm(`Import "${first.name}"?`)) executeRuntimeFSImport(first);
      return;
    }

    const entry = items[0].webkitGetAsEntry();
    if (entry.isDirectory) {
      const name = prompt("Please choose a folder name:", entry.name);
      if (name) {
        setUiBusy(true);
        // Need manual scan for DnD entry
        const scan = async (ent, p) => {
          if (ent.isFile) {
            const f = await new Promise((res, rej) => ent.file(res, rej));
            Object.defineProperty(f, "webkitRelativePath", {
              value: p + f.name,
            });
            return [f];
          } else if (ent.isDirectory) {
            const r = ent.createReader();
            let files = [];
            let batch;
            do {
              batch = await new Promise((res, rej) => r.readEntries(res, rej));
              for (const c of batch)
                files.push(...(await scan(c, p + ent.name + "/")));
            } while (batch.length > 0);
            return files;
          }
        };
        const files = await scan(entry, "");
        await processFileListAndStore(name, files);
      }
    }
  });

  setupServiceWorkerListeners();
  listFolders();

  // Restore textareas
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
});
