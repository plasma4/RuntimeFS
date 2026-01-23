(function () {
  let blobIdCounter = 0;
  // stolen from my FractalSky code
  const fastScheduler = (function () {
    if ("scheduler" in window && "postTask" in scheduler) {
      return (cb) => scheduler.postTask(cb, { priority: "user-blocking" });
    }
    const channel = new MessageChannel();
    const queue = [];
    channel.port1.onmessage = () => {
      const task = queue.shift();
      if (task) task();
    };
    return (cb) => {
      queue.push(cb);
      channel.port2.postMessage(undefined);
    };
  })();

  const yieldToMain = () => new Promise((resolve) => fastScheduler(resolve));

  const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();
  const TEMP_BLOB_DIR = ".rfs_temp_blobs"; // Hidden temp dir for IDB restoration

  async function deriveKey(password, salt) {
    const km = await crypto.subtle.importKey(
      "raw",
      ENC.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      km,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  function isAllowed(category, path, config) {
    if (
      config.exclude?.[category]?.some(
        (t) => path === t || path.startsWith(t + "/"),
      )
    )
      return false;
    if (config.include?.[category]?.length > 0) {
      return config.include[category].some(
        (t) => path === t || path.startsWith(t + "/"),
      );
    }
    return true;
  }

  function prepForCBOR(item, externalBlobs) {
    if (!item || typeof item !== "object") return item;
    if (item instanceof Blob) {
      const id = (blobIdCounter++).toString(36); // Fast, short ID
      externalBlobs.push({ uuid: id, blob: item });
      return { __le_blob_ref: id, type: item.type, size: item.size };
    }

    if (item instanceof ArrayBuffer || ArrayBuffer.isView(item)) {
      return item;
    }

    if (item instanceof Date || item instanceof RegExp) {
      return item;
    }

    if (Array.isArray(item)) {
      const len = item.length;
      const res = new Array(len);
      for (let i = 0; i < len; i++) {
        res[i] = prepForCBOR(item[i], externalBlobs);
      }
      return res;
    }

    const res = {};
    for (const k in item) {
      res[k] = prepForCBOR(item[k], externalBlobs);
    }
    return res;
  }

  async function restoreFromCBOR(item, tempBlobDir) {
    if (!item || typeof item !== "object") return item;
    if (item.__le_blob_ref) {
      try {
        const fh = await tempBlobDir.getFileHandle(item.__le_blob_ref);
        const file = await fh.getFile();
        // Use slice to set the correct MIME type without wrapping the Blob in another Blob
        return file.slice(0, file.size, item.type);
      } catch (e) {
        console.warn("Missing blob ref:", item.__le_blob_ref);
        return null;
      }
    }
    if (item.__le_blob) {
      return new Blob([item.data], { type: item.type });
    }
    if (Array.isArray(item)) {
      return Promise.all(item.map((i) => restoreFromCBOR(i, tempBlobDir)));
    }
    if (item.constructor === Object) {
      const n = {};
      for (const k in item) {
        n[k] = await restoreFromCBOR(item[k], tempBlobDir);
      }
      return n;
    }
    return item;
  }

  const HEADER_TEMPLATE = new Uint8Array(512);
  (function initTemplate() {
    const enc = new TextEncoder();
    // Pre-fill constant "000664 \0", "000000 \0", "ustar\0", "00"
    enc.encodeInto("000664 \0", HEADER_TEMPLATE.subarray(100, 108));
    enc.encodeInto("000000 \0", HEADER_TEMPLATE.subarray(108, 116));
    enc.encodeInto("000000 \0", HEADER_TEMPLATE.subarray(116, 124));
    enc.encodeInto("        ", HEADER_TEMPLATE.subarray(148, 156)); // Checksum placeholder
    enc.encodeInto("ustar\0", HEADER_TEMPLATE.subarray(257, 263));
    enc.encodeInto("00", HEADER_TEMPLATE.subarray(263, 265));
  })();

  function createTarHeader(filename, size, time, isDir = false) {
    const buffer = HEADER_TEMPLATE.slice(0);

    // Calculate byte size first to prevent buffer overflow/corruption
    let nameBytes = ENC.encode(filename);
    let prefixBytes = new Uint8Array(0);

    if (nameBytes.length > 100) {
      // Find a split point based on BYTES, not characters
      let splitIndex = -1;
      for (let i = 0; i < filename.length; i++) {
        if (filename.charCodeAt(i) === 47) {
          // Check bytes of the prefix (0 to i)
          const prefixCandidate = filename.slice(0, i);
          const nameCandidate = filename.slice(i + 1);

          const pLen = ENC.encode(prefixCandidate).byteLength;
          const nLen = ENC.encode(nameCandidate).byteLength;

          if (pLen <= 155 && nLen <= 100) {
            splitIndex = i;
          }
        }
      }

      if (splitIndex !== -1) {
        const prefixStr = filename.slice(0, splitIndex);
        const nameStr = filename.slice(splitIndex + 1);
        prefixBytes = ENC.encode(prefixStr);
        nameBytes = ENC.encode(nameStr);
      } else {
        console.warn("Filename too long for USTAR:", filename);
        nameBytes = nameBytes.slice(0, 100);
      }
    }

    const writeStr = (strOrBytes, offset, len) => {
      const dest = buffer.subarray(offset, offset + len);
      if (typeof strOrBytes === "string") {
        ENC.encodeInto(strOrBytes, dest);
      } else {
        // It's already Uint8Array
        for (let i = 0; i < Math.min(len, strOrBytes.length); i++) {
          dest[i] = strOrBytes[i];
        }
      }
    };

    const writeOctal = (num, offset, len) => {
      let i = offset + len - 1;
      buffer[i] = 0;
      i--;
      if (num < 2147483647) {
        while (i >= offset) {
          buffer[i] = (num & 7) + 48;
          num >>>= 3;
          i--;
        }
      } else {
        while (i >= offset) {
          buffer[i] = (num % 8) + 48;
          num = Math.floor(num / 8);
          i--;
        }
      }
    };

    // Pass the pre-calculated bytes to avoid re-encoding
    writeStr(nameBytes, 0, 100);
    writeOctal(0o664, 100, 8);
    writeOctal(0, 108, 8);
    writeOctal(0, 116, 8);
    writeOctal(size, 124, 12);
    writeOctal(time, 136, 12);
    writeStr("        ", 148, 8);
    buffer[156] = isDir ? 53 : 48;
    writeStr("ustar", 257, 6);
    writeStr("00", 263, 2);
    if (prefixBytes.length > 0) writeStr(prefixBytes, 345, 155);

    let sum = 0;
    for (let i = 0; i < 512; i++) sum += buffer[i];
    writeOctal(sum, 148, 7);
    return buffer;
  }

  class TarWriter {
    constructor(writableStream) {
      this.writer = writableStream.getWriter();
      this.pos = 0;
      this.bytesWritten = 0;
      this.time = Math.floor(Date.now() / 1000);
    }
    async writeEntry(path, data) {
      const bytes = typeof data === "string" ? ENC.encode(data) : data;
      const header = createTarHeader(path, bytes.length, this.time);
      const paddingLen = (512 - ((this.pos + 512 + bytes.length) % 512)) % 512;
      const totalLen = 512 + bytes.length + paddingLen;
      const combined = new Uint8Array(totalLen);

      combined.set(header, 0);
      combined.set(bytes, 512);
      await this.write(combined);
    }
    async writeStream(path, size, readableStream) {
      await this.write(createTarHeader(path, size, this.time));
      await readableStream.pipeTo(
        new WritableStream({
          write: async (chunk) => {
            await this.write(chunk);
          },
        }),
      );
      await this.pad();
    }
    async write(chunk) {
      await this.writer.write(chunk);
      this.pos += chunk.byteLength;
      this.bytesWritten += chunk.byteLength;
    }
    async pad() {
      const padding = (512 - (this.pos % 512)) % 512;
      if (padding > 0) await this.write(new Uint8Array(padding));
    }
    async close() {
      await this.write(new Uint8Array(1024));
      await this.writer.close();
    }
  }

  class EncryptionTransformer {
    constructor(password, salt) {
      this.salt = salt;
      this.keyPromise = deriveKey(password, salt);
      this.pending = new Uint8Array(0);
    }
    async start(controller) {
      controller.enqueue(ENC.encode("LE_ENC"));
      controller.enqueue(this.salt);
      // Empty block for alignment/reserved
      await this.encryptAndPush(
        new Uint8Array(0),
        controller,
        await this.keyPromise,
      );
    }
    async transform(chunk, controller) {
      const key = await this.keyPromise;
      const newPending = new Uint8Array(this.pending.length + chunk.length);
      newPending.set(this.pending);
      newPending.set(chunk, this.pending.length);
      this.pending = newPending;

      while (this.pending.length >= CHUNK_SIZE) {
        const slice = this.pending.slice(0, CHUNK_SIZE);
        this.pending = this.pending.slice(CHUNK_SIZE);
        await this.encryptAndPush(slice, controller, key);
      }
    }
    async flush(controller) {
      if (this.pending.length > 0) {
        await this.encryptAndPush(
          this.pending,
          controller,
          await this.keyPromise,
        );
      }
    }
    async encryptAndPush(data, controller, key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data,
      );
      const lenParams = new DataView(new ArrayBuffer(4));
      lenParams.setUint32(0, ciphertext.byteLength, true);
      controller.enqueue(iv);
      controller.enqueue(new Uint8Array(lenParams.buffer));
      controller.enqueue(new Uint8Array(ciphertext));
    }
  }

  // A zero-copy-friendly buffer that manages a queue of chunks
  class ChunkBuffer {
    constructor() {
      this.chunks = [];
      this.totalSize = 0;
    }
    push(chunk) {
      if (!chunk || chunk.byteLength === 0) return;
      this.chunks.push(chunk);
      this.totalSize += chunk.byteLength;
    }
    has(n) {
      return this.totalSize >= n;
    }
    read(n) {
      if (n === 0) return new Uint8Array(0);
      if (this.totalSize < n) throw new Error("Insufficient data in buffer");
      if (this.chunks[0].byteLength >= n) {
        const result = this.chunks[0].subarray(0, n);
        if (this.chunks[0].byteLength === n) this.chunks.shift();
        else this.chunks[0] = this.chunks[0].subarray(n);
        this.totalSize -= n;
        return result;
      }
      const result = new Uint8Array(n);
      let offset = 0;
      while (offset < n) {
        const chunk = this.chunks[0];
        const remaining = n - offset;
        const toCopy = Math.min(chunk.byteLength, remaining);
        result.set(chunk.subarray(0, toCopy), offset);
        offset += toCopy;
        this.totalSize -= toCopy;
        if (toCopy === chunk.byteLength) this.chunks.shift();
        else this.chunks[0] = chunk.subarray(toCopy);
      }
      return result;
    }
  }

  class DecryptionSource {
    constructor(readableStream, password) {
      this.stream = readableStream;
      this.password = password;
      this.buffer = new ChunkBuffer();
    }
    readable() {
      const self = this;
      let reader;
      async function ensure(n) {
        while (!self.buffer.has(n)) {
          const { value, done } = await reader.read();
          if (done) return false;
          self.buffer.push(value);
        }
        return true;
      }
      return new ReadableStream({
        async start(controller) {
          reader = self.stream.getReader();
          try {
            if (!(await ensure(22))) throw new Error("File too small");
            const sig = new TextDecoder().decode(self.buffer.read(6));
            if (sig !== "LE_ENC") throw new Error("Not an encrypted archive");

            const salt = self.buffer.read(16);
            const key = await deriveKey(self.password, salt);

            if (!(await ensure(16))) throw new Error("Corrupt header");
            const initIV = self.buffer.read(12);
            const initLenRaw = self.buffer.read(4);
            const initLen = new DataView(
              initLenRaw.buffer,
              initLenRaw.byteOffset,
              initLenRaw.byteLength,
            ).getUint32(0, true);

            if (!(await ensure(initLen))) throw new Error("Corrupt header");
            const initCipher = self.buffer.read(initLen);
            try {
              await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: initIV },
                key,
                initCipher,
              );
            } catch (e) {
              throw new Error("Incorrect password or corrupt file.");
            }

            while (true) {
              if (!self.buffer.has(16)) {
                const { value, done } = await reader.read();
                if (done) {
                  if (self.buffer.totalSize === 0) break;
                  throw new Error("Truncated encrypted stream");
                }
                self.buffer.push(value);
                continue;
              }
              const iv = self.buffer.read(12);
              const lenRaw = self.buffer.read(4);
              const lenVal = new DataView(
                lenRaw.buffer,
                lenRaw.byteOffset,
                lenRaw.byteLength,
              ).getUint32(0, true);

              while (!self.buffer.has(lenVal)) {
                const { value, done } = await reader.read();
                if (done) throw new Error("Unexpected EOF in ciphertext");
                self.buffer.push(value);
              }
              const cipher = self.buffer.read(lenVal);
              const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                cipher,
              );
              controller.enqueue(new Uint8Array(plain));
            }
            controller.close();
          } catch (e) {
            controller.error(e);
          } finally {
            reader.releaseLock();
          }
        },
      });
    }
  }

  async function exportData(config = {}) {
    blobIdCounter = 0;
    const CBOR = window.CBOR;
    const opts = {
      fileName: "archive",
      opfs: true,
      localStorage: true,
      session: true,
      cookies: true,
      idb: true,
      cache: true,
      customItems: [],
      include: {},
      exclude: {},
      dbFilter: () => true,
      ...config,
    };
    const logger = opts.logger || console.log;

    let outputStream, downloadUrl;
    if (window.showSaveFilePicker && opts.download !== false) {
      try {
        const name = opts.password
          ? `${opts.fileName}.enc`
          : `${opts.fileName}.tar.gz`;
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        outputStream = await handle.createWritable();
      } catch (e) {
        if (e.name === "AbortError") return logger("Export cancelled.");
        console.warn("FS Picker failed, falling back.");
      }
    }

    if (!outputStream) {
      const chunks = [];
      outputStream = new WritableStream({
        write(c) {
          chunks.push(c);
        },
        close() {
          downloadUrl = URL.createObjectURL(
            new Blob(chunks, { type: "application/octet-stream" }),
          );
        },
      });
    }

    let outputBytesWritten = 0;
    const countingStream = new TransformStream({
      transform(chunk, controller) {
        outputBytesWritten += chunk.byteLength;
        controller.enqueue(chunk);
      },
    });

    const counterPromise = countingStream.readable.pipeTo(outputStream);
    let targetWritable = countingStream.writable;

    if (opts.password) {
      logger("Encrypting...");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const encStream = new TransformStream(
        new EncryptionTransformer(opts.password, salt),
      );
      encStream.readable.pipeTo(targetWritable);
      targetWritable = encStream.writable;
    }

    const gzip = new CompressionStream("gzip");
    // Important: We don't await this immediately, but checking errors is good
    gzip.readable
      .pipeTo(targetWritable)
      .catch((e) => console.error("GZIP Pipe Error", e));

    const tar = new TarWriter(gzip.writable);
    const reportProgress = () => {
      logger(
        `Exporting... (${(outputBytesWritten / 1024 / 1024).toFixed(2)} MB)`,
      );
    };
    const progressInterval = setInterval(reportProgress, 250);

    try {
      for (const item of opts.customItems) {
        logger(`Archiving custom: ${item.path}`);
        const path = `data/custom/${item.path}`;
        if (item.data instanceof Blob)
          await tar.writeStream(path, item.data.size, item.data.stream());
        else
          await tar.writeEntry(
            path,
            typeof item.data === "string"
              ? item.data
              : JSON.stringify(item.data),
          );
      }

      if (opts.localStorage) {
        const d = {};
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (isAllowed("localStorage", k, opts))
            d[k] = localStorage.getItem(k);
        }
        await tar.writeEntry("data/ls.json", JSON.stringify(d));
      }

      if (opts.session) {
        const d = {};
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i);
          if (isAllowed("session", k, opts)) d[k] = sessionStorage.getItem(k);
        }
        await tar.writeEntry("data/ss.json", JSON.stringify(d));
      }

      if (opts.cookies) {
        const c = document.cookie.split(";").reduce((acc, v) => {
          const [key, val] = v.split("=").map((s) => s.trim());
          if (key) acc[key] = val;
          return acc;
        }, {});
        await tar.writeEntry("data/cookies.json", JSON.stringify(c));
      }

      if (opts.idb && window.indexedDB && CBOR) {
        const dbs = await window.indexedDB.databases();
        for (const { name, version } of dbs) {
          if (!isAllowed("idb", name, opts) || !opts.dbFilter(name)) continue;
          const safeName = encodeURIComponent(name);
          logger(`Scanning IDB: ${name}`);

          const db = await new Promise((res, rej) => {
            const r = indexedDB.open(name);
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
            r.onblocked = () => rej(new Error("Blocked"));
          });

          const storeNames = Array.from(db.objectStoreNames);
          const stores = [];
          if (storeNames.length > 0) {
            const tx = db.transaction(storeNames, "readonly");
            for (const sName of storeNames) {
              const s = tx.objectStore(sName);
              stores.push({
                name: sName,
                keyPath: s.keyPath,
                autoIncrement: s.autoIncrement,
                indexes: Array.from(s.indexNames).map((i) => {
                  const idx = s.index(i);
                  return {
                    name: idx.name,
                    keyPath: idx.keyPath,
                    unique: idx.unique,
                    multiEntry: idx.multiEntry,
                  };
                }),
              });
            }
          }
          await tar.writeEntry(
            `data/idb/${safeName}/schema.cbor`,
            CBOR.encode({ name, version, stores }),
          );

          for (const sName of storeNames) {
            logger(`Archiving IDB: ${name}/${sName}`);
            let chunkId = 0;
            let lastKey = null;
            let hasMore = true;

            while (hasMore) {
              // Open new transaction for each batch
              const batchData = await new Promise((resolve, reject) => {
                const tx = db.transaction(sName, "readonly");
                const store = tx.objectStore(sName);
                const range = lastKey
                  ? IDBKeyRange.lowerBound(lastKey, true)
                  : null;
                const req = store.openCursor(range);

                const items = [];
                let batchSize = 0;
                const MAX_ITEMS = 2000;
                const MAX_BYTES = 5 * 1024 * 1024; // 5MB

                req.onsuccess = (e) => {
                  const cursor = e.target.result;
                  if (cursor) {
                    items.push({ k: cursor.key, v: cursor.value });
                    // Rough estimation
                    batchSize += 200;
                    if (cursor.value && typeof cursor.value === "string")
                      batchSize += cursor.value.length;

                    if (items.length >= MAX_ITEMS || batchSize >= MAX_BYTES) {
                      resolve({ items, next: cursor.key, done: false });
                    } else {
                      cursor.continue();
                    }
                  } else {
                    resolve({ items, next: null, done: true });
                  }
                };
                req.onerror = (e) => reject(e.target.error);
              });

              if (batchData.items.length > 0) {
                const blobsInBatch = [];
                const encBatch = [];
                for (const item of batchData.items) {
                  const val = prepForCBOR(item.v, blobsInBatch);
                  encBatch.push({ k: item.k, v: val });
                }

                for (const b of blobsInBatch) {
                  await tar.writeStream(
                    `data/blobs/${b.uuid}`,
                    b.blob.size,
                    b.blob.stream(),
                  );
                }

                await tar.writeEntry(
                  `data/idb/${safeName}/${encodeURIComponent(sName)}/${chunkId++}.cbor`,
                  CBOR.encode(encBatch),
                );
              }

              if (batchData.done) {
                hasMore = false;
              } else {
                lastKey = batchData.items[batchData.items.length - 1].k;
                // Allow UI update
                await yieldToMain();
              }
            }
          }
          db.close();
        }
      }

      if (opts.cache && window.caches && CBOR) {
        for (const cacheName of await caches.keys()) {
          if (!isAllowed("cache", cacheName, opts)) continue;
          logger(`Archiving Cache: ${cacheName}`);
          const cache = await caches.open(cacheName);
          for (const req of await cache.keys()) {
            const res = await cache.match(req);
            if (!res) continue;
            const blob = await res.blob();
            const safeHash = btoa(req.url).slice(0, 50).replace(/\//g, "_");
            await tar.writeEntry(
              `data/cache/${encodeURIComponent(cacheName)}/${safeHash}.cbor`,
              CBOR.encode({
                meta: {
                  url: req.url,
                  status: res.status,
                  headers: Object.fromEntries(res.headers),
                  type: blob.type,
                },
                data: new Uint8Array(await blob.arrayBuffer()),
              }),
            );
          }
        }
      }

      if (opts.opfs && navigator.storage) {
        const root = await navigator.storage.getDirectory();
        async function walk(dir, p) {
          for await (const entry of dir.values()) {
            const fp = p ? `${p}/${entry.name}` : entry.name;
            if (!isAllowed("opfs", fp, opts)) continue;
            if (entry.kind === "file") {
              const f = await entry.getFile();
              await tar.writeStream(`opfs/${fp}`, f.size, f.stream());
            } else await walk(entry, fp);
          }
        }
        await walk(root, "");
      }

      await tar.close(); // Closes Gzip input
      await counterPromise; // Waits for File stream to close

      if (downloadUrl) {
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = opts.password
          ? `${opts.fileName}.enc`
          : `${opts.fileName}.tar.gz`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
      }
      reportProgress();
      logger("Export complete!");
    } catch (e) {
      logger("Export error: " + e.message);
      console.error(e);
      try {
        await targetWritable.abort(e);
      } catch (z) {}
    } finally {
      clearInterval(progressInterval);
    }
  }

  async function importData(arg1, arg2 = {}) {
    const CBOR = window.CBOR;
    let config = arg2;
    let sourceInput = arg1;

    if (
      arg1 &&
      typeof arg1 === "object" &&
      !arg1.stream &&
      !arg1.arrayBuffer &&
      !arg1.slice &&
      (arg1.source || arg1.include || arg1.exclude)
    ) {
      config = arg1;
      sourceInput = config.source;
    }

    const opts = { ...config };
    const logger = opts.logger || console.log;

    try {
      let rawStream;
      if (typeof sourceInput === "string") {
        if (!sourceInput.startsWith("http"))
          sourceInput = "https://" + sourceInput;
        const response = await fetch(sourceInput);
        if (!response.ok) throw new Error("Fetch failed");
        rawStream = response.body;
      } else if (sourceInput && typeof sourceInput.stream === "function") {
        rawStream = sourceInput.stream();
      } else {
        throw new Error("Invalid source");
      }

      const rawReader = rawStream.getReader();
      const initialChunks = [];
      let initialBytes = 0;

      while (initialBytes < 8) {
        const { value, done } = await rawReader.read();
        if (done) break;
        initialChunks.push(value);
        initialBytes += value.byteLength;
      }
      rawReader.releaseLock();

      const combinedStream = new ReadableStream({
        async start(controller) {
          for (const chunk of initialChunks) controller.enqueue(chunk);
          const reader = rawStream.getReader();
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              controller.enqueue(value);
            }
            controller.close();
          } catch (e) {
            controller.error(e);
          }
        },
      });

      const probeHeader = new Uint8Array(8);
      if (initialBytes > 0) {
        let offset = 0;
        for (const chunk of initialChunks) {
          const needed = 8 - offset;
          if (needed <= 0) break;
          const toCopy = Math.min(needed, chunk.byteLength);
          probeHeader.set(chunk.subarray(0, toCopy), offset);
          offset += toCopy;
        }
      }

      const sig = DEC.decode(probeHeader.slice(0, 6));
      let inputStream;

      if (sig === "LE_ENC") {
        let password = opts.password || prompt("Enter the password:");
        if (!password) throw new Error("Password required");
        inputStream = new DecryptionSource(combinedStream, password)
          .readable()
          .pipeThrough(new DecompressionStream("gzip"));
      } else if (probeHeader[0] === 0x1f && probeHeader[1] === 0x8b) {
        inputStream = combinedStream.pipeThrough(
          new DecompressionStream("gzip"),
        );
      } else {
        inputStream = combinedStream;
      }

      const reader = inputStream.getReader();
      const streamBuffer = new ChunkBuffer();
      let done = false;

      async function ensure(n) {
        while (!streamBuffer.has(n) && !done) {
          const { value, done: d } = await reader.read();
          if (d) done = true;
          else streamBuffer.push(value);
        }
        return streamBuffer.has(n);
      }

      async function skip(n) {
        while (n > 0) {
          if (streamBuffer.totalSize === 0 && !done) await ensure(1);
          if (streamBuffer.totalSize === 0) break;
          const avail = streamBuffer.totalSize;
          const toSkip = Math.min(avail, n);
          streamBuffer.read(toSkip);
          n -= toSkip;
        }
      }

      async function streamToWriter(writer, size) {
        let remaining = size;
        while (remaining > 0) {
          if (streamBuffer.totalSize > 0) {
            const chunk = streamBuffer.read(
              Math.min(remaining, streamBuffer.totalSize),
            );
            await writer.write(chunk);
            remaining -= chunk.byteLength;
          } else {
            const { value, done: d } = await reader.read();
            if (d) throw new Error("Unexpected EOF");
            if (value.byteLength <= remaining) {
              await writer.write(value);
              remaining -= value.byteLength;
            } else {
              await writer.write(value.subarray(0, remaining));
              streamBuffer.push(value.subarray(remaining));
              remaining = 0;
            }
          }
        }
        await writer.close();
      }

      const rootOpfs = await navigator.storage.getDirectory();
      let tempBlobDir;
      try {
        tempBlobDir = await rootOpfs.getDirectoryHandle(TEMP_BLOB_DIR, {
          create: true,
        });
      } catch (e) {}
      const dbCache = {};

      let lastLog = Date.now();

      while (true) {
        if (Date.now() - lastLog > 500) {
          logger(`Importing...`);
          lastLog = Date.now();
          await yieldToMain();
        }

        if (!(await ensure(512))) break;
        const header = streamBuffer.read(512);
        if (header.every((b) => b === 0)) break;

        let name = DEC.decode(header.slice(0, 100)).replace(/\0/g, "").trim();
        const prefix = DEC.decode(header.slice(345, 500))
          .replace(/\0/g, "")
          .trim();
        if (prefix) name = `${prefix}/${name}`;

        const sizeStr = DEC.decode(header.slice(124, 136))
          .replace(/\0/g, "")
          .trim();
        const size = parseInt(sizeStr, 8);
        const padding = (512 - (size % 512)) % 512;

        if (name.startsWith("data/")) {
          if (name.startsWith("data/blobs/")) {
            const uuid = name.split("/").pop();
            if (tempBlobDir) {
              const fh = await tempBlobDir.getFileHandle(uuid, {
                create: true,
              });
              await streamToWriter(await fh.createWritable(), size);
            } else await skip(size);
          } else {
            if (size === 0) {
              await skip(padding);
              continue;
            }
            if (!(await ensure(size)))
              throw new Error("Unexpected EOF for metadata");
            const d = streamBuffer.read(size);

            if (name === "data/ls.json")
              Object.assign(localStorage, JSON.parse(DEC.decode(d)));
            else if (name === "data/ss.json") {
              const s = JSON.parse(DEC.decode(d));
              for (const k in s) sessionStorage.setItem(k, s[k]);
            } else if (name === "data/cookies.json") {
              const c = JSON.parse(DEC.decode(d));
              for (const k in c)
                document.cookie = `${k}=${c[k]}; path=/; max-age=31536000`;
            } else if (name.startsWith("data/custom/") && opts.onCustomItem) {
              await opts.onCustomItem(name.replace("data/custom/", ""), d);
            } else if (
              name.startsWith("data/idb/") &&
              CBOR &&
              opts.idb !== false
            ) {
              const parts = name.split("/");
              const dbName = decodeURIComponent(parts[2]);

              if (name.endsWith("schema.cbor")) {
                const schema = CBOR.decode(d);
                if (dbCache[dbName]) {
                  dbCache[dbName].close();
                  delete dbCache[dbName];
                }
                await new Promise((r) => {
                  const q = indexedDB.deleteDatabase(schema.name);
                  q.onsuccess = r;
                  q.onerror = r;
                });
                await new Promise((res, rej) => {
                  const req = indexedDB.open(schema.name, schema.version);
                  req.onupgradeneeded = (e) => {
                    const db = e.target.result;
                    schema.stores.forEach((s) => {
                      if (!db.objectStoreNames.contains(s.name)) {
                        const st = db.createObjectStore(s.name, {
                          keyPath: s.keyPath,
                          autoIncrement: s.autoIncrement,
                        });
                        s.indexes.forEach((i) =>
                          st.createIndex(i.name, i.keyPath, {
                            unique: i.unique,
                            multiEntry: i.multiEntry,
                          }),
                        );
                      }
                    });
                  };
                  req.onsuccess = (e) => {
                    e.target.result.close();
                    res();
                  };
                  req.onerror = rej;
                });
              } else {
                const storeName = decodeURIComponent(parts[3]);
                const records = await restoreFromCBOR(
                  CBOR.decode(d),
                  tempBlobDir,
                );
                if (!dbCache[dbName]) {
                  dbCache[dbName] = await new Promise((res, rej) => {
                    const r = indexedDB.open(dbName);
                    r.onsuccess = () => res(r.result);
                    r.onerror = rej;
                  });
                }
                try {
                  const tx = dbCache[dbName].transaction(
                    storeName,
                    "readwrite",
                  );
                  const st = tx.objectStore(storeName);
                  await Promise.all(
                    records.map(
                      (r) =>
                        new Promise((res) => {
                          const q = st.put(r.v, st.keyPath ? undefined : r.k);
                          q.onsuccess = res;
                          q.onerror = res;
                        }),
                    ),
                  );
                } catch (e) {
                  console.warn("IDB Import Error", e);
                }
              }
            }
          }
        } else {
          if (opts.opfs !== false) {
            const cleanName = name.startsWith("opfs/")
              ? name.replace("opfs/", "")
              : name;
            const parts = cleanName.split("/").filter((p) => p.length);
            if (parts.length > 0) {
              const fname = parts.pop();
              let dir = rootOpfs;
              for (const p of parts)
                dir = await dir.getDirectoryHandle(p, { create: true });
              const fh = await dir.getFileHandle(fname, { create: true });
              if (size > 0)
                await streamToWriter(await fh.createWritable(), size);
              else {
                const w = await fh.createWritable();
                await w.close();
              }
            } else await skip(size);
          } else await skip(size);
        }
        await skip(padding);
      }

      Object.values(dbCache).forEach((d) => d.close());
      if (tempBlobDir)
        try {
          await rootOpfs.removeEntry(TEMP_BLOB_DIR, { recursive: true });
        } catch (e) {}

      logger("Import complete!");
      if (opts.onsuccess) opts.onsuccess();
    } catch (e) {
      logger("Error: " + e.message);
      if (opts.onerror) opts.onerror(e);
      else throw e;
    }
  }

  window.LittleExport = { importData, exportData, deriveKey };
})();
