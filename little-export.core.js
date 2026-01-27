(function () {
  let blobIdCounter = 0;
  function createYielder(threshold = 100) {
    let lastYield = Date.now();
    const channel = new MessageChannel();
    const resolvers = [];

    channel.port1.onmessage = () => {
      const res = resolvers.shift();
      if (res) res();
    };

    return function (force = false) {
      const now = Date.now();
      if (force || now - lastYield > threshold) {
        lastYield = now;
        return (async () => {
          if ("scheduler" in window && "yield" in scheduler) {
            await scheduler.yield();
          } else {
            await new Promise((res) => {
              resolvers.push(res);
              channel.port2.postMessage(null);
            });
          }
        })();
      }
      return null;
    };
  }

  const CHUNK_SIZE = 4194304; // 4MB, for encryption
  const TAR_BUFFER_SIZE = 65536; // 64KB, for optimization
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();
  const TEMP_BLOB_DIR = ".rfs_temp_blobs"; // Hidden temp dir for IDB restoring

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
      const id = (blobIdCounter++).toString(36);
      externalBlobs.push({ uuid: id, blob: item });
      return { __le_blob_ref: id, type: item.type, size: item.size };
    }

    if (
      item instanceof ArrayBuffer ||
      ArrayBuffer.isView(item) ||
      item instanceof Date ||
      item instanceof RegExp
    ) {
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
      const fh = await tempBlobDir.getFileHandle(item.__le_blob_ref);
      const file = await fh.getFile();
      // Use slice to set the correct MIME type without wrapping the Blob in another Blob
      return file.slice(0, file.size, item.type);
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

  const TAR_CONSTANTS = {
    USTAR_MAGIC: new Uint8Array([117, 115, 116, 97, 114, 0]), // "ustar\0"
    USTAR_VER: new Uint8Array([48, 48]), // "00"
    EMPTY_SPACE: new Uint8Array(8).fill(32), // 8 spaces
  };

  // Pre-compute a clean header template
  const HEADER_TEMPLATE = new Uint8Array(512);
  (function initTemplate() {
    const w = (str, off) => ENC.encodeInto(str, HEADER_TEMPLATE.subarray(off));
    // Default values
    w("000664 \0", 100); // Mode
    w("000000 \0", 108); // UID
    w("000000 \0", 116); // GID
    HEADER_TEMPLATE.set(TAR_CONSTANTS.EMPTY_SPACE, 148); // Checksum (spaces)
    HEADER_TEMPLATE[156] = 48; // Typeflag "0"
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_MAGIC, 257);
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_VER, 263);
  })();

  function createTarHeader(filename, size, time, isDir = false) {
    // Max size check (USTAR limit)
    if (size > 8589934591) {
      throw new Error(
        "File size exceeds USTAR 8GB limit. Extensions required.",
      );
    }

    const buffer = HEADER_TEMPLATE.slice(0); // Fast zero-copy clone

    // Directory conventions
    if (isDir) {
      if (!filename.endsWith("/")) filename += "/";
      buffer[156] = 53; // '5'
    }

    // Paths
    const fullBytes = ENC.encode(filename);

    if (fullBytes.length <= 100) {
      buffer.set(fullBytes, 0);
    } else {
      // Split logic: Prefix (155) + Name (100)
      let bestSplit = -1;

      for (let i = 0; i < fullBytes.length; i++) {
        // Split strictly on slash
        if (fullBytes[i] === 47) {
          const prefixLen = i;
          const nameLen = fullBytes.length - 1 - i;

          // Check if both parts fit their respective fields
          if (prefixLen <= 155 && nameLen <= 100 && nameLen > 0) {
            bestSplit = i;
          }
        }
      }

      if (bestSplit !== -1) {
        buffer.set(fullBytes.subarray(bestSplit + 1), 0); // Name
        buffer.set(fullBytes.subarray(0, bestSplit), 345); // Prefix
      } else {
        throw new Error(
          `Filename too long or unsplittable for USTAR: ${filename}`,
        );
      }
    }

    // Helper to write octal safely
    const writeOctal = (num, offset, len) => {
      const str = Math.floor(num)
        .toString(8)
        .padStart(len - 1, "0");
      // Ensure we don't overflow the field width (already checked size, but good practice)
      if (str.length >= len) throw new Error("Octal field overflow");

      ENC.encodeInto(str, buffer.subarray(offset, offset + len - 1));
      buffer[offset + len - 1] = 0; // Null terminate
    };

    writeOctal(size, 124, 12);
    writeOctal(time, 136, 12);

    // Treat checksum field (148-155) as spaces (ASCII 32)
    let sum = 0;
    for (let i = 0; i < 512; i++) {
      sum += buffer[i];
    }

    // Finally write the checksum (6 digits + null + space)
    const cksumStr = sum.toString(8).padStart(6, "0");
    ENC.encodeInto(cksumStr, buffer.subarray(148));
    buffer[154] = 0;
    buffer[155] = 32; // space
    return buffer;
  }

  class TarWriter {
    constructor(writableStream, yielder) {
      this.writer = writableStream.getWriter();
      this.yielder = yielder;
      this.pos = 0;
      this.bytesWritten = 0;
      this.time = Math.floor(Date.now() / 1000);

      this.buffer = new Uint8Array(TAR_BUFFER_SIZE);
      this.bufferOffset = 0;
    }

    async writeEntry(path, data) {
      const bytes = typeof data === "string" ? ENC.encode(data) : data;
      const header = createTarHeader(path, bytes.length, this.time);

      await this.write(header);
      await this.write(bytes);
      await this.pad();
    }

    async writeStream(path, size, readableStream) {
      await this.write(createTarHeader(path, size, this.time));
      const reader = readableStream.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          await this.write(value);
          const p = this.yielder();
          if (p) await p;
        }
      } finally {
        reader.releaseLock();
      }

      await this.pad();
    }

    async write(chunk) {
      const len = chunk.byteLength;

      // If the chunk is larger than our buffer, bypass the buffer entirely (Zero-Copy)
      if (len >= TAR_BUFFER_SIZE) {
        await this.flush();
        await this.writer.write(chunk);
      } else if (this.bufferOffset + len > TAR_BUFFER_SIZE) {
        await this.flush();
        this.buffer.set(chunk, 0);
        this.bufferOffset = len;
      } else {
        this.buffer.set(chunk, this.bufferOffset);
        this.bufferOffset += len;
      }

      this.pos += len;
      this.bytesWritten += len;
    }

    async pad() {
      const padding = (512 - (this.pos % 512)) % 512;
      if (padding > 0) {
        // Create padding array once
        const pad = new Uint8Array(padding);
        await this.write(pad);
      }
    }

    async flush() {
      if (this.bufferOffset > 0) {
        await this.writer.write(this.buffer.subarray(0, this.bufferOffset));
        this.bufferOffset = 0;
      }
    }

    async close() {
      // Write 2 empty blocks (standard TAR footer)
      await this.write(new Uint8Array(1024));
      await this.flush();
      await this.writer.close();
    }
  }

  class EncryptionTransformer {
    constructor(password, salt) {
      this.salt = salt;
      this.keyPromise = deriveKey(password, salt);
      this.chunks = [];
      this.currentSize = 0;
    }

    async start(controller) {
      controller.enqueue(ENC.encode("LE_ENC"));
      controller.enqueue(this.salt);
      await this.encryptAndPush(
        new Uint8Array(0),
        controller,
        await this.keyPromise,
      );
    }

    async transform(chunk, controller) {
      this.chunks.push(chunk);
      this.currentSize += chunk.byteLength;

      // Buffer chunks until we hit 4MB to ensure efficient encryption block sizes
      if (this.currentSize >= CHUNK_SIZE) {
        const fullBuffer = new Uint8Array(this.currentSize);
        let offset = 0;
        for (const c of this.chunks) {
          fullBuffer.set(c, offset);
          offset += c.byteLength;
        }

        const key = await this.keyPromise;
        let pos = 0;
        // Process complete 4MB chunks
        while (pos + CHUNK_SIZE <= fullBuffer.length) {
          await this.encryptAndPush(
            fullBuffer.subarray(pos, pos + CHUNK_SIZE),
            controller,
            key,
          );
          pos += CHUNK_SIZE;
        }

        // Keep the remainder for the next transform call
        const remainder = fullBuffer.subarray(pos);
        this.chunks = remainder.length > 0 ? [remainder] : [];
        this.currentSize = remainder.length;
      }
    }

    async flush(controller) {
      // Write whatever is left in the buffer
      if (this.currentSize > 0) {
        const finalBuffer = new Uint8Array(this.currentSize);
        let offset = 0;
        for (const c of this.chunks) {
          finalBuffer.set(c, offset);
          offset += c.byteLength;
        }
        await this.encryptAndPush(
          finalBuffer,
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
    constructor(readableStream, password, yielder) {
      this.stream = readableStream;
      this.password = password;
      this.yielder = yielder;
      this.buffer = new ChunkBuffer();
    }
    readable() {
      let reader;
      async function ensure(n) {
        while (!this.buffer.has(n)) {
          const { value, done } = await reader.read();
          if (done) return false;
          this.buffer.push(value);
        }
        return true;
      }
      return new ReadableStream({
        async start(controller) {
          reader = this.stream.getReader();
          try {
            if (!(await ensure(22))) throw new Error("File too small");
            const sig = new TextDecoder().decode(this.buffer.read(6));
            if (sig !== "LE_ENC") throw new Error("Not an encrypted archive");

            const salt = this.buffer.read(16);
            const key = await deriveKey(this.password, salt);

            if (!(await ensure(16))) throw new Error("Corrupt header");
            const initIV = this.buffer.read(12);
            const initLenRaw = this.buffer.read(4);
            const initLen = new DataView(
              initLenRaw.buffer,
              initLenRaw.byteOffset,
              initLenRaw.byteLength,
            ).getUint32(0, true);

            if (!(await ensure(initLen))) throw new Error("Corrupt header");
            const initCipher = this.buffer.read(initLen);
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
              const p = this.yielder();
              if (p) await p;
              if (!this.buffer.has(16)) {
                const { value, done } = await reader.read();
                if (done) {
                  if (this.buffer.totalSize === 0) break;
                  throw new Error("Truncated encrypted stream");
                }
                this.buffer.push(value);
                continue;
              }
              const iv = this.buffer.read(12);
              const lenRaw = this.buffer.read(4);
              const lenVal = new DataView(
                lenRaw.buffer,
                lenRaw.byteOffset,
                lenRaw.byteLength,
              ).getUint32(0, true);

              while (!this.buffer.has(lenVal)) {
                const { value, done } = await reader.read();
                if (done) throw new Error("Unexpected EOF in ciphertext");
                this.buffer.push(value);
                const p2 = this.yielder();
                if (p2) await p2;
              }
              const cipher = this.buffer.read(lenVal);
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
      logSpeed: 100,
      customItems: [],
      include: {},
      exclude: {},
      dbFilter: () => true,
      ...config,
    };
    const logger = opts.logger || console.log;
    const yielder = createYielder(opts.logSpeed);

    let outputStream,
      downloadUrl,
      chunks = [];
    if (window.showSaveFilePicker && opts.download !== false) {
      try {
        const name = opts.password
          ? `${opts.fileName}.enc`
          : `${opts.fileName}.tar.gz`;
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        outputStream = await handle.createWritable();
      } catch (e) {
        if (e.name === "AbortError") {
          logger("Export cancelled.");
          return;
        }
        console.warn("FileSystem picker failed, falling back.");
      }
    }

    if (!outputStream) {
      outputStream = new WritableStream({
        write(c) {
          chunks.push(c);
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

    const gzip = new CompressionStream("gzip");

    let pipeline = gzip.readable;

    if (opts.password) {
      logger("Encrypting...");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      pipeline = pipeline.pipeThrough(
        new TransformStream(new EncryptionTransformer(opts.password, salt)),
      );
    }

    // Finalize the chain by adding the counter and piping to the sink (outputStream)
    const exportFinishedPromise = pipeline
      .pipeThrough(countingStream)
      .pipeTo(outputStream);

    const tar = new TarWriter(gzip.writable, yielder);

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

          const dbForSchema = await new Promise((res, rej) => {
            const r = indexedDB.open(name);
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
            r.onblocked = () => rej(new Error("IndexedDB open was blocked."));
          });

          const storeNames = Array.from(dbForSchema.objectStoreNames);
          const stores = [];
          if (storeNames.length > 0) {
            const tx = dbForSchema.transaction(storeNames, "readonly");
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
          dbForSchema.close(); // Close immediately after schema read

          await tar.writeEntry(
            `data/idb/${safeName}/schema.cbor`,
            CBOR.encode({ name, version, stores }),
          );

          for (const sName of storeNames) {
            logger(`Archiving IDB: ${name}/${sName}`);

            let lastKey = null;
            let chunkId = 0;
            let hasMore = true;

            while (hasMore) {
              const batchData = await new Promise((resolve, reject) => {
                const r = indexedDB.open(name);
                r.onsuccess = (ev) => {
                  const db = ev.target.result;
                  try {
                    const tx = db.transaction(sName, "readonly");
                    const store = tx.objectStore(sName);
                    const range = lastKey
                      ? IDBKeyRange.lowerBound(lastKey, true)
                      : null;
                    const cursorReq = store.openCursor(range);

                    const batch = [];
                    const BATCH_LIMIT = 200; // Smaller batches prevent locking UI during synchronous fetch

                    cursorReq.onsuccess = (e) => {
                      const cursor = e.target.result;
                      if (cursor && batch.length < BATCH_LIMIT) {
                        batch.push({ k: cursor.key, v: cursor.value });
                        lastKey = cursor.key;
                        cursor.continue();
                      } else {
                        // Batch full or no more items
                        db.close();
                        resolve({
                          items: batch,
                          done: !cursor,
                        });
                      }
                    };
                    cursorReq.onerror = (e) => {
                      db.close();
                      reject(e);
                    };
                  } catch (err) {
                    db.close();
                    reject(err);
                  }
                };
                r.onerror = (e) => reject(e);
              });

              hasMore = !batchData.done;

              if (batchData.items.length > 0) {
                const finalBatch = [];
                for (const item of batchData.items) {
                  const blobsInBatch = [];
                  const encVal = prepForCBOR(item.v, blobsInBatch);
                  finalBatch.push({ k: item.k, v: encVal });

                  for (const b of blobsInBatch) {
                    await tar.writeStream(
                      `data/blobs/${b.uuid}`,
                      b.blob.size,
                      b.blob.stream(),
                    );
                  }
                }

                await tar.writeEntry(
                  `data/idb/${safeName}/${encodeURIComponent(sName)}/${chunkId++}.cbor`,
                  CBOR.encode(finalBatch),
                );

                const p = yielder();
                if (p) await p;
              }
            }
          }
        }
      }

      if (opts.cache && window.caches && CBOR) {
        for (const cacheName of await caches.keys()) {
          if (!isAllowed("cache", cacheName, opts)) continue;
          logger(`Archiving Cache: ${cacheName}`);
          const p = yielder();
          if (p) await p;
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
        async function walk(dir, pStr) {
          for await (const entry of dir.values()) {
            const p = yielder();
            if (p) await p;
            const fp = pStr ? `${pStr}/${entry.name}` : entry.name;
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
      await exportFinishedPromise;
      if (chunks.length > 0) {
        downloadUrl = URL.createObjectURL(
          new Blob(chunks, { type: "application/octet-stream" }),
        );
      }

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
    const yielder = createYielder(opts.logSpeed || 100);

    try {
      let rawStream;
      if (typeof sourceInput === "string") {
        if (!sourceInput.startsWith("http"))
          sourceInput = "https://" + sourceInput;
        const response = await fetch(sourceInput);
        if (!response.ok) throw new Error("Fetching of URL failed.");
        rawStream = response.body;
      } else if (sourceInput && typeof sourceInput.stream === "function") {
        rawStream = sourceInput.stream();
      } else {
        throw new Error("Invalid source.");
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
        if (!password)
          throw new Error("A password is required to decrypt this data.");
        inputStream = new DecryptionSource(combinedStream, password, yielder)
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
      let totalRead = 0;

      async function ensure(n) {
        while (!streamBuffer.has(n) && !done) {
          const { value, done: d } = await reader.read();
          if (d) done = true;
          else {
            totalRead += value.byteLength;
            streamBuffer.push(value);
          }
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
          const p = yielder();
          if (p) await p;
          if (streamBuffer.totalSize > 0) {
            const chunk = streamBuffer.read(
              Math.min(remaining, streamBuffer.totalSize),
            );
            await writer.write(chunk);
            remaining -= chunk.byteLength;
          } else {
            const { value, done: d } = await reader.read();
            if (d) throw new Error("Unexpected EOF");
            totalRead += value.byteLength;
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

      while (true) {
        if (!(await ensure(512))) break;
        const header = streamBuffer.read(512);
        if (header.every((b) => b === 0)) break;

        let name = DEC.decode(header.slice(0, 100)).replace(/\0/g, "").trim();
        const prefix = DEC.decode(header.slice(345, 500))
          .replace(/\0/g, "")
          .trim();
        if (prefix) name = `${prefix}/${name}`;
        const p = yielder();
        if (p) {
          logger(
            `Importing (${(totalRead / 1048576).toFixed(2)} MB) ${name}...`,
          );
          await p;
        }

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
                  console.error(e);
                  alert(
                    "IDB importing error for DB " +
                      dbName +
                      "(perhaps close other tabs?): " +
                      e,
                  );
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
