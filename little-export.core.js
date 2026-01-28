(function () {
  const TYPE = { OPFS: 1, IDB: 2, LS: 4, SS: 8, COOKIE: 16, CACHE: 32 };
  const DECISION = { SKIP: 0, PROCESS: 1, TRUST: 2, ABORT: 3 };

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

  const CHUNK_SIZE = 4194304;
  const TAR_BUFFER_SIZE = 65536;
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();
  const TEMP_BLOB_DIR = ".rfs_temp_blobs";

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

  // Simple mode filter, supports functions and arrays
  function checkSimpleFilter(category, pathStr, config) {
    const { include, exclude } = config;

    // Check exclude first (blacklist)
    if (exclude && exclude[category]) {
      const filter = exclude[category];
      if (typeof filter === "function") {
        if (filter(pathStr)) return false;
      } else if (Array.isArray(filter)) {
        // For arrays: exact match or prefix match
        if (
          filter.some(
            (t) =>
              pathStr === t ||
              pathStr.startsWith(t + "/") ||
              pathStr.startsWith(t),
          )
        )
          return false;
      }
    }

    // Check include (whitelist), only if specified
    if (include && include[category]) {
      const filter = include[category];
      if (typeof filter === "function") {
        return filter(pathStr);
      } else if (Array.isArray(filter) && filter.length > 0) {
        return filter.some(
          (t) =>
            pathStr === t ||
            pathStr.startsWith(t + "/") ||
            pathStr.startsWith(t),
        );
      }
    }

    return true;
  }

  function prepForCBOR(item, externalBlobs, seen) {
    if (!item || typeof item !== "object") return item;

    // Circular reference protection
    if (!seen) seen = new WeakSet();
    if (seen.has(item)) return { __le_circular: true };

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

    seen.add(item);

    if (Array.isArray(item)) {
      const len = item.length;
      const res = new Array(len);
      for (let i = 0; i < len; i++) {
        res[i] = prepForCBOR(item[i], externalBlobs, seen);
      }
      return res;
    }

    const res = {};
    for (const k in item) {
      if (Object.prototype.hasOwnProperty.call(item, k)) {
        res[k] = prepForCBOR(item[k], externalBlobs, seen);
      }
    }
    return res;
  }

  async function restoreFromCBOR(item, tempBlobDir) {
    if (!item || typeof item !== "object") return item;
    if (item.__le_blob_ref) {
      if (!tempBlobDir) return null;
      try {
        const fh = await tempBlobDir.getFileHandle(item.__le_blob_ref);
        const file = await fh.getFile();
        return file.slice(0, file.size, item.type);
      } catch (e) {
        return null; // Blob not found, gracefully return null
      }
    }
    if (item.__le_blob) {
      return new Blob([item.data], { type: item.type });
    }
    if (item.__le_circular) {
      return null; // Can't restore circular references
    }

    if (Array.isArray(item)) {
      const res = new Array(item.length);
      for (let i = 0; i < item.length; i++) {
        res[i] = await restoreFromCBOR(item[i], tempBlobDir);
      }
      return res;
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
    USTAR_MAGIC: new Uint8Array([117, 115, 116, 97, 114, 0]),
    USTAR_VER: new Uint8Array([48, 48]),
    EMPTY_SPACE: new Uint8Array(8).fill(32),
  };

  const HEADER_TEMPLATE = new Uint8Array(512);
  (function initTemplate() {
    const w = (str, off) => ENC.encodeInto(str, HEADER_TEMPLATE.subarray(off));
    w("000664 \0", 100);
    w("000000 \0", 108);
    w("000000 \0", 116);
    HEADER_TEMPLATE.set(TAR_CONSTANTS.EMPTY_SPACE, 148);
    HEADER_TEMPLATE[156] = 48;
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_MAGIC, 257);
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_VER, 263);
  })();

  function createTarHeader(filename, size, time, isDir = false) {
    if (size > 8589934591) {
      throw new Error("File size exceeds USTAR 8GB limit.");
    }

    const buffer = HEADER_TEMPLATE.slice(0);

    if (isDir) {
      if (!filename.endsWith("/")) filename += "/";
      buffer[156] = 53;
    }

    const fullBytes = ENC.encode(filename);

    if (fullBytes.length <= 100) {
      buffer.set(fullBytes, 0);
    } else {
      let bestSplit = -1;

      for (let i = 0; i < fullBytes.length; i++) {
        if (fullBytes[i] === 47) {
          const prefixLen = i;
          const nameLen = fullBytes.length - 1 - i;

          if (prefixLen <= 155 && nameLen <= 100 && nameLen > 0) {
            bestSplit = i;
          }
        }
      }

      if (bestSplit !== -1) {
        buffer.set(fullBytes.subarray(bestSplit + 1), 0);
        buffer.set(fullBytes.subarray(0, bestSplit), 345);
      } else {
        throw new Error(`Filename too long for USTAR: ${filename}`);
      }
    }

    const writeOctal = (num, offset, len) => {
      const str = Math.floor(num)
        .toString(8)
        .padStart(len - 1, "0");
      if (str.length >= len) throw new Error("Octal field overflow");
      ENC.encodeInto(str, buffer.subarray(offset, offset + len - 1));
      buffer[offset + len - 1] = 0;
    };

    writeOctal(size, 124, 12);
    writeOctal(time, 136, 12);

    let sum = 0;
    for (let i = 0; i < 512; i++) sum += buffer[i];

    const cksumStr = sum.toString(8).padStart(6, "0");
    ENC.encodeInto(cksumStr, buffer.subarray(148));
    buffer[154] = 0;
    buffer[155] = 32;
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
        await this.write(new Uint8Array(padding));
      }
    }

    async writeDir(path) {
      const header = createTarHeader(path, 0, this.time, true);
      await this.write(header);
    }

    async flush() {
      if (this.bufferOffset > 0) {
        await this.writer.write(this.buffer.subarray(0, this.bufferOffset));
        this.bufferOffset = 0;
      }
    }

    async close() {
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

      if (this.currentSize >= CHUNK_SIZE) {
        const fullBuffer = new Uint8Array(this.currentSize);
        let offset = 0;
        for (const c of this.chunks) {
          fullBuffer.set(c, offset);
          offset += c.byteLength;
        }

        const key = await this.keyPromise;
        let pos = 0;
        while (pos + CHUNK_SIZE <= fullBuffer.length) {
          await this.encryptAndPush(
            fullBuffer.subarray(pos, pos + CHUNK_SIZE),
            controller,
            key,
          );
          pos += CHUNK_SIZE;
        }

        const remainder = fullBuffer.subarray(pos);
        this.chunks = remainder.length > 0 ? [remainder] : [];
        this.currentSize = remainder.length;
      }
    }

    async flush(controller) {
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
            const sig = DEC.decode(self.buffer.read(6));
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
              const p = self.yielder();
              if (p) await p;

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
                const p2 = self.yielder();
                if (p2) await p2;
              }
              const cipher = self.buffer.read(lenVal);
              const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                cipher,
              );

              const pForce = self.yielder(true);
              if (pForce) await pForce;

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
      graceful: false,
      download: true,
      ...config,
    };

    const logger = opts.logger || (() => {});
    const yielder = createYielder(opts.logSpeed);
    const graceful = opts.graceful;
    const useOnVisit = typeof opts.onVisit === "function";
    const onVisit = opts.onVisit;

    let aborted = false;

    function getDecision(type, path, meta) {
      if (!useOnVisit) return DECISION.TRUST;
      return onVisit(type, path, meta);
    }

    async function tryGraceful(fn, context) {
      try {
        return await fn();
      } catch (e) {
        if (graceful) {
          if (opts.onerror) opts.onerror(e);
          logger(`Warning: ${context} - ${e.message}`);
          return null;
        }
        throw e;
      }
    }

    const status = { category: "Init", detail: "preparing..." };

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
        close() {},
      });
    }

    let outputBytesWritten = 0;
    const countingStream = new TransformStream({
      async transform(chunk, controller) {
        outputBytesWritten += chunk.byteLength;
        const p = yielder();
        if (p) {
          logger(
            `Exporting ${status.category}: ${(outputBytesWritten / 1048576).toFixed(2)} MB (${status.detail})`,
          );
          await p;
        }
        controller.enqueue(chunk);
      },
    });

    const gzip = new CompressionStream("gzip");
    let pipeline = gzip.readable;

    if (opts.password) {
      status.category = "Setup";
      status.detail = "Encrypting...";
      const salt = crypto.getRandomValues(new Uint8Array(16));
      pipeline = pipeline.pipeThrough(
        new TransformStream(new EncryptionTransformer(opts.password, salt)),
      );
    }

    const exportFinishedPromise = pipeline
      .pipeThrough(countingStream)
      .pipeTo(outputStream);
    const tar = new TarWriter(gzip.writable, yielder);

    try {
      // Custom items (always processed)
      for (const item of opts.customItems) {
        if (aborted) break;
        status.category = "Custom";
        status.detail = item.path;
        const path = `data/custom/${item.path}`;
        if (item.data instanceof Blob) {
          await tar.writeStream(path, item.data.size, item.data.stream());
        } else {
          await tar.writeEntry(
            path,
            typeof item.data === "string"
              ? item.data
              : JSON.stringify(item.data),
          );
        }
      }

      // OPFS
      if (!aborted && opts.opfs && navigator.storage) {
        let categoryDecision = getDecision(TYPE.OPFS, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "OPFS";
          const root = await navigator.storage.getDirectory();
          const trustAll = categoryDecision === DECISION.TRUST;

          async function walkOpfs(dir, pathArray, inherited) {
            for await (const entry of dir.values()) {
              if (aborted) return;

              const currentPath = [...pathArray, entry.name];
              const pathStr = currentPath.join("/");
              let decision = inherited;

              status.detail = pathStr;

              if (!inherited) {
                if (useOnVisit) {
                  let raw = getDecision(TYPE.OPFS, currentPath, {
                    kind: entry.kind,
                    handle: entry,
                  });
                  if (raw && typeof raw.then === "function") raw = await raw;
                  decision = raw;

                  if (decision === DECISION.ABORT) {
                    aborted = true;
                    return;
                  }
                  if (decision === DECISION.SKIP) continue;
                } else {
                  if (!checkSimpleFilter("opfs", pathStr, opts)) continue;
                  decision = DECISION.TRUST;
                }
              }

              const trustChildren = decision === DECISION.TRUST;

              if (entry.kind === "file") {
                await tryGraceful(async () => {
                  const f = await entry.getFile();
                  await tar.writeStream(`opfs/${pathStr}`, f.size, f.stream());
                }, `OPFS file ${pathStr}`);
              } else {
                await tar.writeDir(`opfs/${pathStr}`);
                await walkOpfs(
                  entry,
                  currentPath,
                  trustChildren ? DECISION.TRUST : false,
                );
              }

              const p = yielder();
              if (p) await p;
            }
          }

          await walkOpfs(root, [], trustAll ? DECISION.TRUST : false);
        }
      }

      // IndexedDB
      if (!aborted && opts.idb && window.indexedDB && CBOR) {
        let categoryDecision = getDecision(TYPE.IDB, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "IndexedDB";
          const trustAllDbs = categoryDecision === DECISION.TRUST;
          const dbs = await window.indexedDB.databases();

          for (const { name, version } of dbs) {
            if (aborted) break;

            status.detail = name;
            const safeName = encodeURIComponent(name);

            const db = await tryGraceful(async () => {
              return await new Promise((resolve, reject) => {
                const req = indexedDB.open(name);
                const timeout = setTimeout(
                  () => reject(new Error(`Database ${name} timed out`)),
                  5000,
                );
                req.onblocked = () => {
                  clearTimeout(timeout);
                  reject(new Error(`Database ${name} blocked`));
                };
                req.onsuccess = () => {
                  clearTimeout(timeout);
                  resolve(req.result);
                };
                req.onerror = () => {
                  clearTimeout(timeout);
                  reject(req.error);
                };
              });
            }, `Opening IDB ${name}`);

            if (!db) continue;

            let dbDecision = trustAllDbs ? DECISION.TRUST : DECISION.PROCESS;

            if (!trustAllDbs) {
              if (useOnVisit) {
                let raw = getDecision(TYPE.IDB, [name], { database: db });
                if (raw && typeof raw.then === "function") raw = await raw;
                dbDecision = raw;

                if (dbDecision === DECISION.ABORT) {
                  aborted = true;
                  db.close();
                  break;
                }
                if (dbDecision === DECISION.SKIP) {
                  db.close();
                  continue;
                }
              } else {
                if (!checkSimpleFilter("idb", name, opts)) {
                  db.close();
                  continue;
                }
              }
            }

            const trustAllStores = dbDecision === DECISION.TRUST;

            try {
              const storeNames = Array.from(db.objectStoreNames);

              if (storeNames.length === 0) {
                await tar.writeEntry(
                  `data/idb/${safeName}/schema.cbor`,
                  CBOR.encode({ name, version, stores: [] }),
                );
                continue;
              }

              const stores = [];
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

              await tar.writeEntry(
                `data/idb/${safeName}/schema.cbor`,
                CBOR.encode({ name, version, stores }),
              );

              for (const sName of storeNames) {
                if (aborted) break;

                let storeDecision = trustAllStores
                  ? DECISION.TRUST
                  : DECISION.PROCESS;

                if (!trustAllStores) {
                  if (useOnVisit) {
                    let raw = getDecision(TYPE.IDB, [name, sName], {
                      database: db,
                    });
                    if (raw && typeof raw.then === "function") raw = await raw;
                    storeDecision = raw;

                    if (storeDecision === DECISION.ABORT) {
                      aborted = true;
                      break;
                    }
                    if (storeDecision === DECISION.SKIP) continue;
                  } else {
                    if (!checkSimpleFilter("idb", `${name}/${sName}`, opts))
                      continue;
                  }
                }

                status.detail = `${name} / ${sName}`;

                let lastKey = null;
                let chunkId = 0;
                let hasMore = true;

                while (hasMore && !aborted) {
                  const batch = await tryGraceful(async () => {
                    const batchSizeLimit = 100;
                    return await new Promise((resolve, reject) => {
                      const innerTx = db.transaction(sName, "readonly");
                      const store = innerTx.objectStore(sName);
                      const range =
                        lastKey !== null
                          ? IDBKeyRange.lowerBound(lastKey, true)
                          : null;
                      const request = store.openCursor(range);
                      const keys = [];
                      const values = [];

                      request.onsuccess = (e) => {
                        const cursor = e.target.result;
                        if (cursor && keys.length < batchSizeLimit) {
                          keys.push(cursor.key);
                          values.push(cursor.value);
                          lastKey = cursor.key;
                          cursor.continue();
                        } else {
                          resolve({ keys, values, done: !cursor });
                        }
                      };
                      request.onerror = () => reject(request.error);
                    });
                  }, `Reading IDB ${name}/${sName}`);

                  if (!batch) break;
                  hasMore = !batch.done;

                  if (batch.keys.length > 0) {
                    const processedValues = [];
                    for (let i = 0; i < batch.values.length; i++) {
                      const blobsInItem = [];
                      const cleanValue = prepForCBOR(
                        batch.values[i],
                        blobsInItem,
                      );
                      processedValues.push(cleanValue);
                      for (const b of blobsInItem) {
                        await tar.writeStream(
                          `data/blobs/${b.uuid}`,
                          b.blob.size,
                          b.blob.stream(),
                        );
                      }
                    }

                    await tar.writeEntry(
                      `data/idb/${safeName}/${encodeURIComponent(sName)}/${chunkId++}.cbor`,
                      CBOR.encode([batch.keys, processedValues]),
                    );
                    const p = yielder();
                    if (p) await p;
                  }
                }
              }
            } finally {
              db.close();
            }
          }
        }
      }

      // localStorage
      if (!aborted && opts.localStorage) {
        let categoryDecision = getDecision(TYPE.LS, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "Storage";
          status.detail = "Local Storage";
          const d = {};
          const trustAll = categoryDecision === DECISION.TRUST;

          for (let i = 0; i < localStorage.length && !aborted; i++) {
            const k = localStorage.key(i);
            status.detail = `localStorage: ${k}`;

            let shouldInclude = trustAll;

            if (!shouldInclude) {
              if (useOnVisit) {
                let keyDecision = getDecision(TYPE.LS, [k], {
                  value: localStorage.getItem(k),
                });
                if (keyDecision && typeof keyDecision.then === "function")
                  keyDecision = await keyDecision;

                if (keyDecision === DECISION.ABORT) {
                  aborted = true;
                  break;
                }
                shouldInclude = keyDecision !== DECISION.SKIP;
              } else {
                shouldInclude = checkSimpleFilter("localStorage", k, opts);
              }
            }

            if (shouldInclude) {
              d[k] = localStorage.getItem(k);
            }
          }

          if (!aborted && Object.keys(d).length > 0) {
            await tar.writeEntry("data/ls.json", JSON.stringify(d));
          }
        }
      }

      // sessionStorage
      if (!aborted && opts.session) {
        let categoryDecision = getDecision(TYPE.SS, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "Storage";
          status.detail = "Session Storage";
          const d = {};
          const trustAll = categoryDecision === DECISION.TRUST;

          for (let i = 0; i < sessionStorage.length && !aborted; i++) {
            const k = sessionStorage.key(i);
            status.detail = `sessionStorage: ${k}`;

            let shouldInclude = trustAll;

            if (!shouldInclude) {
              if (useOnVisit) {
                let keyDecision = getDecision(TYPE.SS, [k], {
                  value: sessionStorage.getItem(k),
                });
                if (keyDecision && typeof keyDecision.then === "function")
                  keyDecision = await keyDecision;

                if (keyDecision === DECISION.ABORT) {
                  aborted = true;
                  break;
                }
                shouldInclude = keyDecision !== DECISION.SKIP;
              } else {
                shouldInclude = checkSimpleFilter("session", k, opts);
              }
            }

            if (shouldInclude) {
              d[k] = sessionStorage.getItem(k);
            }
          }

          if (!aborted && Object.keys(d).length > 0) {
            await tar.writeEntry("data/ss.json", JSON.stringify(d));
          }
        }
      }

      // Cookies
      if (!aborted && opts.cookies) {
        let categoryDecision = getDecision(TYPE.COOKIE, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "Storage";
          status.detail = "Cookies";
          const c = {};
          const trustAll = categoryDecision === DECISION.TRUST;

          const cookiePairs = document.cookie
            .split(";")
            .map((s) => s.trim())
            .filter(Boolean);

          for (const pair of cookiePairs) {
            if (aborted) break;

            const eqIndex = pair.indexOf("=");
            const key =
              eqIndex > -1 ? pair.slice(0, eqIndex).trim() : pair.trim();
            const val = eqIndex > -1 ? pair.slice(eqIndex + 1).trim() : "";

            if (!key) continue;

            status.detail = `cookie: ${key}`;

            let shouldInclude = trustAll;

            if (!shouldInclude) {
              if (useOnVisit) {
                let keyDecision = getDecision(TYPE.COOKIE, [key], {
                  value: val,
                });
                if (keyDecision && typeof keyDecision.then === "function")
                  keyDecision = await keyDecision;

                if (keyDecision === DECISION.ABORT) {
                  aborted = true;
                  break;
                }
                shouldInclude = keyDecision !== DECISION.SKIP;
              } else {
                shouldInclude = checkSimpleFilter("cookies", key, opts);
              }
            }

            if (shouldInclude) {
              c[key] = val;
            }
          }

          if (!aborted && Object.keys(c).length > 0) {
            await tar.writeEntry("data/cookies.json", JSON.stringify(c));
          }
        }
      }

      // Cache storage
      if (!aborted && opts.cache && window.caches && CBOR) {
        let categoryDecision = getDecision(TYPE.CACHE, undefined, undefined);
        if (categoryDecision && typeof categoryDecision.then === "function")
          categoryDecision = await categoryDecision;

        if (categoryDecision === DECISION.ABORT) aborted = true;

        if (!aborted && categoryDecision !== DECISION.SKIP) {
          status.category = "Cache";
          const cacheNames = await caches.keys();
          const trustAll = categoryDecision === DECISION.TRUST;

          for (const cacheName of cacheNames) {
            if (aborted) break;

            let shouldProcess = trustAll;

            if (!shouldProcess) {
              if (useOnVisit) {
                let cacheDecision = getDecision(TYPE.CACHE, [cacheName], null);
                if (cacheDecision && typeof cacheDecision.then === "function")
                  cacheDecision = await cacheDecision;

                if (cacheDecision === DECISION.ABORT) {
                  aborted = true;
                  break;
                }
                shouldProcess = cacheDecision !== DECISION.SKIP;
              } else {
                shouldProcess = checkSimpleFilter("cache", cacheName, opts);
              }
            }

            if (!shouldProcess) continue;

            status.detail = cacheName;
            const p = yielder();
            if (p) await p;

            await tryGraceful(async () => {
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
            }, `Cache ${cacheName}`);
          }
        }
      }

      status.category = "Finishing";
      status.detail = "compressing...";
      await tar.close();
      await exportFinishedPromise;

      if (chunks.length > 0) {
        downloadUrl = URL.createObjectURL(
          new Blob(chunks, { type: "application/octet-stream" }),
        );
      }

      if (downloadUrl) {
        if (opts.download !== false) {
          const a = document.createElement("a");
          a.href = downloadUrl;
          a.download = opts.password
            ? `${opts.fileName}.enc`
            : `${opts.fileName}.tar.gz`;
          a.click();
          setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
        }
        if (opts.onsuccess) opts.onsuccess(downloadUrl);
      } else if (!opts.download && opts.onsuccess) {
        opts.onsuccess(null);
      }

      logger("Export complete!");
    } catch (e) {
      try {
        await outputStream.abort(e).catch(() => {});
      } catch (z) {}
      if (opts.onerror) opts.onerror(e);
      else throw e;
    }
  }

  async function importData(config = {}) {
    const CBOR = window.CBOR;

    const opts = {
      opfs: true,
      localStorage: true,
      session: true,
      cookies: true,
      idb: true,
      cache: true,
      logSpeed: 100,
      graceful: false,
      ...config,
    };

    const sourceInput = opts.source;
    if (!sourceInput) {
      throw new Error(
        "No source provided. Pass a URL, Blob, or File via the 'source' property.",
      );
    }

    const logger = opts.logger || (() => {});
    const yielder = createYielder(opts.logSpeed);
    const graceful = opts.graceful;
    const useOnVisit = typeof opts.onVisit === "function";
    const onVisit = opts.onVisit;

    let aborted = false;
    const categoryDecisions = {};
    const trustedPaths = {};

    function getDecision(type, path, meta) {
      if (!useOnVisit) return DECISION.TRUST;
      return onVisit(type, path, meta);
    }

    async function tryGraceful(fn, context) {
      try {
        return await fn();
      } catch (e) {
        if (graceful) {
          if (opts.onerror) opts.onerror(e);
          logger(`Warning: ${context} - ${e.message}`);
          return null;
        }
        throw e;
      }
    }

    async function shouldProcess(type, pathArray, pathStr, categoryKey) {
      if (aborted) return false;

      if (categoryDecisions[categoryKey] === undefined) {
        if (useOnVisit) {
          let decision = getDecision(type, undefined, undefined);
          if (decision && typeof decision.then === "function")
            decision = await decision;
          categoryDecisions[categoryKey] = decision;

          if (categoryDecisions[categoryKey] === DECISION.ABORT) {
            aborted = true;
            return false;
          }
        } else {
          categoryDecisions[categoryKey] = DECISION.TRUST;
        }
      }

      if (categoryDecisions[categoryKey] === DECISION.SKIP) return false;
      if (categoryDecisions[categoryKey] === DECISION.TRUST) return true;

      if (useOnVisit && pathArray) {
        if (!trustedPaths[categoryKey]) trustedPaths[categoryKey] = new Set();

        for (let i = 1; i <= pathArray.length; i++) {
          const parentKey = pathArray.slice(0, i).join("/");
          if (trustedPaths[categoryKey].has(parentKey)) return true;
        }

        let decision = getDecision(type, pathArray, null);
        if (decision && typeof decision.then === "function")
          decision = await decision;

        if (decision === DECISION.ABORT) {
          aborted = true;
          return false;
        }
        if (decision === DECISION.SKIP) return false;
        if (decision === DECISION.TRUST) {
          trustedPaths[categoryKey].add(pathArray.join("/"));
        }
        return true;
      } else if (!useOnVisit) {
        return checkSimpleFilter(categoryKey, pathStr, opts);
      }

      return true;
    }

    let currentContext = { category: "Init", detail: "..." };

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
          const toSkip = Math.min(streamBuffer.totalSize, n);
          streamBuffer.read(toSkip);
          n -= toSkip;
        }
      }

      async function streamToWriter(writer, size) {
        try {
          let remaining = size;
          while (remaining > 0) {
            const p = yielder();
            if (p) {
              const mb = (totalRead / 1048576).toFixed(2);
              logger(
                `Importing ${currentContext.category}: ${mb} MB (${currentContext.detail})`,
              );
              await p;
            }
            if (streamBuffer.totalSize > 0) {
              let chunk = streamBuffer.read(
                Math.min(remaining, streamBuffer.totalSize),
              );
              await writer.write(chunk);
              remaining -= chunk.byteLength;
            } else {
              let { value, done: d } = await reader.read();
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
        } finally {
          await writer.close();
        }
      }

      const rootOpfs = await navigator.storage.getDirectory();
      let tempBlobDir;
      try {
        tempBlobDir = await rootOpfs.getDirectoryHandle(TEMP_BLOB_DIR, {
          create: true,
        });
      } catch (e) {}

      const dbCache = {};
      const processedDbSchemas = new Set();

      while (!aborted) {
        if (!(await ensure(512))) break;
        const header = streamBuffer.read(512);
        if (header.every((b) => b === 0)) break;

        let name = DEC.decode(header.slice(0, 100)).replace(/\0/g, "").trim();
        const prefix = DEC.decode(header.slice(345, 500))
          .replace(/\0/g, "")
          .trim();
        if (prefix) name = `${prefix}/${name}`;

        if (name.startsWith("data/idb/")) {
          currentContext.category = "IndexedDB";
          const parts = name.split("/");
          currentContext.detail = parts[2]
            ? decodeURIComponent(parts[2])
            : "data";
        } else if (name.startsWith("data/cache/")) {
          currentContext.category = "Cache";
          const parts = name.split("/");
          currentContext.detail = parts[2]
            ? decodeURIComponent(parts[2])
            : "item";
        } else if (name.startsWith("opfs/")) {
          currentContext.category = "OPFS";
          currentContext.detail = name.replace("opfs/", "");
        } else if (name.startsWith("data/blobs/")) {
          currentContext.category = "Blobs";
          currentContext.detail = "restoring...";
        } else {
          currentContext.category = "Config";
          currentContext.detail = name;
        }

        const p = yielder();
        if (p) {
          logger(
            `Importing ${currentContext.category}: ${(totalRead / 1048576).toFixed(2)} MB (${currentContext.detail})`,
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
              let dataConsumed = false;
              await tryGraceful(async () => {
                const fh = await tempBlobDir.getFileHandle(uuid, {
                  create: true,
                });
                dataConsumed = true;
                await streamToWriter(await fh.createWritable(), size);
              }, `Blob ${uuid}`);
              if (!dataConsumed) {
                await skip(size);
              }
            } else {
              await skip(size);
            }
            await skip(padding);
            continue;
          } else {
            if (size === 0) {
              await skip(padding);
              continue;
            }
            if (!(await ensure(size)))
              throw new Error("Unexpected EOF for metadata");
            const d = streamBuffer.read(size);

            // localStorage
            if (name === "data/ls.json" && opts.localStorage !== false) {
              if (await shouldProcess(TYPE.LS, null, null, "localStorage")) {
                const data = JSON.parse(DEC.decode(d));
                const trustAll =
                  categoryDecisions["localStorage"] === DECISION.TRUST;

                for (const k in data) {
                  if (aborted) break;

                  let shouldSet = trustAll;

                  if (!shouldSet) {
                    if (useOnVisit) {
                      let keyDecision = getDecision(TYPE.LS, [k], {
                        value: data[k],
                      });
                      if (keyDecision && typeof keyDecision.then === "function")
                        keyDecision = await keyDecision;

                      if (keyDecision === DECISION.ABORT) {
                        aborted = true;
                        break;
                      }
                      shouldSet = keyDecision !== DECISION.SKIP;
                    } else {
                      shouldSet = checkSimpleFilter("localStorage", k, opts);
                    }
                  }

                  if (shouldSet) {
                    localStorage.setItem(k, data[k]);
                  }
                }
              }
            }
            // sessionStorage
            else if (name === "data/ss.json" && opts.session !== false) {
              if (await shouldProcess(TYPE.SS, null, null, "session")) {
                const data = JSON.parse(DEC.decode(d));
                const trustAll =
                  categoryDecisions["session"] === DECISION.TRUST;

                for (const k in data) {
                  if (aborted) break;

                  let shouldSet = trustAll;

                  if (!shouldSet) {
                    if (useOnVisit) {
                      let keyDecision = getDecision(TYPE.SS, [k], {
                        value: data[k],
                      });
                      if (keyDecision && typeof keyDecision.then === "function")
                        keyDecision = await keyDecision;

                      if (keyDecision === DECISION.ABORT) {
                        aborted = true;
                        break;
                      }
                      shouldSet = keyDecision !== DECISION.SKIP;
                    } else {
                      shouldSet = checkSimpleFilter("session", k, opts);
                    }
                  }

                  if (shouldSet) {
                    sessionStorage.setItem(k, data[k]);
                  }
                }
              }
            }
            // Cookies
            else if (name === "data/cookies.json" && opts.cookies !== false) {
              if (await shouldProcess(TYPE.COOKIE, null, null, "cookies")) {
                const c = JSON.parse(DEC.decode(d));
                const trustAll =
                  categoryDecisions["cookies"] === DECISION.TRUST;

                for (const k in c) {
                  if (aborted) break;

                  let shouldSet = trustAll;

                  if (!shouldSet) {
                    if (useOnVisit) {
                      let keyDecision = getDecision(TYPE.COOKIE, [k], {
                        value: c[k],
                      });
                      if (keyDecision && typeof keyDecision.then === "function")
                        keyDecision = await keyDecision;

                      if (keyDecision === DECISION.ABORT) {
                        aborted = true;
                        break;
                      }
                      shouldSet = keyDecision !== DECISION.SKIP;
                    } else {
                      shouldSet = checkSimpleFilter("cookies", k, opts);
                    }
                  }

                  if (shouldSet) {
                    document.cookie = `${k}=${c[k]}; path=/; max-age=31536000`;
                  }
                }
              }
            }
            // Custom items
            else if (name.startsWith("data/custom/") && opts.onCustomItem) {
              await opts.onCustomItem(name.replace("data/custom/", ""), d);
            }
            // IndexedDB
            else if (
              name.startsWith("data/idb/") &&
              CBOR &&
              opts.idb !== false
            ) {
              const parts = name.split("/");
              const dbName = decodeURIComponent(parts[2]);

              if (name.endsWith("schema.cbor")) {
                if (!(await shouldProcess(TYPE.IDB, [dbName], dbName, "idb")))
                  continue;

                const schema = CBOR.decode(d);
                processedDbSchemas.add(dbName);

                if (dbCache[dbName]) {
                  dbCache[dbName].close();
                  delete dbCache[dbName];
                }

                await tryGraceful(async () => {
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
                }, `IDB schema ${dbName}`);
              } else {
                const storeName = decodeURIComponent(parts[3]);

                if (!processedDbSchemas.has(dbName)) continue;

                if (
                  !(await shouldProcess(
                    TYPE.IDB,
                    [dbName, storeName],
                    `${dbName}/${storeName}`,
                    "idb",
                  ))
                )
                  continue;

                const decoded = CBOR.decode(d);
                const [keys, values] = await restoreFromCBOR(
                  decoded,
                  tempBlobDir,
                );

                if (!dbCache[dbName]) {
                  const db = await tryGraceful(async () => {
                    return await new Promise((resolve, reject) => {
                      const req = indexedDB.open(dbName);
                      const timeout = setTimeout(
                        () => reject(new Error(`Database ${dbName} timed out`)),
                        5000,
                      );
                      req.onblocked = () => {
                        clearTimeout(timeout);
                        reject(new Error(`Database ${dbName} blocked`));
                      };
                      req.onsuccess = () => {
                        clearTimeout(timeout);
                        resolve(req.result);
                      };
                      req.onerror = () => {
                        clearTimeout(timeout);
                        reject(req.error);
                      };
                    });
                  }, `Opening IDB ${dbName}`);

                  if (!db) continue;
                  dbCache[dbName] = db;
                }

                await tryGraceful(async () => {
                  const tx = dbCache[dbName].transaction(
                    storeName,
                    "readwrite",
                  );
                  const st = tx.objectStore(storeName);
                  for (let i = 0; i < keys.length; i++) {
                    st.put(values[i], st.keyPath ? undefined : keys[i]);
                  }
                  await new Promise((res, rej) => {
                    tx.oncomplete = res;
                    tx.onerror = () => rej(tx.error);
                    tx.onabort = () => rej(new Error("Transaction aborted"));
                  });
                }, `IDB ${dbName}/${storeName}`);
              }
            }
            // Cache storage
            else if (
              name.startsWith("data/cache/") &&
              CBOR &&
              opts.cache !== false
            ) {
              const parts = name.split("/");
              const cacheName = decodeURIComponent(parts[2]);

              if (
                await shouldProcess(TYPE.CACHE, [cacheName], cacheName, "cache")
              ) {
                await tryGraceful(async () => {
                  const data = CBOR.decode(d);
                  const cache = await caches.open(cacheName);
                  const response = new Response(data.data, {
                    status: data.meta.status,
                    headers: data.meta.headers,
                  });
                  await cache.put(data.meta.url, response);
                }, `Cache ${cacheName}`);
              }
            }
          }
        } else {
          // OPFS files and directories
          if (opts.opfs !== false) {
            const cleanName = name.startsWith("opfs/") ? name.slice(5) : name;
            const isDirectory = cleanName.endsWith("/") || header[156] === 53;
            const normalizedName = cleanName.replace(/\/$/, "");
            const parts = normalizedName.split("/").filter((p) => p.length);

            if (parts.length > 0) {
              const pathArray = [...parts];

              if (
                await shouldProcess(
                  TYPE.OPFS,
                  pathArray,
                  normalizedName,
                  "opfs",
                )
              ) {
                await tryGraceful(async () => {
                  let dir = rootOpfs;
                  if (isDirectory) {
                    for (const p of parts) {
                      dir = await dir.getDirectoryHandle(p, { create: true });
                    }
                  } else {
                    const fname = parts[parts.length - 1];
                    const dirParts = parts.slice(0, -1);
                    for (const p of dirParts) {
                      dir = await dir.getDirectoryHandle(p, { create: true });
                    }
                    const fh = await dir.getFileHandle(fname, { create: true });
                    if (size > 0) {
                      await streamToWriter(await fh.createWritable(), size);
                    } else {
                      const w = await fh.createWritable();
                      await w.close();
                    }
                  }
                }, `OPFS ${normalizedName}`);
              } else {
                await skip(size);
              }
            } else {
              await skip(size);
            }
          } else {
            await skip(size);
          }
        }
        await skip(padding);
      }

      Object.values(dbCache).forEach((d) => d.close());

      if (tempBlobDir) {
        try {
          await rootOpfs.removeEntry(TEMP_BLOB_DIR, { recursive: true });
        } catch (e) {}
      }

      if (!aborted) {
        logger("Import complete!");
        if (opts.onsuccess) opts.onsuccess();
      }
    } catch (e) {
      logger("Error: " + e.message);
      if (opts.onerror) opts.onerror(e);
      else throw e;
    }
  }

  window.LittleExport = { importData, exportData, deriveKey, TYPE, DECISION };
})();
