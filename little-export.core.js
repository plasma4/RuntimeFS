(function () {
  const TYPE = { OPFS: 1, IDB: 2, LS: 4, SS: 8, COOKIE: 16, CACHE: 32 };
  const DECISION = { SKIP: 0, PROCESS: 1, TRUST: 2, ABORT: 3 };

  let blobIdCounter = 0;

  function createYielder(threshold = 100) {
    // Testing has shown that Chromium's performance.now() is worst-case slower than all other browsers (but can still be called millions of times per second). Date.now() Browsers like Firefox actually have performance.now() over 10x faster than Date.now(), upwards of hundreds of millions of checks per second. However, this shouldn't really matter too much here as yielding is not checked often enough for this to add up significantly.
    let lastYield = 0;
    let inflight = null;

    const channel = new MessageChannel();
    const resolvers = [];
    channel.port1.onmessage = () => resolvers.shift()?.();

    async function doYield() {
      if ("scheduler" in window && "yield" in scheduler) {
        await scheduler.yield();
      } else {
        await new Promise((res) => {
          resolvers.push(res);
          channel.port2.postMessage(null);
        });
      }
      lastYield = Date.now();
      inflight = null;
    }

    return function (force = false) {
      const now = Date.now();
      if (!force && now - lastYield <= threshold) return null;
      if (!inflight) inflight = doYield();
      return inflight;
    };
  }

  const CHUNK_SIZE = 4194304;
  const TAR_BUFFER_SIZE = 65536;
  const ENC = new TextEncoder();
  const DEC = new TextDecoder("utf-8", { fatal: false });
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
        if (filter.some((t) => pathStr === t || pathStr.startsWith(t + "/")))
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

  function prepForCBOR(item, externalBlobs, seen = new WeakMap()) {
    if (!item || typeof item !== "object") return item;

    // Passthrough types (add others if needed)
    if (
      item instanceof ArrayBuffer ||
      ArrayBuffer.isView(item) ||
      item instanceof Date
    ) {
      return item;
    }

    // Handle Cycles: Return the reference to the object currently being built
    if (seen.has(item)) return seen.get(item);

    // Extract Blobs
    if (item instanceof Blob) {
      const id = (blobIdCounter++).toString(36);
      externalBlobs.push({ uuid: id, blob: item });
      // Note: We don't cache Blobs in 'seen' as they aren't recursive
      return { __le_blob_ref: id, type: item.type, size: item.size };
    }

    let res;

    if (Array.isArray(item)) {
      const keys = Object.keys(item);
      // Sparse Array Detection
      const isSparse = keys.length < item.length || keys.some((k) => isNaN(k));

      if (isSparse) {
        res = { __le_type: "sparse_array", length: item.length, data: {} };
        seen.set(item, res); // Register before recursion
        for (const k of keys) {
          res.data[k] = LittleExport.prepForCBOR(item[k], externalBlobs, seen);
        }
      } else {
        res = new Array(item.length);
        seen.set(item, res); // Register before recursion
        for (let i = 0; i < item.length; i++) {
          res[i] = LittleExport.prepForCBOR(item[i], externalBlobs, seen);
        }
      }
    } else {
      // Plain Object
      res = {};
      seen.set(item, res); // Register before recursion
      for (const k in item) {
        if (Object.prototype.hasOwnProperty.call(item, k)) {
          res[k] = LittleExport.prepForCBOR(item[k], externalBlobs, seen);
        }
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
    if (item.__le_type === "sparse_array") {
      const arr = new Array(item.length);
      // data contains the indices
      for (const k in item.data) {
        arr[k] = await LittleExport.restoreFromCBOR(item.data[k], tempBlobDir);
      }
      return arr;
    }

    if (Array.isArray(item)) {
      const res = new Array(item.length);
      for (let i = 0; i < item.length; i++) {
        res[i] = await LittleExport.restoreFromCBOR(item[i], tempBlobDir);
      }
      return res;
    }

    if (item.constructor === Object) {
      const n = {};
      for (const k in item) {
        n[k] = await LittleExport.restoreFromCBOR(item[k], tempBlobDir);
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
    w("000644 \0", 100);
    w("000000 \0", 108);
    w("000000 \0", 116);
    HEADER_TEMPLATE.set(TAR_CONSTANTS.EMPTY_SPACE, 148);
    HEADER_TEMPLATE[156] = 48;
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_MAGIC, 257);
    HEADER_TEMPLATE.set(TAR_CONSTANTS.USTAR_VER, 263);
  })();

  function createPaxData(path, size) {
    const encoder = new TextEncoder();
    let content = new Uint8Array(0);

    const addRecord = (keyword, value) => {
      if (value === null || value === undefined) return;
      const strVal = String(value);
      // Format: "length keyword=value\n"
      const suffix = ` ${keyword}=${strVal}\n`;
      const suffixBytes = encoder.encode(suffix);

      // Calculate total length (bytes of length string + space + bytes of suffix)
      let total = suffixBytes.length;
      let lenStr = String(total);

      // Adjust length until it stabilizes (e.g. 9 -> 10 adds a digit)
      while (true) {
        const newTotal = suffixBytes.length + lenStr.length;
        if (newTotal === total) break;
        total = newTotal;
        lenStr = String(total);
      }

      const line = encoder.encode(`${lenStr}${suffix}`);
      const newContent = new Uint8Array(content.length + line.length);
      newContent.set(content);
      newContent.set(line, content.length);
      content = newContent;
    };

    addRecord("path", path);
    if (size > 8589934591) {
      addRecord("size", size);
    }

    return content;
  }

  function createTarHeader(filename, size, time, type = "0", mode = "000644") {
    const safeSize = size > 8589934591 ? 0 : size;
    const buffer = HEADER_TEMPLATE.slice(0);

    // 0=file, 5=dir, x=pax
    buffer[156] = type.charCodeAt(0);

    // Write filename
    const nameBytes = ENC.encode(filename);
    if (nameBytes.length > 100) {
      let cut = 100;
      while (cut > 0 && (nameBytes[cut] & 0xc0) === 0x80) cut--;
      buffer.set(nameBytes.subarray(0, cut), 0);
    } else {
      buffer.set(nameBytes, 0);
    }

    if (mode) {
      ENC.encodeInto(mode.padEnd(7, "\0"), buffer.subarray(100, 108));
    }

    const writeOctal = (num, offset, len) => {
      const str = Math.floor(num)
        .toString(8)
        .padStart(len - 1, "0");
      if (str.length >= len) return;
      ENC.encodeInto(str, buffer.subarray(offset, offset + len - 1));
      buffer[offset + len - 1] = 0; // Space/null termination
    };

    writeOctal(safeSize, 124, 12);
    writeOctal(time, 136, 12);

    let sum = 0;
    for (let i = 0; i < 512; i++) {
      sum += buffer[i];
    }

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
      const size = bytes.byteLength;
      await this.smartWrite(path, size, async () => {
        await this.write(bytes);
      });
    }

    async checkAndWritePax(path, size) {
      const needsPaxPath = ENC.encode(path).length > 100;
      const needsPaxSize = size > 8589934591;

      if (needsPaxPath || needsPaxSize) {
        const paxData = createPaxData(path, size);
        const safeName =
          "PaxHeaders/" + (path.length > 50 ? path.slice(0, 50) : path);

        const paxHeader = createTarHeader(
          safeName,
          paxData.length,
          this.time,
          "x",
        );
        await this.write(paxHeader);
        await this.write(paxData);
        await this.pad();
        return true;
      }
      return false;
    }

    async writeStream(path, size, readableStream) {
      let contentWritten = 0; // Use a local variable for pure content tracking
      await this.smartWrite(path, size, async () => {
        const reader = readableStream.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            await this.write(value);
            contentWritten += value.byteLength;
            if (this.onFileProgress) this.onFileProgress(contentWritten, size);
            const p = this.yielder();
            if (p) await p;
          }
        } finally {
          reader.releaseLock();
        }
      });
    }

    async smartWrite(path, size, contentFn) {
      const pathBytes = ENC.encode(path); // byte length matters, not string
      const needsPax = pathBytes.length > 100 || size > 8589934591;

      if (needsPax) {
        const paxData = createPaxData(path, size);
        const safePaxName =
          "PaxHeaders/" + (path.length > 50 ? path.slice(0, 50) : path);

        await this.write(
          createTarHeader(safePaxName, paxData.length, this.time, "x"),
        );
        await this.write(paxData);
        await this.pad();
      }

      await this.write(
        createTarHeader(
          path,
          size,
          this.time,
          size === 0 && path.endsWith("/") ? "5" : "0",
        ),
      );
      const prevFileProgress = this.bytesWritten;
      this.bytesWritten = 0;
      if (contentFn) await contentFn();
      await this.pad();
      this.bytesWritten = 0;
    }

    async writeDir(path) {
      await this.checkAndWritePax(path, 0);
      const header = createTarHeader(path, 0, this.time, "5", "000755");
      await this.write(header);
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
      if (padding > 0) await this.write(new Uint8Array(padding));
    }

    async flush() {
      if (this.bufferOffset > 0) {
        await this.writer.write(this.buffer.subarray(0, this.bufferOffset));
        this.bufferOffset = 0;
      }
    }

    async close() {
      await this.write(new Uint8Array(1024)); // EOF
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

    _internalConsume(n, callback) {
      let consumed = 0;
      while (consumed < n) {
        const chunk = this.chunks[0];
        const remainingNeeded = n - consumed;
        const toTake = Math.min(chunk.byteLength, remainingNeeded);

        // Provide the segment to the requester
        callback(chunk.subarray(0, toTake));

        if (toTake === chunk.byteLength) {
          this.chunks.shift();
        } else {
          this.chunks[0] = chunk.subarray(toTake);
        }

        this.totalSize -= toTake;
        consumed += toTake;
      }
    }

    read(n) {
      if (n === 0) return new Uint8Array(0);
      if (this.totalSize < n) throw new Error("Insufficient data");

      if (this.chunks[0].byteLength >= n) {
        const res = this.chunks[0].subarray(0, n);
        if (this.chunks[0].byteLength === n) this.chunks.shift();
        else this.chunks[0] = this.chunks[0].subarray(n);
        this.totalSize -= n;
        return res;
      }

      const result = new Uint8Array(n);
      let offset = 0;
      this._internalConsume(n, (seg) => {
        result.set(seg, offset);
        offset += seg.byteLength;
      });
      return result;
    }

    async consume(n, callback) {
      let remaining = n;
      while (remaining > 0) {
        const chunk = this.chunks[0];
        const toProcess = Math.min(chunk.byteLength, remaining);

        // Pass the existing memory view to the callback
        await callback(chunk.subarray(0, toProcess));

        if (toProcess === chunk.byteLength) {
          this.chunks.shift();
        } else {
          this.chunks[0] = chunk.subarray(toProcess);
        }

        this.totalSize -= toProcess;
        remaining -= toProcess;
      }
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

            if (initLen !== 16 || !(await ensure(initLen)))
              throw new Error("Corrupt header");
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

  function verifyChecksum(header) {
    // Checksum is at offset 148, length 8
    const claimed = parseInt(DEC.decode(header.slice(148, 156)).trim(), 8);
    if (isNaN(claimed)) return false;

    // Calculate sum of bytes
    let sum = 0;
    for (let i = 0; i < 512; i++) {
      // The 8 bytes at 148 must be treated as spaces (ASCII 32)
      if (i >= 148 && i < 156) sum += 32;
      else sum += header[i];
    }
    return sum === claimed;
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
      cborExtensionName: "cbor",
      ...config,
    };

    const encoder =
      opts.encoder ||
      new CBOR.Encoder({
        copyBuffers: false,
        bundleStrings: true, // Optimization for strings at the cost of inconsistency with the formal CBOR spec (and lack of explicit documentation in cbor-x to parse). See the LittleExport README for more information.
        ...opts.cborOptions,
      });

    const cborExtensionName = opts.cborExtensionName;
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
          logger(`Error: ${context} - ${e.message}`);
          return null;
        }
        throw e;
      }
    }

    const status = { category: "", detail: "" };

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
          if (status.category)
            if (status.category === "Finishing") {
              logger("Finishing...");
            } else {
              let msg = `Exporting ${status.category}: ${(outputBytesWritten / 1e6).toFixed(2)} MB`;
              if (currentFileProgress.total > 1e6) {
                msg += ` (${status.detail}: ${(currentFileProgress.written / 1e6).toFixed(1)}/${(currentFileProgress.total / 1e6).toFixed(1)} MB)`;
              } else {
                msg += ` (${status.detail})`;
              }
              logger(msg);
            }
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

    let currentFileProgress = { written: 0, total: 0 };
    const exportFinishedPromise = pipeline
      .pipeThrough(countingStream)
      .pipeTo(outputStream);
    const tar = new TarWriter(gzip.writable, yielder);
    tar.onFileProgress = (written, total) => {
      currentFileProgress.written = written;
      currentFileProgress.total = total;
    };

    try {
      // Custom items (always processed)
      for (const item of opts.customItems) {
        if (aborted) break;
        status.category = "custom";
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
            try {
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
                    await tar.writeStream(
                      `opfs/${pathStr}`,
                      f.size,
                      f.stream(),
                    );
                  }, `OPFS file ${pathStr}`);
                } else {
                  // Write directory entry
                  await tar.writeDir(`opfs/${pathStr}`);
                  // Recurse
                  await walkOpfs(
                    entry,
                    currentPath,
                    trustChildren ? DECISION.TRUST : false,
                  );
                }

                const p = yielder();
                if (p) await p;
              }
            } catch (e) {
              // Log error but allow other folders to continue processing
              logger(
                `Error: accessing OPFS folder /${pathArray.join("/")} failed (${e.message})`,
              );
              if (opts.onerror) opts.onerror(e);
              if (!graceful) throw e;
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
                  `data/idb/${safeName}/schema.${cborExtensionName}`,
                  encoder.encode({ name, version, stores: [] }),
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
                `data/idb/${safeName}/schema.${cborExtensionName}`,
                encoder.encode({ name, version, stores }),
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

                status.detail = `${name}/${sName}`;

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
                      const cleanValue = LittleExport.prepForCBOR(
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
                      `data/idb/${safeName}/${encodeURIComponent(sName)}/${chunkId++}.${cborExtensionName}`,
                      encoder.encode([batch.keys, processedValues]),
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

            status.detail = `Cookie: ${key}`;
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
                const blobsInItem = [];
                const cleanData = LittleExport.prepForCBOR(blob, blobsInItem);

                // Write the external blobs (the large file body)
                for (const b of blobsInItem) {
                  await tar.writeStream(
                    `data/blobs/${b.uuid}`,
                    b.blob.size,
                    b.blob.stream(),
                  );
                }

                // Write the metadata record containing the reference
                await tar.writeEntry(
                  `data/cache/${encodeURIComponent(cacheName)}/${safeHash}.${cborExtensionName}`,
                  encoder.encode({
                    meta: {
                      url: req.url,
                      status: res.status,
                      headers: Object.fromEntries(res.headers),
                      type: blob.type,
                    },
                    data: cleanData,
                  }),
                );
              }
            }, `Cache ${cacheName}`);
          }
        }
      }

      status.category = "finishing";
      status.detail = "almost done";
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
          let fileName = opts.fileName;
          a.download = fileName.includes(".")
            ? fileName
            : opts.password
              ? `${fileName}.enc`
              : `${fileName}.tar.gz`;
          a.click();
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
      logger(`Error: ${context} - ${e.message}`);
      if (opts.onerror) opts.onerror(e);
      if (!graceful) throw e;
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

    const decoder =
      opts.decoder ||
      new CBOR.Decoder({
        structuredClone: true, // Circular references may cause errors/problems if disabled.
        bundleStrings: true, // Optimization for strings at the cost of inconsistency with the formal CBOR spec (and lack of explicit documentation in cbor-x to parse). See the LittleExport README for more information.
        copyBuffers: false, // Free optimization of preventing copying of buffers (less memory use).
        // implied
        ...opts.cborOptions,
      });

    const cborExtensionName = opts.cborExtensionName;
    let sourceInput = opts.source;
    if (!sourceInput) {
      throw new Error(
        "No source provided. Pass a URL, Blob, or File via the source config property.",
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
        if (opts.onerror) opts.onerror(e);
        logger(`Error: ${context} - ${e.message}`);
        if (!graceful) throw e;
        return null;
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

    let status = { category: "", detail: "" };
    const dbCache = {};

    try {
      let rawStream;
      if (typeof sourceInput === "string") {
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

      let totalRead = 0;
      const combinedStream = new ReadableStream({
        async start(controller) {
          for (const chunk of initialChunks) {
            totalRead += chunk.byteLength;
            controller.enqueue(chunk);
          }
          const reader = rawStream.getReader();
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              totalRead += value.byteLength;
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

          const chunk = streamBuffer.chunks[0];
          const toSkip = Math.min(chunk.byteLength, n);

          if (toSkip === chunk.byteLength) {
            streamBuffer.chunks.shift(); // Drop the whole chunk
          } else {
            streamBuffer.chunks[0] = chunk.subarray(toSkip); // Slice (Cheap View)
          }

          streamBuffer.totalSize -= toSkip;
          n -= toSkip;
        }
      }

      async function streamToWriter(writer, size) {
        try {
          let remaining = size;
          while (remaining > 0) {
            const p = yielder();
            if (p) {
              let msg = `Importing ${status.category}: ${(totalRead / 1e6).toFixed(2)} MB`;
              if (size > 1e6) {
                msg += ` (${status.detail}: ${((size - remaining) / 1e6).toFixed(1)}/${(size / 1e6).toFixed(1)} MB)`;
              } else {
                msg += ` (${status.detail})`;
              }
              logger(msg);
              await p;
            }

            if (streamBuffer.totalSize > 0) {
              const batchSize = Math.min(remaining, streamBuffer.totalSize);
              await streamBuffer.consume(batchSize, async (chunk) => {
                await writer.write(chunk);
                remaining -= chunk.byteLength;
              });
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
          try {
            await writer.close();
          } catch (e) {}
        }
      }

      const rootOpfs = await navigator.storage.getDirectory();
      let tempBlobDir;
      try {
        tempBlobDir = await rootOpfs.getDirectoryHandle(TEMP_BLOB_DIR, {
          create: true,
        });
      } catch (e) {}

      const processedDbSchemas = new Set();

      function parsePax(paxBytes) {
        const res = {};
        let pos = 0;
        while (pos < paxBytes.length) {
          // Find the first space to get the length
          let spacePos = -1;
          for (let i = pos; i < paxBytes.length; i++) {
            if (paxBytes[i] === 32) {
              spacePos = i;
              break;
            }
          }
          if (spacePos === -1) break;

          const lenStr = DEC.decode(paxBytes.subarray(pos, spacePos));
          const len = parseInt(lenStr, 10);
          if (isNaN(len)) break;

          // Slice the exact byte range for this record
          const recordBytes = paxBytes.subarray(pos, pos + len);
          const recordStr = DEC.decode(recordBytes);

          const eq = recordStr.indexOf("=");
          if (eq !== -1) {
            const spaceIdx = recordStr.indexOf(" ");
            const key = recordStr.slice(spaceIdx + 1, eq);
            const val = recordStr.slice(eq + 1, -1); // remove trailing \n
            res[key] = val;
          }
          pos += len;
        }
        return res;
      }

      let paxOverrides = null;

      while (!aborted) {
        const hasHeader = await ensure(512);

        if (!hasHeader) {
          // Stream ended but we never saw the two null blocks
          if (!foundEofMarker) {
            throw new Error("Archive truncated: Stream ended prematurely.");
          }
          break;
        }

        const header = streamBuffer.read(512);

        // Check for the first EOF block (all zeros)
        if (header[0] === 0 && header.every((b) => b === 0)) {
          foundEofMarker = true;
          continue;
        }

        if (!verifyChecksum(header)) {
          throw new Error("Corrupt TAR header: Checksum mismatch.");
        }

        let name = DEC.decode(header.slice(0, 100)).replace(/\0/g, "").trim();
        const typeFlag = header[156]; // '0', '5', 'x'
        const sizeStr = DEC.decode(header.slice(124, 136))
          .replace(/\0/g, "")
          .trim();
        const entrySize = parseInt(sizeStr, 8) || 0;
        const padding = (512 - (entrySize % 512)) % 512;

        if (typeFlag === 120) {
          if (!(await ensure(entrySize)))
            throw new Error("Unexpected EOF in PAX");
          const paxBytes = streamBuffer.read(entrySize);
          await skip(padding);
          paxOverrides = parsePax(paxBytes);
          continue; // Move to the next block which contains the actual file
        }

        let size = entrySize;
        if (paxOverrides) {
          if (paxOverrides.path) name = paxOverrides.path;
          if (paxOverrides.size) size = parseInt(paxOverrides.size, 10);
          paxOverrides = null;
        }

        if (name.startsWith("data/idb/")) {
          status.category = "IndexedDB";
          const parts = name.split("/");
          status.detail = parts[2] ? decodeURIComponent(parts[2]) : "data";
        } else if (name.startsWith("data/cache/")) {
          status.category = "Cache";
          const parts = name.split("/");
          status.detail = parts[2] ? decodeURIComponent(parts[2]) : "item";
        } else if (name.startsWith("opfs/")) {
          status.category = "OPFS";
          status.detail = name.replace("opfs/", "");
        } else if (name.startsWith("data/blobs/")) {
          status.category = "Blobs";
          status.detail = "restoring...";
        } else {
          status.category = "Config";
          status.detail = name;
        }

        const p = yielder();
        if (p) {
          if (status.category)
            logger(
              `Importing ${status.category}: ${(totalRead / 1e6).toFixed(2)} MB (${status.detail})`,
            );
          await p;
        }

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

              if (name.endsWith("schema." + cborExtensionName)) {
                if (!(await shouldProcess(TYPE.IDB, [dbName], dbName, "idb")))
                  continue;

                const schema = decoder.decode(d);
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

                const decoded = decoder.decode(d);
                const [keys, values] = await LittleExport.restoreFromCBOR(
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
                  const data = decoder.decode(d);
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

      if (tempBlobDir) {
        try {
          await rootOpfs.removeEntry(TEMP_BLOB_DIR, { recursive: true });
        } catch (e) {}
      }

      Object.values(dbCache).forEach((d) => d.close());
      if (!aborted) {
        logger("Import complete!");
      }
    } catch (e) {
      Object.values(dbCache).forEach((d) => {
        try {
          d.close();
        } catch (e) {}
      });

      logger(`Error: ${e.message}`);
      if (opts.onerror) opts.onerror(e);
      if (!graceful) throw e;
    }
  }

  function folderToTarStream(source, yielder) {
    const { readable, writable } = new TransformStream();
    // Generate stream on the fly
    const tar = new TarWriter(writable, yielder);

    (async () => {
      try {
        if (
          window.FileSystemDirectoryHandle &&
          source instanceof FileSystemDirectoryHandle
        ) {
          async function walk(dir, pathPrefix) {
            for await (const [name, entry] of dir.entries()) {
              if (entry.kind === "directory" && name === "PaxHeaders") continue;
              const fullPath = pathPrefix ? `${pathPrefix}/${name}` : name;

              if (entry.kind === "file") {
                const file = await entry.getFile();
                await tar.writeStream(fullPath, file.size, file.stream());
              } else if (entry.kind === "directory") {
                await tar.writeDir(fullPath);
                await walk(entry, fullPath);
              }
            }
          }
          await walk(source, "");
        } else if (
          source instanceof FileList ||
          (Array.isArray(source) && source[0] instanceof File)
        ) {
          const files = Array.from(source);
          const relativePath = files[0].webkitRelativePath;
          const rootName = relativePath ? relativePath.split("/")[0] + "/" : ""; // Only strip root if webkitRelativePath exists (indicates folder upload)

          for (const file of files) {
            let path = file.webkitRelativePath;
            if (path.startsWith(rootName)) {
              path = path.slice(rootName.length);
            }

            if (!path) path = file.name;
            await tar.writeStream(path, file.size, file.stream());
          }
        }
        await tar.close();
      } catch (e) {
        try {
          await writable.abort(e);
        } catch (e) {}
      }
    })();

    return readable;
  }

  async function importFromFolder(config = {}) {
    const opts = { ...config };
    const yielder = createYielder(opts.logSpeed);

    // Helper to run the importData logic using our custom stream
    const runImport = (streamSource) => {
      return importData({
        ...opts,
        source: {
          stream: () => streamSource,
        },
      });
    };

    if (window.showDirectoryPicker && opts.legacy !== true) {
      try {
        const handle = await window.showDirectoryPicker();
        const stream = folderToTarStream(handle, yielder);
        return await runImport(stream);
      } catch (e) {
        if (e.name === "AbortError") {
          logger("User cancelled the directory picker.");
          return; // User cancelled
        }
        logger("Directory Picker failed, falling back to legacy input.");
        console.warn(
          "Directory Picker failed, falling back to legacy input.",
          e,
        );
      }
    }

    return new Promise((resolve, reject) => {
      const input = document.createElement("input");
      input.type = "file";
      input.webkitdirectory = true;
      input.multiple = true;
      input.style.display = "none";
      document.body.appendChild(input);

      input.onchange = async () => {
        if (!input.files || input.files.length === 0) {
          resolve(); // Cancelled or empty
          return;
        }

        try {
          // Convert FileList to Stream
          const stream = folderToTarStream(input.files, yielder);
          await runImport(stream);
          resolve();
        } catch (e) {
          reject(e);
        } finally {
          document.body.removeChild(input);
        }
      };

      input.oncancel = () => {
        document.body.removeChild(input);
        resolve();
      };

      input.click();
    });
  }

  window.LittleExport = {
    importData,
    exportData,
    deriveKey,
    prepForCBOR,
    restoreFromCBOR,
    importFromFolder,
    folderToTarStream,
    TYPE,
    DECISION,
  };
})();
