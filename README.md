# RuntimeFS
![RuntimeFS explanation](RuntimeFS.png)
View the [working demo](https://plasma4.org/projects/RuntimeFS/)!

RuntimeFS is a no-nonsense `OPFS` and `ServiceWorker` file-system, served in your browser. It allows you to open HTML projects, use some encryption techniques, and comes with **full offline** and **complete .tar.gz or encrypted data export** functionality that no other tool has!

Imagine an offline localhost, in your browser with no server-based storage of files. It saves all files and data locally, and can easily be integrated within an existing website too (the code is MIT Licensed, and only around 100KB).

After initial page load, RuntimeFS no longer needs internet connection to function. RuntimeFS also supports in-place opening of files, which doesn't require opening another tab.

## Setup
RuntimeFS utilizes [cbor-x](https://github.com/kriszyp/cbor-x) and my own [LittleExport](https://github.com/plasma4/LittleExport) tool. Both are MIT Licensed. (LittleExport is integrated directly into RuntimeFS; no separate license file is required.) Only `main.min.js` and `sw.min.js` are required for RuntimeFS to work.

Make sure to modify `APP_SHELL_FILES` in the SW and `SW_LINK` in the main code if you are changing the file configuration for proper caching. (Code is minified by using [JSCompress](https://jscompress.com/), which uses `UglifyJS` 3 and `babel-minify`.)

## Usage
You can use Enter on text inputs to perform actions, instead of clicking buttons. On the Folder to Open section text inputs you can use Shift+Enter to open in-place and Ctrl/Cmd+Enter to sync and open.

Custom regex and headers save on reload and export but do not affect stored files, and only work when opening the file (in-place or new tab) from the RuntimeFS menu (reloading or navigating to the URL directly do not yet).

To update to a newer version you can delete the ServiceWorker such as with `chrome://serviceworker-internals/`, or equivalents in other browsers, then reload/force reload.

## Browser Support
(Safari has to be version 26.0 or above due to [`createWritable`](https://caniuse.com/mdn-api_filesystemfilehandle_createwritable), although I'm unable to verify if anything else is broken on my device for the newest Safari versions.)

File System API features (such as syncing or folder encryption) are Chromium-exclusive, and these options will be hidden in other browsers. RuntimeFS has been tested in Chromium, Firefox, and Safari.

(Firefox has a very specific issue involving initially loading JS scripts in `generateResponseForVirtualFile`, so an automatic reload is performed that injects `?boot=1` to the end of the URL. This also means that headers won't work.)
| Feature | 🟢 Chromium | 🟡 Firefox | 🟡 Safari |
| :--- | :--- | :--- | :--- |
| **Folder Upload** | ✅ Yes | ⚠️ `<input>` fallback, no sync | ⚠️ `<input>` fallback, no sync |
| **Encryption (folder-based)** | ✅ Yes | ❌ No | ❌ No |
| **Export (including encryption)** | ✅ Mostly streamed to disk | ⚠️ RAM only (crashes if too big) | ⚠️ RAM only (crashes if too big) |

## URL Persistence & Location Spoofing
URL Persistence is an informal term that means that websites store data along with URLs. Examples include the Ruffle emulator (in `localStorage`) and Unity (in `IndexedDB`). If you export data from `example.com/v1/` and try to import it to `example.com/v2/` (or to different domains), it probably won't work.

Because of this problem, you must normalize these URL keys during exporting or importing with a mock location object (and replace `document.URL` if needed). See a **standardized** RuntimeFS location spoofer in [LittleExport](https://github.com/plasma4/LittleExport).

## Notes
There are also additional (private) variations of RuntimeFS for site hosters and developers, so do reach out to me on Discord (`@1_e0`) if you need a better implementation, encounter issues, or need clarification!

Not all applications will work! Out of the many sites I tested, there were the main reasons why they broke, even with custom headers:
- The application requests something externally (this might not always break, but sometimes sites are strict!). ServiceWorkers cannot intercept these anyway.
- Somewhere in the application, sync AJAX is used. There is sadly no simple workaround. (This type of request is also being phased out from browsers gradually; I've tried getting this working with `Atomics` and web workers but it sadly isn't fixable.)
- The application isn't compiled yet, such as on a Vite GitHub download.
- The application requests URLs from root (`/`). The current version has some fetch interception for this, but it's not guaranteed to work for everything (or, custom `<base>` elements might actually interfere). This might be fixable with `<base href="/n/FolderName">`.

> [!WARNING]
> Folders are **not sandboxed**! Because RuntimeFS serves files from the same origin, uploaded scripts have unrestricted access to local data (including `localStorage`, `IndexedDB`, and `OPFS`).
>
> In theory, a malicious site hosted inside RuntimeFS could exfiltrate your data. Keep in mind you are basically using a localhost **but without subdomain/site isolation**. If this is a concern, use Content-Security-Policy (CSP) headers to stop external requests.

Also note:
- File names are case-sensitive.
- Using the tool in Incognito will probably fail due to restrictions on memory or ServiceWorkers (browser dependent).
- Headers currently **do not work** for in-place opening and Firefox.
- Cookie exporting does not store `max-age`; only the key and value.
- The most likely reason that data export fails when transferring between sites is because those websites use URL properties as part of the key (either from `document.URL` or `location`). You might be able to force a site to use a hardcoded URL for storage with clever regex or code changes.
- Using regex requires any matched files to be fully loaded into memory, reducing performance. Be careful!
- Exporting any single files with very large sizes not from OPFS (such as from IndexedDB, or cache storage) might result in crashes.
- Check `getMimeType` in the ServiceWorker for the supported MIME types; you may need to add your own in some cases.
- You might encounter freezing of all RuntimeFS-related tabs if any tab is stuck or waiting for something (such as making a IndexedDB writable).

A single-file plugin exists for customizing cache in the `plugin` (or requesting an update), allowing for you to fully customize RuntimeFS from any site hosting it (although **it will clear the cache on hard reload**).

### TODO
- Devtools panel (for some cases where Inspect is unavailable, using something like Eruda)
- LittleExport improvements
- More complete documentation