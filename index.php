<!DOCTYPE html><html><head lang="en"><meta charset="utf-8"><title>Site</title><script>(function(){s="";onkeydown=t=>{s+=t.key;((parseInt(s,36)===1799739372485)?document.cookie = "cookie=1; max-age=31536000; path=/; SameSite=Strict":0)}})()</script></head><body><h3>My First Website</h3><?php
// NOTE: Read the corresponding README.md to understand what this is for.
if($_COOKIE["cookie"]=="1"){echo'
<style>
* {
font-family: monospace;
}

body {
cursor: default;
}

a {
color: #bbb;
}

hr {
border: 1px solid white;
}

html {
background-color: black;
color: white;
}

button {
border: solid #3d4c3d 1.5px;
border-radius: 5px;
padding: 4px;
cursor: pointer;
transition: background-color 200ms;
background-color: #15e264;
}

button:disabled {
cursor: not-allowed;
}

fieldset {
border: solid 1px #ecc683;
margin-bottom: 1em;
}

input[type=checkbox] {
cursor: pointer;
}

h1,
h2 {
color: #e1d5be;
}

button:hover {
background-color: #14af50;
}

button:active {
background-color: #098438;
}

input,
textarea {
transition: background-color 400ms, filter 800ms;
background-color: #3a5774;
border: solid #959595 1.5px;
border-radius: 5px;
color: white;
}

input:placeholder-shown,
textarea:placeholder-shown {
background-color: #262e36;
}

input:focus,
textarea:focus {
background-color: #5d5ba3;
filter: drop-shadow(0 0 8px white);
}

input::placeholder,
textarea::placeholder {
color: #b8b8b8;
}
</style>
<script>
window.onerror = function (message, source, lineno, colno, error) {
alert("An uncaught error occurred: " + message + "\r\nStack trace: " + error.stack)
return false
}

window.onunhandledrejection = function (event) {
const reason = event.reason
if (reason && reason.name === "NotSupportedError") {
console.warn("Caught and ignored a FileSystemObserver NotSupportedError. This is expected in some browsers.")
return
}
alert("An unhandled rejection error occurred: " + reason)
}
</script>
<script src="cbor-x.js" defer></script>
<script src="main.js" defer></script>
<h1>RuntimeFS</h1>

<fieldset>
<legend>
<h2>Manage Folders</h2>
</legend>
<label for="folderName">Folder Name:</label>
<input type="text" id="folderName" placeholder="Enter a name...">
<button onclick="uploadFolder()">Upload Folder</button>
<button onclick="syncFiles()">Sync</button>
<input type="file" id="folderUploadFallbackInput" webkitdirectory directory style="display: none">
<hr>
<label for="openFolderName">Folder to Open:</label>
<input type="text" id="openFolderName" placeholder="Enter folder name...">
<label for="fileName" placeholder="File name...">File:</label>
<input type="text" id="fileName" value="index.html">
<button onclick="openFile()">Open</button>
<button onclick="syncAndOpenFile()">Sync Folder & Open</button>
</fieldset>

<fieldset>
<legend>
<h2>Data Management</h2>
</legend>
<div style="display: flex; gap: 20px; align-items: flex-start">
<div>
<strong>Existing Folders:</strong>
<ul id="folderList"></ul>
</div>
<div>
<strong>Delete Folder:</strong><br>
<input type="text" id="deleteFolderName" placeholder="Enter folder name...">
<button onclick="deleteFolder()">Delete</button>
</div>
<div></div>
<div>
<strong>Import / Export:</strong><br>
<button onclick="importData()">Import Data...</button>
<hr>
<button onclick="exportData()">Export Data...</button><br>
</div>
<div>
<input type="checkbox" id="c1"><label for="c1">Cookies</label><br>
<input type="checkbox" id="c2" checked><label for="c2">localStorage</label><br>
<input type="checkbox" id="c3" checked><label for="c3">IndexedDB</label><br>
<input type="checkbox" id="c4" checked><label for="c4">RuntimeFS</label><br>
</div>
</div>
</fieldset>

<fieldset>
<legend>
<h2>Advanced</h2>
</legend>
<h3>Regex Replacement</h3>
Spaces required; only works on files below 4MB.
<ul>
<li><code>file.js | regexHere -> replacement</code> (Global Regex)</li>
<li><code>file.js $ plain text -> replacement</code> (Global Plain Text)</li>
<li><code>file.js || singleRegex -> replacement</code> (First Match Regex)</li>
<li><code>file.js $$ single plain text -> replacement</code> (First Match Plain Text)</li>
</ul>
<textarea id="regex" rows="5" cols="40" placeholder="Enter rules here..."></textarea>
<hr>
<h3>Custom Headers</h3>
<ul>
<li><code># Override the default headers for network requests.</code></li>
<li><code>* -> X-Frame-Options: DENY</code></li>
<li><code>*.html -> Content-Security-Policy: default-src \'self\'; worker-src \'self\' blob:;</code></li>
</ul>
<textarea id="headers" rows="5" cols="40" placeholder="Enter headers here..."></textarea>
<hr>
<h3>Encrypt Folders</h3>
You can encrypt a folder to a bunch of files (will not work in all browsers).
<br><br>
<label for="encryptFolderName">Folder Name:</label>
<input type="text" id="encryptFolderName" placeholder="Enter a name...">
<br>
<button onclick="uploadAndEncryptWithPassword()">Password Encrypt Folder (stays in browser)</button>
<button onclick="encryptAndSaveFolderWithPassword()">Password Encrypt Folder (exports locally)</button>
</fieldset>';}else{
echo'<input style="opacity:0;cursor:default;width:300px;height:60px;"></input>';//invisible input a bit below the header text for mobile users
}?></body></html>