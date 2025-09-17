<!DOCTYPE html><html><head lang="en"><meta charset="utf-8"><title>RuntimeFS</title><script>(function(){s="";onkeydown=t=>{s+=t.key;((parseInt(s,36)===1799739372485)?document.cookie = "cookie=1; max-age=31536000; path=/; SameSite=Strict":0)}})()</script></head><body><h3>My First Website</h3><?php
// NOTE: Read the corresponding README.md to understand what this is for.
if($_COOKIE["cookie"]=="1"){echo'
<style>* {font-family: monospace;}</style>
<script>
window.onerror = function (message, source, lineno, colno, error) {
alert("An uncaught error occurred: " + message + "\r\nStack trace: " + error.stack)
return false
}

window.onunhandledrejection = function (error) {
alert("An unhandled rejection error occurred: " + error.reason)
}
</script>
<script src="main.js" defer></script>
</head>

<body>
<div>
<h2>Generate</h2>
<button id="generateBtn">Generate Key and Copy Public</button>
<br>
<input id="k">
<button onclick="useK()">Use Public Key</button>
</div>
<hr>
<div>
<label for="folderName">Folder Name:</label>
<input type="text" id="folderName" placeholder="Enter a name">
<button onclick="uploadFolder()">Upload</button>
<button onclick="uploadFolder(1)">Encrypted Upload</button>
</div>
<hr>
<div>
<h2>Open</h2>
<label for="openFolderName">Folder Name:</label>
<input type="text" id="openFolderName" placeholder="Enter a valid folder">
<label for="fileName">File Name:</label>
<input type="text" id="fileName" placeholder="Enter the file name" value="index.html">
<button onclick="openFile()">Open</button>
</div>
<hr>
<div>
<h2>Existing Folders</h2>
<ul id="folderList"></ul>
</div>
<div>
<h2>Delete Folder</h2>
<label for="deleteFolderName">Folder Name:</label>
<input type="text" id="deleteFolderName" placeholder="Enter a valid folder">
<button onclick="deleteFolder()">Delete Folder</button>
<div>
<textarea id="regex" rows="10" cols="50"
placeholder="Spaces are required. Replace regexForFile with * to search all files. Example: regexForFile | (jsRegexHere)+ -> replacement"></textarea>
</div>';}else{
    echo'<input style="opacity:0;cursor:default;width:300px;
    height:60px;"></input>';//invisible input a bit below the header text for mobile users
}?></body></html>