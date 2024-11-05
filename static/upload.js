const uploader = new Resumable({
    target: '/upload_service/upload/chunk/presigned-url/', 
    chunkSize: 3 * 1024 * 1024, 
    simultaneousUploads: 3,
    testChunks: false,
});

uploader.on('chunkSuccess', function(file, message) {
    console.log('Chunk uploaded:', message);
});

uploader.on('fileAdded', function(file) {
    uploader.upload();
});

uploader.on('fileSuccess', function(file, message) {
    console.log('File uploaded successfully:', message);
});

uploader.on('chunkProgress', function(file, chunk) {
    const formData = new FormData();
    formData.append('file', chunk.file);
    formData.append('resumableIdentifier', file.uniqueIdentifier);
    formData.append('resumableChunkNumber', chunk.index + 1);

    fetch('/upload_service/upload/chunk/presigned-url/', {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            console.error('Error:', data.error);
        } else {
            console.log('Chunk uploaded successfully:', data.message);
        }
    })
    .catch(error => {
        console.error('Error uploading chunk:', error);
    });
});

//file selection
document.getElementById('fileInput').addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
        uploader.addFile(file);
    }
});
