document.getElementById('uploadButton').addEventListener('click', async () => {
    const videoInput = document.getElementById('videoInput');
    const videoUrlInput = document.getElementById('video-url-input');
    const submitBtn = document.getElementById('submit-btn');
    const logDiv = document.getElementById('log');

    if (!videoInput.files.length) {
        alert('Please select a video file first.');
        return;
    }

    const file = videoInput.files[0];
    logDiv.innerHTML = 'Uploading...<br>';

    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch("{% url 'get_presigned_url' %}", {
        method: 'POST',
        body: formData
    });

    const data = await response.json();
    if (data.file_url) {
        videoUrlInput.value = data.file_url;
        logDiv.innerHTML += 'Upload complete!<br>';
        submitBtn.disabled = false;
    } else {
        logDiv.innerHTML += 'Upload failed.<br>';
    }
});
