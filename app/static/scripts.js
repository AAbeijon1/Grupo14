document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const videoFeed = document.getElementById('videoFeed');
    const roiCanvas = document.getElementById('roiCanvas');
    const detectionInfo = document.getElementById('detectionInfo');
    const modelSelect = document.getElementById('modelSelect');
    
    // ROI Configuration Inputs
    const roiIdInput = document.getElementById('roiIdInput');
    const targetClassesInput = document.getElementById('targetClassesInput');
    const minConfidenceInput = document.getElementById('minConfidenceInput');
    const maxNoDetectionTimeInput = document.getElementById('maxNoDetectionTimeInput');
    const addRoiButton = document.getElementById('addRoiButton');
    const clearRoiButton = document.getElementById('clearRoiButton');
    const activeRoisListDiv = document.getElementById('activeRoisList');

    let ctx = roiCanvas.getContext('2d');
    let isDrawing = false;
    let currentDrawingRoi = {}; // Stores {x1, y1, x2, y2} during mouse drag
    let clientSideRois = {}; // Stores committed ROIs on the client { id: {x1, y1, x2, y2, serverId?, ...otherConfig} }
    let tempRoiIdCounter = 0;


    // --- Canvas Setup and Synchronization ---
    function setupCanvas() {
        // Set initial canvas size based on video element's current display size
        if (videoFeed.offsetWidth > 0 && videoFeed.offsetHeight > 0) {
            roiCanvas.width = videoFeed.offsetWidth;
            roiCanvas.height = videoFeed.offsetHeight;
        } else {
            // Fallback if video feed not loaded yet or hidden, try again on video load
            videoFeed.onload = () => {
                roiCanvas.width = videoFeed.offsetWidth;
                roiCanvas.height = videoFeed.offsetHeight;
            };
        }
        // Make canvas visible after setting dimensions if it was hidden
        roiCanvas.style.display = 'block'; 
        redrawAllCommittedRois();
    }

    if (document.readyState === "complete" || document.readyState === "interactive") {
        setupCanvas();
    } else {
        window.addEventListener('load', setupCanvas); // Fallback if DOMContentLoaded already fired
    }
    
    const resizeObserver = new ResizeObserver(entries => {
        for (let entry of entries) {
            if (entry.target === videoFeed) {
                roiCanvas.width = videoFeed.offsetWidth;
                roiCanvas.height = videoFeed.offsetHeight;
                redrawAllCommittedRois(); // Redraw ROIs when video size changes
            }
        }
    });

    if (videoFeed) {
        resizeObserver.observe(videoFeed);
    }

    // --- ROI Drawing Logic ---
    roiCanvas.addEventListener('mousedown', (e) => {
        if (e.button !== 0) return; // Only react to left mouse button
        isDrawing = true;
        const rect = roiCanvas.getBoundingClientRect();
        const startX = e.clientX - rect.left;
        const startY = e.clientY - rect.top;
        currentDrawingRoi = { x1: startX, y1: startY, x2: startX, y2: startY };
        // console.log('mousedown - currentDrawingRoi:', currentDrawingRoi);
    });

    roiCanvas.addEventListener('mousemove', (e) => {
        if (!isDrawing) return;
        const rect = roiCanvas.getBoundingClientRect();
        const currentX = e.clientX - rect.left;
        const currentY = e.clientY - rect.top;
        currentDrawingRoi.x2 = currentX;
        currentDrawingRoi.y2 = currentY;

        ctx.clearRect(0, 0, roiCanvas.width, roiCanvas.height);
        redrawAllCommittedRois();
        drawRect(currentDrawingRoi, 'rgba(255, 0, 0, 0.5)', true); // Active drawing style
    });

    roiCanvas.addEventListener('mouseup', (e) => {
        if (!isDrawing || e.button !== 0) return;
        isDrawing = false;
        const rect = roiCanvas.getBoundingClientRect();
        const endX = e.clientX - rect.left;
        const endY = e.clientY - rect.top;

        currentDrawingRoi.x2 = endX;
        currentDrawingRoi.y2 = endY;

        // Ensure x1 < x2 and y1 < y2
        const finalRoi = {
            x1: Math.min(currentDrawingRoi.x1, currentDrawingRoi.x2),
            y1: Math.min(currentDrawingRoi.y1, currentDrawingRoi.y2),
            x2: Math.max(currentDrawingRoi.x1, currentDrawingRoi.x2),
            y2: Math.max(currentDrawingRoi.y1, currentDrawingRoi.y2),
        };
        
        // Check for minimal size to avoid accidental tiny ROIs
        if (Math.abs(finalRoi.x2 - finalRoi.x1) < 10 || Math.abs(finalRoi.y2 - finalRoi.y1) < 10) {
            console.log("ROI is too small, not committing.");
            currentDrawingRoi = {};
            redrawAllCommittedRois(); // Clear the temporary drawing
            return;
        }
        
        // For now, we are drawing one ROI at a time for configuration.
        // This drawn ROI will be used by the "Add/Update ROI" button.
        // We don't assign a client-side ID here yet, that happens on submit.
        // Instead, we update the form fields.
        console.log('mouseup - finalRoi drawn:', finalRoi);
        
        // Store this as the "active" ROI to be configured
        clientSideRois['temp_current'] = finalRoi; 

        // Update form fields (optional, but good for UX)
        roiIdInput.value = ""; // Clear ID field for new ROI
        // We don't set coordinates in text fields, user sees it on canvas
        
        redrawAllCommittedRois(); // Redraw existing committed ROIs
        drawRect(finalRoi, 'rgba(0, 0, 255, 0.7)', true); // Draw the newly defined ROI distinctly until saved
    });

    roiCanvas.addEventListener('mouseout', (e) => {
        // Optional: if isDrawing and mouse leaves, you could cancel or complete.
        // For simplicity, we rely on mouseup within canvas for now.
        // If isDrawing is true here, it means mouseup happened outside or was missed.
        // if (isDrawing) {
        //     console.log("Mouse left canvas while drawing, cancelling/completing (not fully implemented).");
        //     isDrawing = false;
        //     // Decide whether to commit currentDrawingRoi or discard
        //     currentDrawingRoi = {}; // Discard for now
        //     redrawAllCommittedRois();
        // }
    });

    if(clearRoiButton) {
        clearRoiButton.addEventListener('click', () => {
            currentDrawingRoi = {}; // Clear any active drawing
            if (clientSideRois['temp_current']) {
                delete clientSideRois['temp_current']; // Remove the actively drawn ROI if not yet submitted
            }
            isDrawing = false;
            redrawAllCommittedRois();
            roiIdInput.value = ""; // Clear ROI ID field
        });
    }


    // --- Helper function to draw a rectangle ---
    function drawRect(roi, color = 'rgba(0, 255, 0, 0.5)', isCurrent = false) {
        if (!roi || typeof roi.x1 === 'undefined') return;
        ctx.strokeStyle = color;
        ctx.lineWidth = isCurrent ? 3 : 2;
        ctx.beginPath();
        ctx.rect(roi.x1, roi.y1, roi.x2 - roi.x1, roi.y2 - roi.y1);
        ctx.stroke();
        if (roi.id && roi.id !== 'temp_current') { // Display ID for committed ROIs
             ctx.fillStyle = color;
             ctx.font = "12px Arial";
             ctx.fillText(roi.serverId || roi.id, roi.x1 + 5, roi.y1 + 15);
        }
    }
    
    // --- Redraw all committed ROIs ---
    function redrawAllCommittedRois() {
        ctx.clearRect(0, 0, roiCanvas.width, roiCanvas.height);
        for (const id in clientSideRois) {
            if (id === 'temp_current' && isDrawing) continue; // Don't draw the temp one if currently drawing it
             // Default to green if no specific status color logic yet
            let color = 'rgba(0, 255, 0, 0.7)'; // Green for committed
            if (clientSideRois[id].alert_status) {
                color = 'rgba(255, 0, 0, 0.7)'; // Red for alert
            }
            drawRect(clientSideRois[id], color);
        }
    }

    // --- Add/Update ROI Button ---
    if (addRoiButton) {
        addRoiButton.addEventListener('click', () => {
            let roiToSubmit;
            let clientRoiIdToUpdate = roiIdInput.value.trim();

            if (clientSideRois['temp_current']) { // A new ROI has just been drawn
                roiToSubmit = clientSideRois['temp_current'];
                // If roiIdInput is empty, it's a new ROI. If filled, it's an update to existing one using new coords.
            } else if (clientRoiIdToUpdate && clientSideRois[clientRoiIdToUpdate]) {
                // No new drawing, but an ID is specified, so update existing ROI (non-coordinate fields)
                roiToSubmit = clientSideRois[clientRoiIdToUpdate];
            } else if (clientRoiIdToUpdate && !clientSideRois[clientRoiIdToUpdate]){
                alert(`ROI with client ID "${clientRoiIdToUpdate}" not found for update. Draw a new ROI or use an existing ID.`);
                return;
            } else {
                 alert("Please draw an ROI on the video feed first, or specify an existing ROI ID to update.");
                return;
            }

            // Scale coordinates to original video dimensions if necessary
            // For now, assume canvas and video intrinsic dimensions are handled or 1:1
            // This might need adjustment if videoFeed.naturalWidth/Height differs from offsetWidth/Height
            const videoWidth = videoFeed.naturalWidth || videoFeed.videoWidth || videoFeed.width;
            const videoHeight = videoFeed.naturalHeight || videoFeed.videoHeight || videoFeed.height;
            const canvasWidth = roiCanvas.width;
            const canvasHeight = roiCanvas.height;

            if (videoWidth === 0 || videoHeight === 0) {
                alert("Video dimensions not available. Cannot scale ROI coordinates.");
                return;
            }

            const scaledCoords = {
                x1: Math.round((roiToSubmit.x1 / canvasWidth) * videoWidth),
                y1: Math.round((roiToSubmit.y1 / canvasHeight) * videoHeight),
                x2: Math.round((roiToSubmit.x2 / canvasWidth) * videoWidth),
                y2: Math.round((roiToSubmit.y2 / canvasHeight) * videoHeight),
            };

            const roiConfig = {
                roi_id: clientSideRois[clientRoiIdToUpdate]?.serverId || roiIdInput.value.trim() || null, // Send serverId if known, else input, else null
                coordinates: [scaledCoords.x1, scaledCoords.y1, scaledCoords.x2, scaledCoords.y2], // Ensure tuple/array of 4 ints
                model_name: modelSelect.value,
                target_classes: targetClassesInput.value.split(',').map(s => s.trim()).filter(s => s),
                min_conf: parseFloat(minConfidenceInput.value),
                max_no_detection_time: parseInt(maxNoDetectionTimeInput.value, 10)
            };

            if (isNaN(roiConfig.min_conf) || roiConfig.min_conf < 0 || roiConfig.min_conf > 1) {
                alert("Minimum confidence must be a number between 0 and 1.");
                return;
            }
            if (isNaN(roiConfig.max_no_detection_time) || roiConfig.max_no_detection_time < 1) {
                alert("Max no-detection time must be a positive integer.");
                return;
            }
            if (!roiConfig.model_name) {
                alert("Please select a model.");
                return;
            }
            
            console.log("Submitting ROI config:", roiConfig);
            socket.emit('update_roi_config', roiConfig);
            
            // Clear the temporary drawing state
            if (clientSideRois['temp_current']) {
                 delete clientSideRois['temp_current'];
            }
            currentDrawingRoi = {};
            // The actual clientSideRois update will happen on 'roi_add_success' or 'roi_update_success'
            redrawAllCommittedRois(); 
        });
    }

    // --- Socket.IO Event Handlers (moved from index.html and enhanced) ---
    
    // Model population is handled by Jinja or initial script block in HTML now.
    // This script focuses on dynamic updates and interactions.

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    socket.on('video_frame', function(data) {
        if (data.image_data) {
            const newSrc = 'data:image/jpeg;base64,' + arrayBufferToBase64(data.image_data);
            // Only update src if it's different to avoid flicker/reload if stream is paused
            if (videoFeed.src !== newSrc) { 
                videoFeed.src = newSrc;
            }
            // Ensure canvas is correctly sized after image loads for the first time
            if (roiCanvas.width !== videoFeed.offsetWidth || roiCanvas.height !== videoFeed.offsetHeight) {
                if(videoFeed.offsetWidth > 0) { // only if visible
                    setupCanvas();
                }
            }
        }
    });

    socket.on('detection_update', function(data) {
        let infoHtml = '<h4>Detection Results:</h4>';
        if (data.results && data.results.length > 0) {
            data.results.forEach(roiResult => {
                const alertColor = roiResult.alert_status ? 'red' : 'green';
                infoHtml += `<div style="border: 1px solid #ccc; margin-bottom: 10px; padding: 10px;">`;
                infoHtml += `<p><strong>ROI ID: ${roiResult.roi_id}</strong> | Status: <span style="color: ${alertColor}; font-weight: bold;">${roiResult.alert_status ? 'ALERT!' : 'OK'}</span></p>`;
                
                if (roiResult.detections && roiResult.detections.length > 0) {
                    infoHtml += '<ul>';
                    roiResult.detections.forEach(det => {
                        infoHtml += `<li>${det.class_name}: ${(det.confidence * 100).toFixed(1)}%</li>`;
                    });
                    infoHtml += '</ul>';
                } else {
                    infoHtml += '<p><em>No detections in this frame for this ROI.</em></p>';
                }
                infoHtml += `</div>`;

                // Update alert status for client-side ROI representation for drawing
                if(clientSideRois[roiResult.roi_id]) {
                    clientSideRois[roiResult.roi_id].alert_status = roiResult.alert_status;
                } else if (clientSideRois[('temp_' + roiResult.roi_id)] && clientSideRois[('temp_' + roiResult.roi_id)].serverId === roiResult.roi_id) {
                    // Case where ROI was just added and serverId is now known
                    clientSideRois[('temp_' + roiResult.roi_id)].alert_status = roiResult.alert_status;
                }
            });
        } else {
            infoHtml = '<p>No detections in this frame from any ROI.</p>';
        }
        detectionInfo.innerHTML = infoHtml;
        redrawAllCommittedRois(); // Redraw ROIs to reflect any alert status changes (e.g. color)
    });
    
    // --- ROI Management UI & Server Sync ---

    function updateActiveRoisListFromServer(roisFromServer) {
        activeRoisListDiv.innerHTML = ''; // Clear current list
        clientSideRois = {}; // Reset local store, rebuild from server's truth

        const videoWidth = videoFeed.naturalWidth || videoFeed.videoWidth || videoFeed.width;
        const videoHeight = videoFeed.naturalHeight || videoFeed.videoHeight || videoFeed.height;
        const canvasWidth = roiCanvas.width;
        const canvasHeight = roiCanvas.height;

        if (Object.keys(roisFromServer).length === 0) {
            activeRoisListDiv.innerHTML = '<p>No ROIs configured on server.</p>';
            redrawAllCommittedRois();
            return;
        }

        const ul = document.createElement('ul');
        ul.style.listStyleType = 'none';
        ul.style.paddingLeft = '0';

        for (const serverId in roisFromServer) {
            const roiConfig = roisFromServer[serverId];
            let displayCoords = { x1:0, y1:0, x2:0, y2:0 }; // Default/fallback

            if (videoWidth > 0 && canvasWidth > 0 && videoHeight > 0 && canvasHeight > 0) {
                 displayCoords = { // Scale server coords (video-relative) to canvas-relative
                    x1: Math.round((roiConfig.coordinates[0] / videoWidth) * canvasWidth),
                    y1: Math.round((roiConfig.coordinates[1] / videoHeight) * canvasHeight),
                    x2: Math.round((roiConfig.coordinates[2] / videoWidth) * canvasWidth),
                    y2: Math.round((roiConfig.coordinates[3] / videoHeight) * canvasHeight),
                };
            }
            
            clientSideRois[serverId] = { // Use serverId as the key
                serverId: serverId,
                coordinates: roiConfig.coordinates, // Original (video-relative)
                scaled_coords: displayCoords,       // For drawing on canvas
                model_name: roiConfig.model_name,
                target_classes: roiConfig.target_classes,
                min_conf: roiConfig.min_conf,
                max_no_detection_time: roiConfig.max_no_detection_time,
                alert_status: roiConfig.alert_triggered || false // from server if available
            };

            const li = document.createElement('li');
            li.style.marginBottom = '5px';
            li.style.padding = '5px';
            li.style.border = '1px solid #eee';

            li.textContent = `ID: ${serverId} (Model: ${roiConfig.model_name}, Targets: ${roiConfig.target_classes.join(', ') || 'any'})`;
            
            const loadBtn = document.createElement('button');
            loadBtn.textContent = 'Load';
            loadBtn.style.marginLeft = '10px';
            loadBtn.style.fontSize = '0.8em';
            loadBtn.onclick = () => {
                roiIdInput.value = serverId;
                modelSelect.value = roiConfig.model_name;
                targetClassesInput.value = roiConfig.target_classes.join(',');
                minConfidenceInput.value = roiConfig.min_conf;
                maxNoDetectionTimeInput.value = roiConfig.max_no_detection_time;
                
                // Visually represent the loaded ROI on canvas for potential re-drawing
                currentDrawingRoi = {}; 
                delete clientSideRois['temp_current'];
                clientSideRois['temp_current'] = { ...displayCoords }; // Use scaled_coords for drawing
                redrawAllCommittedRois();
                drawRect(clientSideRois['temp_current'], 'rgba(0, 0, 255, 0.7)', true); // Highlight loaded
            };
            li.appendChild(loadBtn);

            const removeBtn = document.createElement('button');
            removeBtn.textContent = 'Remove';
            removeBtn.style.marginLeft = '5px';
            removeBtn.style.backgroundColor = '#d9534f';
            removeBtn.style.fontSize = '0.8em';

            removeBtn.onclick = () => {
                if (confirm(`Remove ROI ${serverId}?`)) {
                    socket.emit('remove_roi', { roi_id: serverId });
                }
            };
            li.appendChild(removeBtn);
            ul.appendChild(li);
        }
        activeRoisListDiv.appendChild(ul);
        redrawAllCommittedRois();
    }
    
    socket.on('roi_list_updated', (data) => {
        console.log('Received updated ROI list from server:', data.rois);
        updateActiveRoisListFromServer(data.rois || {});
    });

    socket.on('roi_add_success', (data) => {
        console.log('ROI Add/Update Success (from server response):', data);
        alert(`ROI ${data.roi_id} processed successfully by server!`);
        // The 'roi_list_updated' event (broadcast from server) will handle actual list update.
        // Clear form for next potential ROI.
        roiIdInput.value = ''; 
        if (clientSideRois['temp_current']) {
            delete clientSideRois['temp_current']; // Clear the temporary blue drawing
        }
        redrawAllCommittedRois(); // Redraw based on new list from server soon
    });
    
    socket.on('roi_update_success', (data) => { // Could be the same as add_success if server logic is merged
        console.log('ROI Update Success (from server response):', data);
        alert(`ROI ${data.roi_id} updated successfully by server!`);
        // 'roi_list_updated' will refresh the list and drawing.
        roiIdInput.value = ''; 
        if (clientSideRois['temp_current']) {
             delete clientSideRois['temp_current'];
        }
        redrawAllCommittedRois();
    });

    socket.on('roi_removed_success', (data) => { // Server confirms removal
        console.log('ROI Removed Success (from server response):', data);
        // 'roi_list_updated' broadcast will handle the actual list and canvas update.
        alert(`ROI ${data.roi_id} removed successfully by server!`);
    });

    socket.on('roi_update_error', (data) => {
        console.error('ROI Error from server:', data);
        alert(`Error with ROI ${data.roi_id || ''}: ${data.message}`);
    });
    
    // Initial connection and request for ROI list
    socket.on('connect', () => {
        console.log('Connected to server with Socket.IO.');
        socket.emit('request_roi_list'); // Request initial list of ROIs
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });


});
</script>

</body>
</html>
