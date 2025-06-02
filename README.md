# Real-time Multi-ROI Object Detection System

## Overview

This application provides a web-based interface for real-time object detection on a video stream (webcam or video file). Users can define multiple Regions of Interest (ROIs) on the video feed, each with its own YOLOv8 model, target classes, and detection parameters. The system monitors these ROIs and can trigger alerts if no detections occur within a configurable time window. Detections and alerts are displayed in real-time on the web interface.

## Features

-   **Multiple ROI Support:** Define and manage several ROIs simultaneously on a single video stream.
-   **Dynamic Model Loading:** Automatically loads YOLOv8 (`.pt`) models placed in the `app/models/` directory.
-   **Configurable Detection Parameters per ROI:** Each ROI can be configured with:
    -   A specific YOLOv8 model from the loaded ones.
    -   A list of target object classes to detect (e.g., "person", "car").
    -   A minimum confidence threshold for detections.
-   **Inactivity Alerts:** Configure a maximum time for no detections within an ROI before an alert is triggered.
-   **Web-Based Interface:**
    -   Live video stream display.
    -   Interactive ROI drawing on the video feed.
    -   Forms for configuring and managing ROIs.
    -   Real-time display of detection results and alert statuses.
-   **Real-time Communication:** Uses Flask-SocketIO for low-latency communication between the backend and frontend.

## Technologies Used

-   **Backend:**
    -   Python
    -   Flask: Web framework.
    -   Flask-SocketIO: For real-time bidirectional communication.
    -   Ultralytics YOLOv8: For object detection.
    -   OpenCV (cv2): For video capture and image processing.
    -   NumPy: For numerical operations, especially with image data.
-   **Frontend:**
    -   HTML5
    -   CSS3
    -   JavaScript
    -   Socket.IO (client-side): For real-time communication.
    -   HTML Canvas API: For drawing ROIs and detection boxes.

## File Structure

```
.
├── app/
│   ├── __init__.py         # Makes 'app' a package (can be empty)
│   ├── app.py              # Main Flask application logic, SocketIO handlers, video processing.
│   ├── models/             # Directory to store YOLOv8 .pt model files.
│   │   └── yolov8n.pt      # Example (dummy) model file.
│   ├── static/             # Static assets (CSS, JavaScript).
│   │   ├── scripts.js      # Client-side JavaScript for interactivity, ROI drawing, SocketIO.
│   │   └── styles.css      # CSS for styling the web interface.
│   ├── templates/          # HTML templates.
│   │   └── index.html      # Main HTML page for the application.
│   └── utils/              # Utility modules.
│       ├── detection.py    # Function for performing detection on ROIs.
│       └── roi_manager.py  # Class for managing ROI configurations.
├── requirements.txt        # Python package dependencies.
├── sample.mp4              # Example (dummy) video file, used as fallback.
└── README.md               # This file.
```

## Prerequisites

-   Python 3.8+
-   Pip (Python package installer)
-   Git (Optional, for cloning)
-   A compatible operating system (e.g., Linux, macOS, Windows). Some dependencies like `torch` might have specific OS considerations.

## Installation

1.  **Clone the Repository (if applicable):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create and Activate a Virtual Environment:**
    It's highly recommended to use a virtual environment to manage project dependencies.
    ```bash
    # For Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    Install all required Python packages using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```
    This will install Flask, Flask-SocketIO, Ultralytics YOLO (including PyTorch), OpenCV, NumPy, and their dependencies.

## Running the Application

1.  **Start the Flask Server:**
    Navigate to the project's root directory (where `app/app.py` is located) and run:
    ```bash
    python app/app.py
    ```

2.  **Access the Web Interface:**
    Open your web browser and go to:
    [http://127.0.0.1:5000/](http://127.0.0.1:5000/)

    The Flask-SocketIO development server will typically run on port 5000 by default. Check the console output for the exact URL if it differs.

## Usage Guide

### Model Loading

-   Place your YOLOv8 model files (with `.pt` extension) into the `app/models/` directory.
-   The application automatically scans this directory at startup and attempts to load these models.
-   Successfully loaded models will appear in the "Select Model" dropdown in the "ROI Configuration" section of the web interface.
-   *Note:* The repository includes a dummy `app/models/yolov8n.pt` which will not perform real detections. You need to replace it with actual model files from Ultralytics or your own trained models.

### ROI Configuration

1.  **Drawing an ROI:**
    -   On the video feed displayed in the web interface, click and drag your mouse to draw a rectangle defining your Region of Interest.
    -   The drawn rectangle will appear on an overlay canvas.
    -   To clear the current unsaved drawing, use the "Clear Current ROI Drawing" button.

2.  **Filling Configuration Fields:**
    -   **ROI ID:**
        -   For a **new ROI**, you can leave this field blank, and a unique ID will be auto-generated by the system when you submit. You can also input a temporary client-side ID if you wish, which will be used if unique.
        -   To **update an existing ROI's** settings (including its drawn coordinates if you've re-drawn), load the ROI using the "Load" button from the "Active ROIs" list. Its ID will populate this field.
    -   **Select Model:** Choose one of the loaded YOLOv8 models from the dropdown list for this ROI.
    -   **Target Classes:** Enter a comma-separated list of object classes you want this ROI to detect (e.g., `person,car,dog`). Leave this field empty to detect all classes that the selected model is capable of identifying.
    -   **Minimum Confidence:** Set a value between 0.0 and 1.0 (e.g., `0.5`). Detections with a confidence score below this threshold will be ignored for this ROI.
    -   **Max No-Detection Time:** Enter the maximum time in seconds (e.g., `60`) that this ROI can go without detecting any of its target classes (above the minimum confidence) before an alert is triggered.

3.  **Submitting the ROI:**
    -   After drawing the ROI (if new or updating geometry) and filling in the configuration fields, click the "Add/Update ROI" button.
    -   A confirmation message will appear, and the ROI will be added to the "Active ROIs" list or updated if an existing ID was provided.

### Managing Active ROIs

-   The "Active ROIs" section lists all currently configured ROIs with their server-assigned ID and key settings.
-   **Load Button:** Click the "Load" button next to an ROI in the list to populate the "ROI Configuration" form with that ROI's current settings. The ROI will also be highlighted on the video feed (if a new drawing isn't already active). This is useful for viewing or modifying an existing ROI.
-   **Remove Button:** Click the "Remove" button to delete the corresponding ROI from the system.

### Detection Status and Alerts

-   The "Detection Status" area displays real-time information for each active ROI:
    -   ROI ID.
    -   Alert Status: "OK" or "ALERT!".
    -   A list of detected objects (class name and confidence score) within that ROI for the current frame.
-   **Visual Alerts on Video Feed:**
    -   When an ROI is in an "alert" state (due to no detections for the configured `Max No-Detection Time`), its border color on the video feed overlay will change (typically to red).
    -   An "ALERT" message may also be displayed near the ROI on the video feed.
    -   Detected object bounding boxes are drawn on the video feed in real-time.

## Troubleshooting/Notes

-   **Webcam Access:** The application first tries to access a webcam using `cv2.VideoCapture(0)`. Ensure your webcam is connected and accessible by the application. If permissions are needed, grant them.
-   **Video File Fallback:** If a webcam is not found or fails to open, the system attempts to load a video file named `sample.mp4` from the project's root directory.
    -   The `sample.mp4` included in this repository is a **dummy placeholder** and does not contain actual video data. For proper functionality with a video file, replace it with a valid `.mp4` (or other OpenCV-compatible) video file.
    -   For more flexible video file input, you would need to modify `app/app.py` to allow specifying the video path (e.g., via a configuration file or command-line argument).
-   **Model Files:** The `app/models/yolov8n.pt` file is a **dummy placeholder**. Real object detection requires actual YOLOv8 `.pt` model files. Download pre-trained models from Ultralytics (e.g., `yolov8n.pt`, `yolov8s.pt`) or use your own custom-trained models and place them in the `app/models/` directory.
-   **Performance:** Processing video and running multiple YOLO models can be computationally intensive. Performance will depend on your hardware (CPU, GPU), the resolution of the video, and the complexity of the models used.
-   **Console Logs:** Check the terminal where `python app/app.py` is running for detailed log messages, including model loading status, errors, connected clients, and detection outputs.

---

This README provides a comprehensive guide to understanding, installing, and using the application.
