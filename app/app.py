import os
import cv2
import threading
import time
import numpy as np
from typing import Dict, List, Tuple, Optional, Any # Added for type hinting
from flask import Flask, render_template
from flask_socketio import SocketIO
from ultralytics import YOLO

from utils.roi_manager import ROIManager
from utils.detection import perform_detection_on_roi

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

AVAILABLE_MODELS = []
loaded_models: Dict[str, YOLO] = {} # Stores loaded YOLO model instances
roi_manager = ROIManager()
video_capture_thread = None
stop_video_processing_flag = threading.Event()
roi_last_detection_time: Dict[str, float] = {} # For alert tracking

def load_available_models_and_instances():
    """Scans the app/models directory for .pt files, loads them, and returns their names."""
    global AVAILABLE_MODELS, loaded_models
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
        print("Models directory created.")
        AVAILABLE_MODELS = []
        return

    model_files = []
    for f in os.listdir(models_dir):
        if f.endswith(".pt"):
            model_files.append(f)
    
    print(f"Found model files: {model_files}")
    loaded_model_names = []
    for model_file in model_files:
        model_name = os.path.splitext(model_file)[0]
        model_path = os.path.join(models_dir, model_file)
        try:
            loaded_models[model_name] = YOLO(model_path)
            loaded_model_names.append(model_name)
            print(f"Successfully loaded model: {model_name} from {model_path}")
        except Exception as e:
            print(f"Error loading model {model_name} from {model_path}: {e}")
            print("This might be because the .pt file is a dummy or corrupted.")
            print("Real detections will not work with this model.")
            # Optionally, create a mock/placeholder if loading fails but app should run
            # For now, we just skip adding it to loaded_models if critical,
            # or add a placeholder if non-critical features depend on its presence.

    AVAILABLE_MODELS = loaded_model_names
    app.config['AVAILABLE_MODELS'] = AVAILABLE_MODELS
    print(f"Available and loaded models: {AVAILABLE_MODELS}")
    print(f"Loaded model instances: {loaded_models.keys()}")


def video_processing_thread_func():
    """
    Captures video, performs ROI detection, and (eventually) emits results.
    """
    print("Video processing thread started.")
    cap = None
    try:
        # Try webcam first
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            print("Could not open webcam, trying sample.mp4")
            cap = cv2.VideoCapture('sample.mp4')
            if not cap.isOpened():
                print("Error: Could not open video source (webcam or sample.mp4).")
                print("Video processing thread will exit.")
                return
    except Exception as e:
        print(f"Exception opening video source: {e}")
        print("Video processing thread will exit.")
        return

    while not stop_video_processing_flag.is_set():
        ret, frame = cap.read()
        if not ret:
            print("Failed to grab frame. Video source might have ended or encountered an error.")
            # Optional: try to reopen if it's a webcam that got disconnected
            if cap.get(cv2.CAP_PROP_POS_FRAMES) > 0 and cap.get(cv2.CAP_PROP_FRAME_COUNT) > 0 and \
               cap.get(cv2.CAP_PROP_POS_FRAMES) >= cap.get(cv2.CAP_PROP_FRAME_COUNT):
                print("Video file ended.")
                break # End of video file
            time.sleep(0.5) # Wait a bit before retrying or breaking
            continue

        all_detections_for_frame = [] # Initialize for each frame
        all_current_rois = roi_manager.get_all_rois()
        # print(f"Processing frame with {len(all_current_rois)} ROIs") # Can be very verbose

        for roi_id, roi_config in all_current_rois.items():
            model_name = roi_config.get("model_name")
            if not model_name:
                # print(f"ROI {roi_id} has no model_name configured.")
                continue
            
            model_instance = loaded_models.get(model_name)
            if not model_instance:
                # print(f"Model '{model_name}' for ROI {roi_id} not found in loaded_models.")
                continue

            # Ensure coordinates are in the expected (x1, y1, x2, y2) format for perform_detection_on_roi
            # ROIManager stores coordinates as a list of tuples for polygon.
            # perform_detection_on_roi expects a bounding box tuple (x1,y1,x2,y2).
            # This part needs clarification: Does perform_detection_on_roi handle polygon coords
            # or does it need a bounding box of the polygon? Assuming it needs a bounding box for now.
            # perform_detection_on_roi expects a bounding box tuple (x1,y1,x2,y2).
            # ROIManager now stores coordinates in this format.
            roi_coords_tuple = roi_config.get("coordinates")
            if not roi_coords_tuple or not isinstance(roi_coords_tuple, tuple) or len(roi_coords_tuple) != 4:
                print(f"ROI {roi_id} has invalid coordinates format: {roi_coords_tuple}")
                continue
            
            current_detections = perform_detection_on_roi(
                frame, 
                model_instance, 
                roi_coords_tuple,
                roi_config.get("target_classes", []), 
                roi_config.get("min_conf", 0.5)
            )

            roi_alert_status = False
            if current_detections:
                roi_last_detection_time[roi_id] = time.time()
                # print(f"Detections in ROI {roi_id} ({model_name}): {current_detections}") # Verbose
                for det in current_detections:
                    box = det['box']
                    label = f"{det['class_name']}: {det['confidence']:.2f}"
                    cv2.rectangle(frame, (box[0], box[1]), (box[2], box[3]), (0, 255, 0), 2)
                    cv2.putText(frame, label, (box[0], box[1] - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
            else:
                # No detections in this ROI for this frame
                last_detection = roi_last_detection_time.get(roi_id)
                max_time = roi_config.get('max_no_detection_time', 60)
                if last_detection and (time.time() - last_detection > max_time):
                    roi_alert_status = True
                    print(f"ALERT: ROI {roi_id} has no detections for {time.time() - last_detection:.2f}s (max: {max_time}s)!")
                    # Optionally draw something on the frame to indicate alert for this ROI
                    cv2.putText(frame, f"ALERT: {roi_id}", (roi_coords_tuple[0], roi_coords_tuple[1] - 20), 
                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)


            all_detections_for_frame.append({
                'roi_id': roi_id,
                'detections': current_detections,
                'alert_status': roi_alert_status
            })

        if all_detections_for_frame:
            socketio.emit('detection_update', {'results': all_detections_for_frame})

        # Encode and emit the (potentially annotated) frame
        ret_jpeg, buffer = cv2.imencode('.jpg', frame)
        if ret_jpeg:
            jpeg_bytes = buffer.tobytes()
            socketio.emit('video_frame', {'image_data': jpeg_bytes})
        # else:
            # print("Failed to encode frame to JPEG") # Can be verbose

        time.sleep(0.01)  # Control processing speed

    if cap:
        cap.release()
    print("Video processing thread stopped.")

# Load models at startup
load_available_models_and_instances()

@app.route('/')
def index():
    # Pass available_models to the template
    return render_template('index.html', available_models=AVAILABLE_MODELS)

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    # Emit the current ROI list to the newly connected client
    socketio.emit('roi_list_updated', {'rois': roi_manager.get_all_rois()})

@socketio.on('request_roi_list')
def handle_request_roi_list():
    print('Client requested ROI list')
    socketio.emit('roi_list_updated', {'rois': roi_manager.get_all_rois()})

@socketio.on('update_roi_config')
def handle_update_roi_config(data):
    """
    Handles ROI configuration additions or updates from the client.
    """
    print(f"Received ROI config update/add request: {data}")
    try:
        roi_id_from_client = data.get('roi_id') # Can be null/empty for new, or an existing ID for update
        coordinates = data.get('coordinates') # Expected as [x1,y1,x2,y2] from JS, convert to tuple
        model_name = data.get('model_name')
        target_classes = data.get('target_classes', [])
        min_conf = float(data.get('min_conf', 0.5))
        max_no_detection_time = int(data.get('max_no_detection_time', 60))

        if not model_name or model_name not in loaded_models:
            socketio.emit('roi_update_error', {'roi_id': roi_id_from_client, 'message': f"Model '{model_name}' not loaded or not available."})
            return

        if not coordinates or not (isinstance(coordinates, list) and len(coordinates) == 4 and all(isinstance(c, int) for c in coordinates)):
            socketio.emit('roi_update_error', {'roi_id': roi_id_from_client, 'message': 'Invalid coordinates format. Expected list/array of 4 integers.'})
            return
        
        # Convert list from JS to tuple for Python side
        coordinates_tuple: Tuple[int, int, int, int] = tuple(coordinates)


        # Determine if it's an add or update based on roi_id_from_client and if it exists
        # Note: ROIManager.add_roi can also handle updates if roi_id is provided and exists,
        # but its update_roi is more explicit for updates. We'll use add_roi for simplicity if new,
        # and update_roi if roi_id_from_client is provided and exists.

        existing_roi = None
        if roi_id_from_client:
            existing_roi = roi_manager.get_roi(roi_id_from_client)

        if existing_roi:
            # Update existing ROI
            success = roi_manager.update_roi(
                roi_id_from_client,
                coordinates=coordinates_tuple,
                model_name=model_name,
                target_classes=target_classes,
                min_conf=min_conf,
                max_no_detection_time=max_no_detection_time
            )
            if success:
                print(f"ROI {roi_id_from_client} updated.")
                # Emit to the requesting client
                socketio.emit('roi_update_success', {
                    'roi_id': roi_id_from_client, 
                    'config': roi_manager.get_roi(roi_id_from_client),
                    'message': 'ROI updated successfully.'
                })
                # Broadcast updated list to all
                socketio.emit('roi_list_updated', {'rois': roi_manager.get_all_rois()}, broadcast=True)
            else: # Should not happen if get_roi found it, but as a safeguard
                socketio.emit('roi_update_error', {'roi_id': roi_id_from_client, 'message': f'Failed to update ROI {roi_id_from_client}.'})

        else:
            # Add new ROI (roi_id_from_client might be None or a client-generated temp ID)
            # ROIManager will generate a new UUID if roi_id_from_client is None or not already used.
            # If client sends a specific ID for a new ROI, ROIManager will use it.
            new_roi_id = roi_manager.add_roi(
                coordinates=coordinates_tuple,
                model_name=model_name,
                target_classes=target_classes,
                min_conf=min_conf,
                max_no_detection_time=max_no_detection_time,
                roi_id=roi_id_from_client if roi_id_from_client and not roi_id_from_client.startswith('temp_') else None
            )
            print(f"ROI {new_roi_id} added.")
            # Reset last detection time for the new ROI
            roi_last_detection_time[new_roi_id] = time.time() 
            
            # Emit to the requesting client
            socketio.emit('roi_add_success', {
                'roi_id': new_roi_id, 
                'config': roi_manager.get_roi(new_roi_id),
                'message': 'ROI added successfully.'
            })
            # Broadcast updated list to all
            socketio.emit('roi_list_updated', {'rois': roi_manager.get_all_rois()}, broadcast=True)
        
        print(f"Current ROIs: {roi_manager.get_all_rois()}")

    except ValueError as ve:
        print(f"ValueError processing ROI config: {ve}")
        socketio.emit('roi_update_error', {'roi_id': data.get('roi_id'), 'message': f"Invalid data format: {ve}"})
    except Exception as e:
        print(f"Error processing ROI config: {e}")
        socketio.emit('roi_update_error', {'roi_id': data.get('roi_id'), 'message': str(e)})

@socketio.on('remove_roi')
def handle_remove_roi(data):
    roi_id = data.get('roi_id')
    print(f"Received request to remove ROI: {roi_id}")
    if not roi_id:
        socketio.emit('roi_remove_error', {'message': 'ROI ID missing'})
        return

    if roi_manager.remove_roi(roi_id):
        if roi_id in roi_last_detection_time:
            del roi_last_detection_time[roi_id]
        print(f"ROI {roi_id} removed.")
        socketio.emit('roi_removed_success', {'roi_id': roi_id}) # To requester
        socketio.emit('roi_list_updated', {'rois': roi_manager.get_all_rois()}, broadcast=True) # To all
    else:
        print(f"Failed to remove ROI {roi_id} or ROI not found.")
        socketio.emit('roi_remove_error', {'roi_id': roi_id, 'message': 'Failed to remove ROI or ROI not found'})

if __name__ == '__main__':
    print("Starting video processing thread...")
    video_capture_thread = threading.Thread(target=video_processing_thread_func, daemon=True)
    video_capture_thread.start()
    
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, use_reloader=False) # use_reloader=False is important for threads
    
    # Signal the thread to stop when the server is shut down
    stop_video_processing_flag.set()
    if video_capture_thread:
        video_capture_thread.join(timeout=5) # Wait for thread to finish
    print("Application exiting.")
