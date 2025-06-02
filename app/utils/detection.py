import cv2
import numpy as np
from ultralytics import YOLO
from typing import List, Dict, Tuple, Any

def perform_detection_on_roi(
    frame: np.ndarray, 
    model: Any,  # YOLO model object from ultralytics
    roi_coords: Tuple[int, int, int, int], 
    target_classes: List[str], 
    min_conf: float
) -> List[Dict[str, Any]]:
    """
    Performs object detection on a specified Region of Interest (ROI) within a frame.

    Args:
        frame: An OpenCV image (NumPy array).
        model: A loaded Ultralytics YOLOv8 model object.
        roi_coords: A tuple (x1, y1, x2, y2) defining the ROI, where (x1, y1) is 
                    the top-left corner and (x2, y2) is the bottom-right corner.
        target_classes: A list of class names (strings) to filter for. 
                        If empty, all classes are considered.
        min_conf: Minimum confidence threshold (e.g., 0.5).

    Returns:
        A list of dictionaries, where each dictionary represents a detected object 
        and contains keys 'box' (coordinates [x1, y1, x2, y2] relative to the 
        original frame), 'class_name', and 'confidence'.
    """
    detections_in_roi = []

    # Validate ROI coordinates and ensure they are within frame boundaries
    h, w = frame.shape[:2]
    x1, y1, x2, y2 = roi_coords

    # Clip ROI coordinates to be within frame dimensions
    x1_clipped = max(0, x1)
    y1_clipped = max(0, y1)
    x2_clipped = min(w, x2)
    y2_clipped = min(h, y2)

    if x1_clipped >= x2_clipped or y1_clipped >= y2_clipped:
        # Invalid or zero-area ROI after clipping
        return [] 

    # Crop the frame to the ROI
    roi_frame = frame[y1_clipped:y2_clipped, x1_clipped:x2_clipped]

    if roi_frame.size == 0:
        # ROI frame is empty, possibly due to invalid original coords
        return []

    # Perform inference on the cropped ROI
    results = model(roi_frame, verbose=False) # verbose=False to reduce console output

    # Process results
    if results and results[0].boxes:
        for detection in results[0].boxes:
            conf = float(detection.conf[0])
            
            if conf >= min_conf:
                class_id = int(detection.cls[0])
                class_name = model.names[class_id]

                if not target_classes or class_name in target_classes:
                    # Get bounding box (xyxy format)
                    box_roi = detection.xyxy[0].cpu().numpy().astype(int)
                    
                    # Adjust box coordinates from ROI-local to original frame-global
                    box_global = [
                        box_roi[0] + x1_clipped,
                        box_roi[1] + y1_clipped,
                        box_roi[2] + x1_clipped,
                        box_roi[3] + y1_clipped,
                    ]

                    detections_in_roi.append({
                        "box": box_global,
                        "class_name": class_name,
                        "confidence": conf
                    })
    
    return detections_in_roi

if __name__ == '__main__':
    # This is a placeholder for testing and might require a valid model and image.
    # Ensure 'yolov8n.pt' is downloaded or provide a path to a valid YOLOv8 model.
    # You may need to create a dummy app/models directory if it doesn't exist
    # and place the yolov8n.pt file (even a dummy one) there for the path to be valid.
    
    models_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
    if not os.path.exists(models_dir):
        os.makedirs(models_dir)
    
    # Attempt to load the model - replace 'yolov8n.pt' with your model if needed
    # For this example, we use the dummy file created in the 'models' directory.
    # If 'app/models/yolov8n.pt' is just a dummy, actual detection won't work,
    # but the function structure can be tested if model object is mocked.
    try:
        model_path = os.path.join(models_dir, 'yolov8n.pt')
        if not os.path.exists(model_path):
            print(f"Warning: Model file not found at {model_path}. Dummy file might not be sufficient for real detection.")
            # Create a dummy file if it doesn't exist, to allow YOLO constructor to pass
            with open(model_path, 'w') as f:
                f.write("# dummy model")

        model = YOLO(model_path) 
        print(f"Successfully loaded model: {model_path}")
    except Exception as e:
        print(f"Error loading YOLO model: {e}")
        print("Please ensure you have a valid '.pt' model file (e.g., 'yolov8n.pt')")
        print("in the 'app/models' directory or provide the correct path.")
        model = None # Set model to None to avoid errors in dummy run below
        # As a fallback for testing the function structure without a real model,
        # one might mock the model object here. For example:
        # class MockModel:
        #     def __init__(self):
        #         self.names = {0: 'person', 1: 'car', 2: 'cat'}
        #     def __call__(self, frame, verbose=False):
        #         # Return dummy detection results
        #         class MockDetection:
        #             def __init__(self, xyxy, conf, cls):
        #                 self.xyxy = [np.array(xyxy, dtype=float)]
        #                 self.conf = [float(conf)]
        #                 self.cls = [int(cls)]
        #         class MockBoxes:
        #             def __init__(self):
        #                 self.boxes = [
        #                     MockDetection([10,10,50,50], 0.9, 0), # person
        #                     MockDetection([60,60,100,100], 0.8, 1) # car
        #                 ]
        #         return [MockBoxes()]
        # model = MockModel()
        # print("Using mocked model for testing function structure.")


    if model:
        # Create a dummy frame (e.g., a black image)
        dummy_frame = np.zeros((640, 480, 3), dtype=np.uint8)
        cv2.putText(dummy_frame, "Test Image", (50,50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255,255,255), 2)
        
        # Define dummy ROI, target classes, and min_conf
        roi_coords_test = (50, 50, 250, 250) # x1, y1, x2, y2
        target_classes_test = ["person"]    # Only detect persons
        min_conf_test = 0.6

        # Test with potentially out-of-bounds ROI to check clipping
        roi_coords_oob_test = (-20, -20, 700, 500)


        print(f"\nTesting with standard ROI: {roi_coords_test}")
        detections = perform_detection_on_roi(
            dummy_frame, model, roi_coords_test, target_classes_test, min_conf_test
        )
        print(f"Detections: {detections}")

        print(f"\nTesting with out-of-bounds ROI: {roi_coords_oob_test}")
        detections_oob = perform_detection_on_roi(
            dummy_frame, model, roi_coords_oob_test, target_classes_test, min_conf_test
        )
        print(f"Detections (OOB ROI): {detections_oob}")

        print(f"\nTesting with empty target_classes (all classes):")
        detections_all_classes = perform_detection_on_roi(
            dummy_frame, model, roi_coords_test, [], 0.1 # Lower confidence for more potential dummy detections
        )
        print(f"Detections (all classes): {detections_all_classes}")
        
        # Test with invalid ROI (e.g., x1 > x2)
        roi_invalid_coords = (300, 50, 200, 250)
        print(f"\nTesting with invalid ROI: {roi_invalid_coords}")
        detections_invalid = perform_detection_on_roi(
            dummy_frame, model, roi_invalid_coords, target_classes_test, min_conf_test
        )
        print(f"Detections (invalid ROI): {detections_invalid}")

    else:
        print("Skipping perform_detection_on_roi tests as model could not be loaded.")
