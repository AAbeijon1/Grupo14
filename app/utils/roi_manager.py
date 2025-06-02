import uuid
from typing import Dict, List, Optional, Tuple, Any

class ROIManager:
    """Manages Regions of Interest (ROIs) configurations."""

    def __init__(self) -> None:
        """Initializes an empty dictionary to store ROI configurations."""
        self.rois: Dict[str, Dict[str, Any]] = {}

    def add_roi(self, 
                coordinates: Tuple[int, int, int, int], 
                model_name: str, 
                target_classes: List[str], 
                min_conf: float, 
                max_no_detection_time: int,
                roi_id: Optional[str] = None) -> str:
        """
        Adds a new ROI configuration.

        Args:
            roi_id: Optional. A unique ID for the ROI. If None, a new UUID will be generated.
            coordinates: A tuple (x1, y1, x2, y2) defining the ROI bounding box.
            model_name: The name of the model to be used for this ROI.
            target_classes: A list of target class names for detection.
            min_conf: Minimum confidence threshold for detections.
            max_no_detection_time: Maximum time (in seconds) without detection before an alert.

        Returns:
            The ID of the added ROI.
        """
        if roi_id is None:
            roi_id = str(uuid.uuid4())
        
        self.rois[roi_id] = {
            "coordinates": coordinates,
            "model_name": model_name,
            "target_classes": target_classes,
            "min_conf": min_conf,
            "max_no_detection_time": max_no_detection_time,
            "last_detection_time": None, # Placeholder for tracking
            "alert_triggered": False # Placeholder for alert status
        }
        return roi_id

    def remove_roi(self, roi_id: str) -> bool:
        """
        Removes the ROI with the given roi_id.

        Args:
            roi_id: The ID of the ROI to remove.

        Returns:
            True if successful, False otherwise.
        """
        if roi_id in self.rois:
            del self.rois[roi_id]
            return True
        return False

    def update_roi(self, 
                   roi_id: str, 
                   coordinates: Optional[Tuple[int, int, int, int]] = None, 
                   model_name: Optional[str] = None, 
                   target_classes: Optional[List[str]] = None, 
                   min_conf: Optional[float] = None, 
                   max_no_detection_time: Optional[int] = None) -> bool:
        """
        Updates the configuration for the specified roi_id.
        Only updates fields for which a new value is provided.

        Args:
            roi_id: The ID of the ROI to update.
            coordinates: Optional. New coordinates (x1, y1, x2, y2) for the ROI bounding box.
            model_name: Optional. New model name for the ROI.
            target_classes: Optional. New list of target classes.
            min_conf: Optional. New minimum confidence threshold.
            max_no_detection_time: Optional. New maximum time without detection.

        Returns:
            True if successful, False if roi_id not found.
        """
        if roi_id not in self.rois:
            return False

        roi = self.rois[roi_id]
        if coordinates is not None:
            roi["coordinates"] = coordinates
        if model_name is not None:
            roi["model_name"] = model_name
        if target_classes is not None:
            roi["target_classes"] = target_classes
        if min_conf is not None:
            roi["min_conf"] = min_conf
        if max_no_detection_time is not None:
            roi["max_no_detection_time"] = max_no_detection_time
        
        return True

    def get_roi(self, roi_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns the configuration of the specified roi_id.

        Args:
            roi_id: The ID of the ROI to retrieve.

        Returns:
            The ROI configuration dictionary, or None if not found.
        """
        return self.rois.get(roi_id)

    def get_all_rois(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns the dictionary of all ROI configurations.

        Returns:
            A dictionary containing all ROI configurations.
        """
        return self.rois

if __name__ == '__main__':
    # Example Usage
    manager = ROIManager()

    # Add ROI
    roi1_id = manager.add_roi(
        coordinates=(0, 0, 100, 100),  # (x1, y1, x2, y2)
        model_name="model_A",
        target_classes=["person", "car"],
        min_conf=0.5,
        max_no_detection_time=60
    )
    print(f"Added ROI {roi1_id}: {manager.get_roi(roi1_id)}")

    roi2_id = manager.add_roi(
        coordinates=(50, 50, 150, 150), # (x1, y1, x2, y2)
        model_name="model_B",
        target_classes=["cat"],
        min_conf=0.7,
        max_no_detection_time=120
    )
    print(f"Added ROI {roi2_id}: {manager.get_roi(roi2_id)}")

    # Get all ROIs
    print(f"\nAll ROIs: {manager.get_all_rois()}")

    # Update ROI
    manager.update_roi(roi1_id, min_conf=0.6, target_classes=["person"])
    print(f"\nUpdated ROI {roi1_id}: {manager.get_roi(roi1_id)}")

    # Get specific ROI
    print(f"\nROI {roi2_id} data: {manager.get_roi(roi2_id)}")

    # Remove ROI
    manager.remove_roi(roi1_id)
    print(f"\nRemoved ROI {roi1_id}. All ROIs now: {manager.get_all_rois()}")

    # Try to get removed ROI
    print(f"\nTrying to get removed ROI {roi1_id}: {manager.get_roi(roi1_id)}")

    # Try to update non-existent ROI
    print(f"\nTrying to update non-existent ROI: {manager.update_roi('non_existent_id', min_conf=0.9)}")
    
    # Try to remove non-existent ROI
    print(f"\nTrying to remove non-existent ROI: {manager.remove_roi('non_existent_id')}")
