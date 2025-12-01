"""
Kinetic AI Video Analysis Module
Integrated from Colab notebook - YOLOv8 Pose Estimation
"""

import cv2
import numpy as np
import math
import json
from datetime import datetime
from collections import Counter
from ultralytics import YOLO
import os

class KineticAnalyzer:
    """Main analyzer class for exercise form detection and analysis"""
    
    def __init__(self, model_path='yolov8m-pose.pt'):
        """Initialize the analyzer with YOLOv8 pose model"""
        self.model = YOLO(model_path)
        print(f"✓ YOLOv8-Pose model loaded: {model_path}")
        
    def calculate_angle(self, a, b, c):
        """Calculate angle at point b given three points a, b, c"""
        a = np.array(a)
        b = np.array(b)
        c = np.array(c)
        
        radians = np.arctan2(c[1]-b[1], c[0]-b[0]) - np.arctan2(a[1]-b[1], a[0]-b[0])
        angle = np.abs(radians * 180.0 / np.pi)
        
        if angle > 180.0:
            angle = 360 - angle
            
        return angle
    
    def extract_keypoints_from_video(self, video_path):
        """Extract keypoints from video using YOLOv8 pose estimation"""
        cap = cv2.VideoCapture(video_path)
        keypoints_sequence = []
        frame_count = 0
        
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
                
            # Run YOLOv8 pose estimation
            results = self.model(frame, verbose=False)
            
            # Extract keypoints
            if len(results) > 0 and results[0].keypoints is not None:
                keypoints = results[0].keypoints.xy.cpu().numpy()
                if len(keypoints) > 0:
                    keypoints_sequence.append(keypoints[0])  # First person detected
                else:
                    keypoints_sequence.append(np.zeros((17, 2)))  # No person detected
            else:
                keypoints_sequence.append(np.zeros((17, 2)))
                
            frame_count += 1
            
        cap.release()
        return keypoints_sequence, frame_count
    
    def detect_exercise_type(self, keypoints_sequence, num_frames=30):
        """Detect exercise type based on keypoint movement patterns"""
        if len(keypoints_sequence) < num_frames:
            num_frames = len(keypoints_sequence)
            
        hip_heights = []
        shoulder_heights = []
        horizontal_movement = []
        
        for i in range(num_frames):
            kp = keypoints_sequence[i]
            
            if len(kp) < 17:
                continue
                
            # Hip position
            if kp[11].any() and kp[12].any():
                hip_y = (kp[11][1] + kp[12][1]) / 2
                hip_heights.append(hip_y)
                
            # Shoulder position
            if kp[5].any() and kp[6].any():
                shoulder_y = (kp[5][1] + kp[6][1]) / 2
                shoulder_heights.append(shoulder_y)
                
            # Horizontal movement (x-axis)
            if kp[11].any() and kp[12].any():
                hip_x = (kp[11][0] + kp[12][0]) / 2
                horizontal_movement.append(hip_x)
        
        # Analysis
        if len(hip_heights) < 5:
            return 'unknown'
            
        hip_range = max(hip_heights) - min(hip_heights)
        shoulder_range = max(shoulder_heights) - min(shoulder_heights) if shoulder_heights else 0
        
        # Simple heuristics for exercise detection
        if hip_range > 100:  # Significant vertical hip movement
            return 'squat'
        elif shoulder_range > 80:  # Significant shoulder movement
            return 'pushup'
        elif hip_range < 30 and shoulder_range < 30:  # Minimal movement
            return 'plank'
        else:
            return 'squat'  # Default
    
    def get_joint_angles(self, keypoints):
        """Calculate key joint angles from keypoints"""
        angles = {}
        
        # Left elbow angle (shoulder-elbow-wrist)
        if keypoints[5].any() and keypoints[7].any() and keypoints[9].any():
            angles['left_elbow'] = self.calculate_angle(
                keypoints[5], keypoints[7], keypoints[9]
            )
            
        # Right elbow angle
        if keypoints[6].any() and keypoints[8].any() and keypoints[10].any():
            angles['right_elbow'] = self.calculate_angle(
                keypoints[6], keypoints[8], keypoints[10]
            )
            
        # Left knee angle (hip-knee-ankle)
        if keypoints[11].any() and keypoints[13].any() and keypoints[15].any():
            angles['left_knee'] = self.calculate_angle(
                keypoints[11], keypoints[13], keypoints[15]
            )
            
        # Right knee angle
        if keypoints[12].any() and keypoints[14].any() and keypoints[16].any():
            angles['right_knee'] = self.calculate_angle(
                keypoints[12], keypoints[14], keypoints[16]
            )
            
        # Left hip angle (shoulder-hip-knee)
        if keypoints[5].any() and keypoints[11].any() and keypoints[13].any():
            angles['left_hip'] = self.calculate_angle(
                keypoints[5], keypoints[11], keypoints[13]
            )
            
        # Right hip angle
        if keypoints[6].any() and keypoints[12].any() and keypoints[14].any():
            angles['right_hip'] = self.calculate_angle(
                keypoints[6], keypoints[12], keypoints[14]
            )
            
        # Left shoulder angle (hip-shoulder-elbow)
        if keypoints[11].any() and keypoints[5].any() and keypoints[7].any():
            angles['left_shoulder'] = self.calculate_angle(
                keypoints[11], keypoints[5], keypoints[7]
            )
            
        # Right shoulder angle
        if keypoints[12].any() and keypoints[6].any() and keypoints[8].any():
            angles['right_shoulder'] = self.calculate_angle(
                keypoints[12], keypoints[6], keypoints[8]
            )
            
        return angles
    
    def analyze_form(self, keypoints_sequence, exercise_type='squat', reference_angles=None):
        """Analyze exercise form and detect issues"""
        issues = []
        frame_accuracy = []
        all_angles = []
        
        for frame_idx, keypoints in enumerate(keypoints_sequence):
            frame_angles = self.get_joint_angles(keypoints)
            all_angles.append(frame_angles)
            
            frame_issues = []
            
            # Exercise-specific form checks
            if exercise_type == 'squat':
                # Check knee angle
                if 'left_knee' in frame_angles and 'right_knee' in frame_angles:
                    knee_avg = (frame_angles['left_knee'] + frame_angles['right_knee']) / 2
                    if knee_avg > 110:  # Knees not bent enough
                        frame_issues.append('shallow_squat')
                    elif knee_avg < 70:  # Too deep
                        frame_issues.append('deep_squat')
                        
                # Check back angle
                if 'left_hip' in frame_angles and 'right_hip' in frame_angles:
                    hip_avg = (frame_angles['left_hip'] + frame_angles['right_hip']) / 2
                    if hip_avg < 160:  # Back rounding
                        frame_issues.append('back_rounding')
                        
            elif exercise_type == 'pushup':
                # Check elbow angle
                if 'left_elbow' in frame_angles and 'right_elbow' in frame_angles:
                    elbow_avg = (frame_angles['left_elbow'] + frame_angles['right_elbow']) / 2
                    if elbow_avg > 110:  # Not going low enough
                        frame_issues.append('shallow_pushup')
                        
            elif exercise_type == 'plank':
                # Check body alignment
                if 'left_hip' in frame_angles and 'right_hip' in frame_angles:
                    hip_avg = (frame_angles['left_hip'] + frame_angles['right_hip']) / 2
                    if hip_avg < 160:  # Hips sagging
                        frame_issues.append('hips_sagging')
                    elif hip_avg > 190:  # Hips too high
                        frame_issues.append('hips_high')
            
            issues.extend(frame_issues)
            
            # Calculate frame accuracy (0 issues = 100%, each issue reduces by 20%)
            accuracy = max(0, 100 - (len(frame_issues) * 20))
            frame_accuracy.append(accuracy)
        
        # Calculate overall metrics
        avg_accuracy = np.mean(frame_accuracy) if frame_accuracy else 0
        issue_counts = Counter(issues)
        most_common_issues = issue_counts.most_common(3)
        
        return {
            'exercise_type': exercise_type,
            'total_frames': len(keypoints_sequence),
            'average_accuracy': round(avg_accuracy, 2),
            'frame_accuracies': frame_accuracy,
            'issues': dict(issue_counts),
            'most_common_issues': most_common_issues,
            'all_angles': all_angles,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def analyze_video(self, video_path, exercise_type=None):
        """Complete video analysis pipeline"""
        print(f"Analyzing video: {video_path}")
        
        # Extract keypoints
        keypoints, frame_count = self.extract_keypoints_from_video(video_path)
        print(f"✓ Extracted keypoints from {frame_count} frames")
        
        # Detect exercise type if not provided
        if exercise_type is None:
            exercise_type = self.detect_exercise_type(keypoints)
            print(f"✓ Detected exercise type: {exercise_type}")
        
        # Analyze form
        analysis = self.analyze_form(keypoints, exercise_type)
        print(f"✓ Analysis complete - Accuracy: {analysis['average_accuracy']}%")
        
        return analysis
    
    def create_annotated_video(self, video_path, output_path, analysis_results):
        """Create annotated video with pose overlay and feedback"""
        cap = cv2.VideoCapture(video_path)
        
        # Get video properties
        fps = int(cap.get(cv2.CAP_PROP_FPS))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # Video writer
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        frame_idx = 0
        
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
                
            # Run pose estimation
            results = self.model(frame, verbose=False)
            
            # Draw pose overlay
            if len(results) > 0 and results[0].keypoints is not None:
                annotated_frame = results[0].plot()
            else:
                annotated_frame = frame
                
            # Add accuracy text
            if frame_idx < len(analysis_results['frame_accuracies']):
                accuracy = analysis_results['frame_accuracies'][frame_idx]
                color = (0, 255, 0) if accuracy > 80 else (0, 165, 255) if accuracy > 60 else (0, 0, 255)
                cv2.putText(annotated_frame, f"Accuracy: {accuracy:.0f}%", 
                           (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)
                
            # Add exercise type
            cv2.putText(annotated_frame, f"Exercise: {analysis_results['exercise_type']}", 
                       (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
            
            out.write(annotated_frame)
            frame_idx += 1
            
        cap.release()
        out.release()
        
        print(f"✓ Annotated video saved to: {output_path}")
        return output_path


def export_to_csv(keypoints_sequence, all_angles, output_path):
    """Export skeletal data and angles to CSV"""
    import pandas as pd
    
    data = []
    
    for frame_idx, (keypoints, angles) in enumerate(zip(keypoints_sequence, all_angles)):
        row = {'frame': frame_idx}
        
        # Add keypoint coordinates
        keypoint_names = [
            'nose', 'left_eye', 'right_eye', 'left_ear', 'right_ear',
            'left_shoulder', 'right_shoulder', 'left_elbow', 'right_elbow',
            'left_wrist', 'right_wrist', 'left_hip', 'right_hip',
            'left_knee', 'right_knee', 'left_ankle', 'right_ankle'
        ]
        
        for i, name in enumerate(keypoint_names):
            if i < len(keypoints):
                row[f'{name}_x'] = keypoints[i][0]
                row[f'{name}_y'] = keypoints[i][1]
        
        # Add angles
        for angle_name, angle_value in angles.items():
            row[angle_name] = angle_value
            
        data.append(row)
    
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"✓ Data exported to: {output_path}")
    
    return output_path


if __name__ == "__main__":
    # Test the analyzer
    analyzer = KineticAnalyzer()
    print("Kinetic AI Analyzer initialized and ready!")
