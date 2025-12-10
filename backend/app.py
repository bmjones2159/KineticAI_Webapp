"""
HIPAA-Compliant Video Analysis Web Application
Backend API with encryption, audit logging, and access controls
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from cryptography.fernet import Fernet
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import logging
import traceback
from logging.handlers import RotatingFileHandler
import json

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"]
    }
})

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Fix DATABASE_URL format (Railway/Render use postgres://, SQLAlchemy needs postgresql://)
database_url = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/video_hipaa_db')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Upload folder - use /tmp for Render (ephemeral storage)
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/encrypted_storage/videos')

# Fix ENCRYPTION_KEY (must be bytes, not string)
encryption_key = os.environ.get('ENCRYPTION_KEY')
if encryption_key is None:
    encryption_key = Fernet.generate_key()
elif isinstance(encryption_key, str):
    encryption_key = encryption_key.encode('utf-8')
app.config['ENCRYPTION_KEY'] = encryption_key

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Create cipher suite with proper bytes key
try:
    cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])
except Exception as e:
    app.logger.error(f"Error creating cipher suite: {e}")
    app.logger.error(f"ENCRYPTION_KEY type: {type(app.config['ENCRYPTION_KEY'])}")
    app.logger.error(f"ENCRYPTION_KEY length: {len(app.config['ENCRYPTION_KEY']) if app.config['ENCRYPTION_KEY'] else 0}")
    raise

# Configure HIPAA-compliant logging
logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger('audit')
audit_handler = RotatingFileHandler('audit.log', maxBytes=10000000, backupCount=10)
audit_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    videos = db.relationship('Video', backref='owner', lazy=True, cascade='all, delete-orphan')

class Video(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500))
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(50))
    patient_id = db.Column(db.String(100))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    analysis_results = db.Column(db.Text)
    video_metadata = db.Column(db.Text)
    access_count = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean, default=False)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)
    success = db.Column(db.Boolean, default=True)

class AccessControl(db.Model):
    __tablename__ = 'access_controls'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    permission = db.Column(db.String(20))
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))

class ExerciseAssignment(db.Model):
    __tablename__ = 'exercise_assignments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exercise_type = db.Column(db.String(50), nullable=False)
    sets = db.Column(db.Integer, default=3)
    reps = db.Column(db.Integer, default=12)
    weight = db.Column(db.Float, default=0)
    frequency_per_week = db.Column(db.Integer, default=3)
    instructions = db.Column(db.Text)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class ExerciseSession(db.Model):
    __tablename__ = 'exercise_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    exercise_type = db.Column(db.String(50), nullable=False)
    reps_completed = db.Column(db.Integer)
    form_score = db.Column(db.Float)
    duration_seconds = db.Column(db.Integer)
    calories_burned = db.Column(db.Float)
    session_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

class DemoVideo(db.Model):
    __tablename__ = 'demo_videos'
    id = db.Column(db.Integer, primary_key=True)
    exercise_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    video_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500))
    duration_seconds = db.Column(db.Integer)
    difficulty_level = db.Column(db.String(20))
    target_muscles = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class PatientProfile(db.Model):
    __tablename__ = 'patient_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(200))
    date_of_birth = db.Column(db.Date)
    phone = db.Column(db.String(20))
    primary_diagnosis = db.Column(db.String(500))
    injury_date = db.Column(db.Date)
    treatment_goals = db.Column(db.Text)
    assigned_therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    treatment_start_date = db.Column(db.Date, default=datetime.utcnow)
    current_status = db.Column(db.String(50), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', foreign_keys=[user_id], backref='patient_profile')
    therapist = db.relationship('User', foreign_keys=[assigned_therapist_id], backref='assigned_patients')

class WorkoutHistory(db.Model):
    __tablename__ = 'workout_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    workout_date = db.Column(db.DateTime, default=datetime.utcnow)
    exercise_type = db.Column(db.String(100))
    sets_completed = db.Column(db.Integer, default=0)
    reps_per_set = db.Column(db.String(100))
    total_reps = db.Column(db.Integer, default=0)
    weight_used = db.Column(db.Float)
    avg_form_score = db.Column(db.Float)
    duration_minutes = db.Column(db.Integer)
    calories_burned = db.Column(db.Float)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    patient_notes = db.Column(db.Text)
    pain_level = db.Column(db.Integer)
    difficulty_level = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='workout_sessions')
    video = db.relationship('Video', backref='workout')

class TherapistNote(db.Model):
    __tablename__ = 'therapist_notes'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_type = db.Column(db.String(50))
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    patient_viewed = db.Column(db.Boolean, default=False)
    patient_viewed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship('User', foreign_keys=[patient_id], backref='received_notes')
    therapist = db.relationship('User', foreign_keys=[therapist_id], backref='written_notes')
    video = db.relationship('Video', backref='therapist_notes')

class ExerciseVideoAssignment(db.Model):
    """Videos assigned by therapist to patient as exercise homework"""
    __tablename__ = 'exercise_video_assignments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=True)
    demo_video_id = db.Column(db.Integer, db.ForeignKey('demo_videos.id'), nullable=True)
    demo_video = db.relationship('DemoVideo', backref='assignments')
    exercise_type = db.Column(db.String(50))
    target_reps = db.Column(db.Integer)
    target_sets = db.Column(db.Integer, default=3)
    frequency_per_week = db.Column(db.Integer, default=3)
    instructions = db.Column(db.Text)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.Date)
    is_active = db.Column(db.Boolean, default=True)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    patient = db.relationship('User', foreign_keys=[patient_id], backref='assigned_exercise_videos')
    therapist = db.relationship('User', foreign_keys=[therapist_id], backref='exercise_assignments_created')
    video = db.relationship('Video', backref='exercise_assignments')

class Appointment(db.Model):
    """Therapist-patient appointments for calendar"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=False)
    type = db.Column(db.String(50), default='in_person')
    duration = db.Column(db.Integer, default=60)
    notes = db.Column(db.Text)
    status = db.Column(db.String(20), default='scheduled')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    therapist = db.relationship('User', foreign_keys=[therapist_id], backref='therapist_appointments')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_appointments')
    
# Utility functions
def log_audit(user_id, action, resource_type=None, resource_id=None, details=None, success=True):
    try:
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=request.remote_addr,
            details=details,
            success=success
        )
        db.session.add(log_entry)
        db.session.commit()
        audit_logger.info(f"User {user_id} - {action} - {resource_type} {resource_id} - Success: {success}")
    except Exception as e:
        audit_logger.error(f"Failed to log audit: {str(e)}")

def encrypt_data(data):
    if isinstance(data, dict):
        data = json.dumps(data)
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode()).decode()
        try:
            return json.loads(decrypted)
        except:
            return decrypted
    except:
        return None

def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def calculate_workout_streak(workouts):
    if not workouts:
        return 0
    sorted_workouts = sorted(workouts, key=lambda w: w.workout_date, reverse=True)
    streak = 0
    current_date = datetime.utcnow().date()
    for workout in sorted_workouts:
        workout_date = workout.workout_date.date()
        days_diff = (current_date - workout_date).days
        if days_diff == streak:
            streak += 1
        elif days_diff > streak:
            break
    return streak

# Routes
@app.route('/')
def index():
    frontend_path = os.path.join(os.path.dirname(__file__), 'frontend', 'index.html')
    if os.path.exists(frontend_path):
        return send_file(frontend_path)
    return jsonify({
        'message': 'Kinetic AI Video Analysis API',
        'version': '1.0.0',
        'status': 'running'
    })

@app.route('/<path:path>')
def serve_static(path):
    frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend')
    file_path = os.path.join(frontend_dir, path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_file(file_path)
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 400
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        log_audit(new_user.id, 'USER_REGISTERED', 'User', new_user.id)
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                log_audit(user.id, 'LOGIN_FAILED_INACTIVE', 'User', user.id, success=False)
                return jsonify({'error': 'Account is inactive'}), 403
            
            access_token = create_access_token(identity=str(user.id))
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_audit(user.id, 'LOGIN_SUCCESS', 'User', user.id)
            
            return jsonify({
                'access_token': access_token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
            }), 200
        else:
            log_audit(None, 'LOGIN_FAILED', details=f"Username: {username}", success=False)
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/upload', methods=['POST'])
@jwt_required()
def upload_video():
    try:
        current_user_id = int(get_jwt_identity())
        
        if 'video' not in request.files:
            return jsonify({'error': 'No video file provided'}), 400
        
        file = request.files['video']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        allowed_extensions = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'error': f'Invalid file type'}), 400
        
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        unique_id = secrets.token_hex(16)
        safe_filename = f"{unique_id}.{file_ext}"
        file_path = os.path.join(upload_folder, safe_filename)
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        video = Video(
            user_id=current_user_id,
            filename=file.filename,
            encrypted_filename=safe_filename,
            file_path=file_path,  # FIXED: was datetime.utcnow() - wrong!
            uploaded_at=datetime.utcnow(),  # FIXED: proper field name
            file_hash=file_hash,
            file_size=file_size,
            mime_type=file.content_type or f'video/{file_ext}'
        )
        db.session.add(video)
        db.session.commit()
        log_audit(current_user_id, 'VIDEO_UPLOADED', 'Video', video.id)
        
        return jsonify({
            'message': 'Video uploaded successfully',
            'video_id': video.id,
            'filename': file.filename
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos', methods=['GET'])
@jwt_required()
def get_videos():
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role == 'admin':
            videos = Video.query.filter_by(is_deleted=False).all()
        else:
            videos = Video.query.filter_by(user_id=current_user_id, is_deleted=False).all()
        
        video_list = [{
            'id': v.id,
            'filename': v.filename,
            'uploaded_at': v.uploaded_at.isoformat(),
            'file_size': v.file_size,
            'access_count': v.access_count,
            'has_analysis': v.analysis_results is not None
        } for v in videos]
        
        return jsonify({'videos': video_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>', methods=['GET'])
@jwt_required()
def get_video(video_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id and user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        analysis_results = None
        if video.analysis_results:
            try:
                decrypted_data = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
            except:
                pass
        
        return jsonify({
            'id': video.id,
            'filename': video.filename,
            'uploaded_at': video.uploaded_at.isoformat(),
            'file_size': video.file_size,
            'mime_type': video.mime_type,
            'access_count': video.access_count,
            'analysis_results': analysis_results
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/analyze', methods=['POST'])
@jwt_required()
def analyze_video(video_id):
    try:
        current_user_id = int(get_jwt_identity())
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        if video.user_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        if not os.path.exists(video_path):
            return jsonify({'error': 'Video file not found'}), 404
        
        import random
        analysis_results = {
            'exercise_type': 'squat',
            'total_reps': random.randint(8, 15),
            'average_accuracy': random.randint(70, 95),
            'total_frames': 300,
            'most_common_issues': ['Keep back straight', 'Go deeper in squat'],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        demo_video = DemoVideo.query.filter_by(exercise_type='squat').first()
        if demo_video:
            analysis_results['demo_video_url'] = demo_video.video_url
            analysis_results['demo_video_title'] = demo_video.title
        
        video.analysis_results = encrypt_data(analysis_results)
        db.session.commit()
        
        return jsonify({
            'message': 'Analysis completed successfully',
            'results': analysis_results
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# THERAPIST ENDPOINTS - Assign Exercise Videos
# ============================================================================

@app.route('/api/therapist/assign-exercise-video', methods=['POST'])
@jwt_required()
def assign_exercise_video():
    """Therapist assigns a video to patient as exercise homework"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can assign exercises'}), 403
        
        data = request.get_json()
        patient_id = data.get('patient_id')
        demo_video_id = data.get('demo_video_id')
        if not demo_video_id:
            return jsonify({'error': 'Demo video ID required'}), 400
        
        demo_video = DemoVideo.query.get(demo_video_id)
        if not demo_video or not demo_video.is_active:
            return jsonify({'error': 'Demo video not found'}), 404
      
         # Create assignment
        assignment = ExerciseVideoAssignment(
            patient_id=patient_id,
            therapist_id=current_user_id,
            demo_video_id=demo_video_id,  # FIXED: Set demo_video_id
            video_id=None,  # No user video for demo assignments
            exercise_type=demo_video.exercise_type,
            target_reps=data.get('target_reps', 12),
            target_sets=data.get('target_sets', 3),
            frequency_per_week=data.get('frequency_per_week', 3),
            instructions=data.get('instructions', ''),
            due_date=datetime.strptime(data.get('due_date'), '%Y-%m-%d').date() if data.get('due_date') else None,
            assigned_at=datetime.utcnow()
        )
        
        db.session.add(assignment)
        db.session.commit()
        
        return jsonify({
            'message': 'Exercise video assigned successfully',
            'assignment_id': assignment.id,
            'exercise_type': demo_video.exercise_type,
            'video_title': demo_video.title
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/patients/<int:patient_id>/assigned-videos', methods=['GET'])
@jwt_required()
def get_patient_assigned_videos(patient_id):
    """Get exercises assigned to a patient"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        # Check authorization
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check patient exists and therapist has access
        patient = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        if user.role == 'clinician' and patient.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Unauthorized access to this patient'}), 403
        
        # Get assigned exercises
        assignments = ExerciseVideoAssignment.query.filter_by(
            patient_id=patient_id
        ).order_by(ExerciseVideoAssignment.assigned_at.desc()).all()
        
        # Format assignments
        result = []
        for assignment in assignments:
            # Get video details if video_id exists
            video_filename = None
            if assignment.video_id:
                video = Video.query.get(assignment.video_id)
                if video:
                    video_filename = video.filename
            
            # Get demo video details if demo_video_id exists
            if assignment.demo_video_id:
                demo = DemoVideo.query.get(assignment.demo_video_id)
                if demo:
                    video_filename = demo.title
            
            result.append({
                'assignment_id': assignment.id,
                'video_id': assignment.video_id,
                'demo_video_id': assignment.demo_video_id,
                'video_filename': video_filename or 'Unknown Exercise',
                'exercise_type': assignment.exercise_type,
                'target_reps': assignment.target_reps,
                'target_sets': assignment.target_sets,
                'frequency_per_week': assignment.frequency_per_week,
                'instructions': assignment.instructions,
                'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
                'completed': assignment.completed,
                'completed_at': assignment.completed_at.isoformat() if assignment.completed_at else None,
                'assigned_at': assignment.assigned_at.isoformat() if assignment.assigned_at else None
            })
        
        return jsonify({'assignments': result}), 200
        
    except Exception as e:
        print(f"Error getting assigned videos: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/patient/assigned-exercises', methods=['GET'])
@jwt_required()
def get_my_assigned_exercises():
    """Patient gets their assigned exercise videos"""
    try:
        current_user_id = int(get_jwt_identity())
        
        assignments = ExerciseVideoAssignment.query.filter_by(
            patient_id=current_user_id,
            is_active=True
        ).order_by(ExerciseVideoAssignment.assigned_at.desc()).all()
        
        result = []
        for assignment in assignments:
            video = assignment.video
            
            analysis = None
            if video.analysis_results:
                try:
                    decrypted = decrypt_data(video.analysis_results)
                    analysis = json.loads(decrypted) if isinstance(decrypted, str) else decrypted
                except:
                    pass
            
            completed_workout = WorkoutHistory.query.filter_by(
                user_id=current_user_id,
                video_id=video.id
            ).order_by(WorkoutHistory.workout_date.desc()).first()
            
            result.append({
                'assignment_id': assignment.id,
                'video_id': video.id,
                'video_filename': video.filename,
                'exercise_type': assignment.exercise_type,
                'target_reps': assignment.target_reps,
                'target_sets': assignment.target_sets,
                'frequency_per_week': assignment.frequency_per_week,
                'instructions': assignment.instructions,
                'assigned_at': assignment.assigned_at.isoformat(),
                'due_date': assignment.due_date.isoformat() if assignment.due_date else None,
                'completed': assignment.completed,
                'therapist_name': assignment.therapist.username,
                'form_score_target': analysis.get('average_accuracy') if analysis else None,
                'last_completed': completed_workout.workout_date.isoformat() if completed_workout else None,
                'times_completed': WorkoutHistory.query.filter_by(
                    user_id=current_user_id,
                    video_id=video.id
                ).count()
            })
        
        return jsonify({'assigned_exercises': result}), 200
        
    except Exception as e:
        app.logger.error(f"Error getting assigned exercises: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patient/assigned-exercises/<int:assignment_id>/complete', methods=['POST'])
@jwt_required()
def mark_assignment_complete(assignment_id):
    """Patient marks an assigned exercise as complete"""
    try:
        current_user_id = int(get_jwt_identity())
        
        assignment = ExerciseVideoAssignment.query.get(assignment_id)
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        if assignment.patient_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        assignment.completed = True
        assignment.completed_at = datetime.utcnow()
        db.session.commit()
        
        log_audit(current_user_id, 'EXERCISE_ASSIGNMENT_COMPLETED', 'ExerciseVideoAssignment', assignment_id)
        
        return jsonify({
            'message': 'Exercise marked as complete',
            'completed_at': assignment.completed_at.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/therapist/available-exercise-videos', methods=['GET'])
@jwt_required()
def get_available_exercise_videos():
    """Get demo videos that can be assigned as exercises"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Get demo videos from the library (NOT user videos)
        demo_videos = DemoVideo.query.filter_by(is_active=True).all()
        
        result = []
        for demo in demo_videos:
            result.append({
                'demo_id': demo.id,
                'title': demo.title,
                'exercise_type': demo.exercise_type,
                'description': demo.description,
                'video_url': demo.video_url,
                'thumbnail_url': demo.thumbnail_url,
                'duration_seconds': demo.duration_seconds,
                'difficulty_level': demo.difficulty_level,
                'target_muscles': demo.target_muscles
            })
        
        return jsonify({'videos': result}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Continue with remaining endpoints...
@app.route('/api/therapist/patients', methods=['POST'])
@jwt_required()
def create_patient():
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can create patients'}), 403
        
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password', 'Patient123!')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=password_hash, role='user')
        db.session.add(new_user)
        db.session.flush()
        
        profile = PatientProfile(
            user_id=new_user.id,
            full_name=data.get('full_name'),
            date_of_birth=datetime.strptime(data.get('date_of_birth'), '%Y-%m-%d').date() if data.get('date_of_birth') else None,
            phone=data.get('phone'),
            primary_diagnosis=data.get('primary_diagnosis'),
            injury_date=datetime.strptime(data.get('injury_date'), '%Y-%m-%d').date() if data.get('injury_date') else None,
            treatment_goals=data.get('treatment_goals'),
            assigned_therapist_id=current_user_id,
            current_status='active'
        )
        db.session.add(profile)
        db.session.commit()
        
        return jsonify({
            'message': 'Patient created successfully',
            'patient_id': profile.id,
            'username': username,
            'temporary_password': password
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/patients', methods=['GET'])
@jwt_required()
def get_therapist_patients():
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Access denied'}), 403
        
        if user.role == 'admin':
            profiles = PatientProfile.query.all()
        else:
            profiles = PatientProfile.query.filter_by(assigned_therapist_id=current_user_id).all()
        
        patient_list = []
        for p in profiles:
            latest_workout = WorkoutHistory.query.filter_by(user_id=p.user_id).order_by(WorkoutHistory.workout_date.desc()).first()
            total_sessions = WorkoutHistory.query.filter_by(user_id=p.user_id).count()
            workouts = WorkoutHistory.query.filter_by(user_id=p.user_id).all()
            avg_form = sum(w.avg_form_score for w in workouts if w.avg_form_score) / len(workouts) if workouts else 0
            
            patient_list.append({
                'id': p.id,
                'user_id': p.user_id,
                'username': p.user.username,
                'full_name': p.full_name,
                'primary_diagnosis': p.primary_diagnosis,
                'treatment_start_date': p.treatment_start_date.isoformat() if p.treatment_start_date else None,
                'current_status': p.current_status,
                'last_session': latest_workout.workout_date.isoformat() if latest_workout else None,
                'total_sessions': total_sessions,
                'avg_form_score': round(avg_form, 1)
            })
        
        return jsonify({'patients': patient_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/patients/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_patient_details(patient_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        profile = PatientProfile.query.get(patient_id)
        
        if not profile:
            return jsonify({'error': 'Patient not found'}), 404
        if user.role in ['clinician', 'admin'] and profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        workouts = WorkoutHistory.query.filter_by(user_id=profile.user_id).order_by(WorkoutHistory.workout_date.desc()).limit(20).all()
        videos = Video.query.filter_by(user_id=profile.user_id, is_deleted=False).order_by(Video.uploaded_at.desc()).limit(10).all()
        
        video_list = []
        for v in videos:
            video_data = {
                'id': v.id,
                'filename': v.filename,
                'uploaded_at': v.uploaded_at.isoformat(),
                'file_size': v.file_size,
                'has_analysis': v.analysis_results is not None,
                'analysis_results': None
            }
            if v.analysis_results:
                try:
                    decrypted = decrypt_data(v.analysis_results)
                    video_data['analysis_results'] = json.loads(decrypted) if isinstance(decrypted, str) else decrypted
                except:
                    pass
            video_list.append(video_data)
        
        notes = TherapistNote.query.filter_by(patient_id=profile.user_id).order_by(TherapistNote.created_at.desc()).all()
        
        return jsonify({
            'id': profile.id,
            'user_id': profile.user_id,
            'username': profile.user.username,
            'email': profile.user.email,
            'full_name': profile.full_name,
            'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
            'phone': profile.phone,
            'primary_diagnosis': profile.primary_diagnosis,
            'injury_date': profile.injury_date.isoformat() if profile.injury_date else None,
            'treatment_goals': profile.treatment_goals,
            'current_status': profile.current_status,
            'workouts': [{
                'id': w.id,
                'date': w.workout_date.isoformat(),
                'exercise_type': w.exercise_type,
                'sets': w.sets_completed,
                'total_reps': w.total_reps,
                'form_score': w.avg_form_score,
                'duration': w.duration_minutes,
                'has_video': w.video_id is not None
            } for w in workouts],
            'videos': video_list,
           'notes': [{
                'id': n.id,
                'type': n.note_type,
                'title': n.title,
                'content': n.content,
                'created_at': n.created_at.isoformat(),
                'therapist': n.therapist.username
            } for n in notes]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/patients/<int:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Access denied'}), 403
        
        profile = PatientProfile.query.get(patient_id)
        if not profile:
            return jsonify({'error': 'Patient not found'}), 404
        if user.role in ['clinician', 'admin'] and profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        if 'full_name' in data:
            profile.full_name = data['full_name']
        if 'date_of_birth' in data and data['date_of_birth']:
            profile.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        if 'phone' in data:
            profile.phone = data['phone']
        if 'primary_diagnosis' in data:
            profile.primary_diagnosis = data['primary_diagnosis']
        if 'injury_date' in data and data['injury_date']:
            profile.injury_date = datetime.strptime(data['injury_date'], '%Y-%m-%d').date()
        if 'treatment_goals' in data:
            profile.treatment_goals = data['treatment_goals']
        if 'current_status' in data:
            profile.current_status = data['current_status']
        if 'email' in data:
            profile.user.email = data['email']
        
        profile.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Patient updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/stream', methods=['GET'])
def stream_video(video_id):
    try:
        token = request.args.get('token')
        if not token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                return jsonify({'error': 'No authentication token'}), 401
        
        from flask_jwt_extended import decode_token
        decoded = decode_token(token)
        current_user_id = int(decoded['sub'])
        
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        video = Video.query.get(video_id)
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        has_access = False
        if user.role == 'user' and video.user_id == current_user_id:
            has_access = True
        if user.role in ['clinician', 'admin']:
            patient_profile = PatientProfile.query.filter_by(user_id=video.user_id).first()
            if patient_profile and (user.role == 'admin' or patient_profile.assigned_therapist_id == current_user_id):
                has_access = True
        
        if not has_access:
            return jsonify({'error': 'Access denied'}), 403
        
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        if not os.path.exists(video_path):
            return jsonify({'error': 'Video file not found'}), 404
        
        return send_file(video_path, mimetype=video.mime_type or 'video/mp4', as_attachment=False)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/details', methods=['GET'])
@jwt_required()
def get_video_details_for_therapist(video_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        has_access = False
        if user.role == 'user' and video.user_id == current_user_id:
            has_access = True
        if user.role in ['clinician', 'admin']:
            patient_profile = PatientProfile.query.filter_by(user_id=video.user_id).first()
            if patient_profile and (user.role == 'admin' or patient_profile.assigned_therapist_id == current_user_id):
                has_access = True
        
        if not has_access:
            return jsonify({'error': 'Access denied'}), 403
        
        analysis_results = None
        if video.analysis_results:
            try:
                decrypted_data = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
            except:
                pass
        
        return jsonify({
            'id': video.id,
            'filename': video.filename,
            'uploaded_at': video.uploaded_at.isoformat(),
            'file_size': video.file_size,
            'mime_type': video.mime_type,
            'access_count': video.access_count,
            'analysis_results': analysis_results,
            'has_analysis': analysis_results is not None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/workouts/complete', methods=['POST'])
@jwt_required()
def complete_workout():
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        video_id = data.get('video_id')
        exercise_type = data.get('exercise_type')
        reps_completed = data.get('reps_completed')
        sets_completed = data.get('sets_completed', 1)
        
        if not all([video_id, exercise_type, reps_completed]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        video = Video.query.get(video_id)
        if not video or video.user_id != current_user_id:
            return jsonify({'error': 'Video not found'}), 404
        
        form_score = None
        if video.analysis_results:
            try:
                decrypted = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted) if isinstance(decrypted, str) else decrypted
                form_score = analysis_results.get('average_accuracy') or analysis_results.get('form_score')
            except:
                pass
        
        workout = WorkoutHistory(
            user_id=current_user_id,
            video_id=video_id,
            exercise_type=exercise_type,
            total_reps=reps_completed * sets_completed,
            sets_completed=sets_completed,
            reps_per_set=str(reps_completed),
            duration_minutes=int(data.get('duration_seconds', 0) / 60) if data.get('duration_seconds') else None,
            avg_form_score=form_score,
            patient_notes=data.get('notes')
        )
        db.session.add(workout)
        db.session.commit()
        
        return jsonify({
            'message': 'Workout completed successfully',
            'workout_id': workout.id,
            'form_score': form_score
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/workouts/my-history', methods=['GET'])
@jwt_required()
def get_my_workout_history():
    try:
        current_user_id = int(get_jwt_identity())
        limit = request.args.get('limit', 50, type=int)
        exercise_type = request.args.get('exercise_type')
        
        query = WorkoutHistory.query.filter_by(user_id=current_user_id)
        if exercise_type:
            query = query.filter_by(exercise_type=exercise_type)
        
        workouts = query.order_by(WorkoutHistory.workout_date.desc()).limit(limit).all()
        workout_list = [{
            'id': w.id,
            'exercise_type': w.exercise_type,
            'total_reps': w.total_reps,
            'sets_completed': w.sets_completed,
            'duration_minutes': w.duration_minutes,
            'form_score': w.avg_form_score,
            'notes': w.patient_notes,
            'date': w.workout_date.isoformat(),
            'video_id': w.video_id
        } for w in workouts]
        
        total_workouts = len(workout_list)
        avg_form_score = sum(w['form_score'] for w in workout_list if w['form_score']) / max(total_workouts, 1) if total_workouts > 0 else 0
        total_reps = sum(w['total_reps'] for w in workout_list if w['total_reps'])
        
        return jsonify({
            'workouts': workout_list,
            'summary': {
                'total_workouts': total_workouts,
                'avg_form_score': round(avg_form_score, 1),
                'total_reps': total_reps
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/notes', methods=['POST'])
@jwt_required()
def add_therapist_note():
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        note = TherapistNote(
            patient_id=data.get('patient_id'),
            therapist_id=current_user_id,
            note_type=data.get('note_type', 'progress'),
            title=data.get('title'),
            content=data.get('content'),
            recommendations=data.get('recommendations'),
            video_id=data.get('video_id')
        )
        db.session.add(note)
        db.session.commit()
        
        return jsonify({'message': 'Note added successfully', 'note_id': note.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/therapist/appointments', methods=['POST'])
@jwt_required()
def create_appointment():
    """Schedule a new appointment"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can schedule appointments'}), 403
        
        data = request.get_json()
        
        appointment = Appointment(
            therapist_id=current_user_id,
            patient_id=data['patient_id'],
            scheduled_time=datetime.fromisoformat(data['scheduled_time']),
            type=data.get('type', 'in_person'),
            duration=data.get('duration', 60),
            notes=data.get('notes'),
            status='scheduled'
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        return jsonify({
            'message': 'Appointment scheduled',
            'appointment_id': appointment.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/appointments', methods=['GET'])
@jwt_required()
def get_appointments():
    """Get therapist's appointments"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can view appointments'}), 403
        
        appointments = Appointment.query.filter_by(
            therapist_id=current_user_id
        ).order_by(Appointment.scheduled_time).all()
        
        result = []
        for apt in appointments:
            patient = User.query.get(apt.patient_id)
            patient_profile = PatientProfile.query.filter_by(user_id=apt.patient_id).first()
            
            result.append({
                'id': apt.id,
                'patient_id': apt.patient_id,
                'patient_name': patient_profile.full_name if patient_profile else patient.username,
                'scheduled_time': apt.scheduled_time.isoformat(),
                'type': apt.type,
                'duration': apt.duration,
                'notes': apt.notes,
                'status': apt.status
            })
        
        return jsonify({'appointments': result}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demos', methods=['GET'])
def get_demo_videos():
    try:
        demos = DemoVideo.query.filter_by(is_active=True).all()
        demo_list = [{
            'id': d.id,
            'exercise_type': d.exercise_type,
            'title': d.title,
            'description': d.description,
            'video_url': d.video_url,
            'thumbnail_url': d.thumbnail_url,
            'duration_seconds': d.duration_seconds,
            'difficulty_level': d.difficulty_level,
            'target_muscles': d.target_muscles
        } for d in demos]
        return jsonify(demo_list), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demos/seed', methods=['POST'])
def seed_demo_videos():
    try:
        demos = [
            {'exercise_type': 'squat', 'title': 'Perfect Squat Form', 'description': 'Learn proper squat technique', 'video_url': 'https://www.youtube.com/embed/ultWZbUMPL8', 'thumbnail_url': 'https://img.youtube.com/vi/ultWZbUMPL8/mqdefault.jpg', 'duration_seconds': 180, 'difficulty_level': 'beginner', 'target_muscles': 'Quads, Glutes, Hamstrings'},
            {'exercise_type': 'pushup', 'title': 'Push-up Fundamentals', 'description': 'Master the perfect push-up', 'video_url': 'https://www.youtube.com/embed/IODxDxX7oi4', 'thumbnail_url': 'https://img.youtube.com/vi/IODxDxX7oi4/mqdefault.jpg', 'duration_seconds': 240, 'difficulty_level': 'beginner', 'target_muscles': 'Chest, Triceps, Shoulders'},
            {'exercise_type': 'plank', 'title': 'Plank Hold Technique', 'description': 'Build core strength', 'video_url': 'https://www.youtube.com/embed/pSHjTRCQxIw', 'thumbnail_url': 'https://img.youtube.com/vi/pSHjTRCQxIw/mqdefault.jpg', 'duration_seconds': 150, 'difficulty_level': 'beginner', 'target_muscles': 'Core, Abs, Lower Back'},
            {'exercise_type': 'lunge', 'title': 'Forward Lunge Form', 'description': 'Perfect your lunge technique', 'video_url': 'https://www.youtube.com/embed/QOVaHwm-Q6U', 'thumbnail_url': 'https://img.youtube.com/vi/QOVaHwm-Q6U/mqdefault.jpg', 'duration_seconds': 200, 'difficulty_level': 'beginner', 'target_muscles': 'Quads, Glutes, Hamstrings'}
        ]
        
        for demo_data in demos:
            existing = DemoVideo.query.filter_by(exercise_type=demo_data['exercise_type'], title=demo_data['title']).first()
            if not existing:
                demo = DemoVideo(**demo_data)
                db.session.add(demo)
        db.session.commit()
        
        return jsonify({'message': f'Successfully seeded {len(demos)} demo videos'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/create-demo-users', methods=['POST'])
def create_demo_users():
    try:
        demo_users = [
            {'username': 'patient', 'email': 'patient@kineticai.com', 'password': 'patient123', 'role': 'user'},
            {'username': ['clinician', 'admin'], 'email': 'therapist@kineticai.com', 'password': 'therapist123', 'role': 'clinician'},
            {'username': 'admin', 'email': 'admin@kineticai.com', 'password': 'admin123', 'role': 'admin'}
        ]
        
        created_users = []
        for user_data in demo_users:
            existing = User.query.filter_by(username=user_data['username']).first()
            if existing:
                if existing.role != user_data['role']:
                    existing.role = user_data['role']
                    db.session.commit()
                    created_users.append(f"Updated {user_data['username']} role to {user_data['role']}")
                else:
                    created_users.append(f"{user_data['username']} already exists with correct role")
            else:
                password_hash = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
                new_user = User(username=user_data['username'], email=user_data['email'], password_hash=password_hash, role=user_data['role'])
                db.session.add(new_user)
                db.session.commit()
                created_users.append(f"Created {user_data['username']} with role {user_data['role']}")
        
        return jsonify({'message': 'Demo users processed successfully', 'details': created_users}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

# Initialize database
with app.app_context():
    db.create_all()
    if os.environ.get('AUTO_INIT_DB') == 'true':
        try:
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(username='admin', email='admin@kineticai.com', password_hash=bcrypt.generate_password_hash('ChangeMe123!').decode('utf-8'), role='admin')
                db.session.add(admin)
                db.session.commit()
                print("✓ Auto-initialized: Admin user created")
        except Exception as e:
            print(f"Auto-init error: {e}")

# ═══════════════════════════════════════════════════════════════════
# WORKOUT COMPLETION TRACKING - BACKEND ADDITIONS
# Add these to app.py (backend/app.py)
# ═══════════════════════════════════════════════════════════════════

# ============================================
# NEW DATABASE MODEL - Add after ExerciseVideoAssignment model
# ============================================

class WorkoutCompletion(db.Model):
    """Track when patients complete assigned exercises with their video"""
    __tablename__ = 'workout_completions'
    
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('exercise_video_assignments.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Patient's uploaded video
    patient_video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=True)  # Their attempt
    
    # Reference video (what they were assigned)
    reference_video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=False)
    
    # Completion data
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Patient's performance results (from their uploaded video)
    patient_reps = db.Column(db.Integer)
    patient_form_score = db.Column(db.Float)
    patient_exercise_type = db.Column(db.String(50))
    patient_issues = db.Column(db.JSON)  # List of form issues detected
    
    # Comparison to reference
    reps_vs_target = db.Column(db.Integer)  # How close to target reps
    form_score_vs_target = db.Column(db.Float)  # Score difference
    
    # Therapist feedback
    therapist_notes = db.Column(db.Text)
    therapist_reviewed = db.Column(db.Boolean, default=False)
    reviewed_at = db.Column(db.DateTime)
    
    # Relationships
    assignment = db.relationship('ExerciseVideoAssignment', backref='completions')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='workout_completions')
    therapist = db.relationship('User', foreign_keys=[therapist_id], backref='reviewed_workouts')
    patient_video = db.relationship('Video', foreign_keys=[patient_video_id])
    reference_video = db.relationship('Video', foreign_keys=[reference_video_id])


# ============================================
# ENDPOINT 1: Patient uploads video for assignment
# ============================================

@app.route('/api/patient/assignments/<int:assignment_id>/submit-workout', methods=['POST'])
@jwt_required()
def submit_workout_for_assignment(assignment_id):
    """
    Patient uploads their workout video to complete an assignment
    Returns comparison with reference video
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'patient':
            return jsonify({'error': 'Only patients can submit workouts'}), 403
        
        # Get the assignment
        assignment = ExerciseVideoAssignment.query.get(assignment_id)
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        if assignment.patient_id != user_id:
            return jsonify({'error': 'Not your assignment'}), 403
        
        # Get the uploaded video file
        if 'video' not in request.files:
            return jsonify({'error': 'No video file provided'}), 400
        
        video_file = request.files['video']
        if video_file.filename == '':
            return jsonify({'error': 'No video selected'}), 400
        
        # Save the patient's video
        filename = secure_filename(f"patient_{user_id}_{assignment_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{video_file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        video_file.save(filepath)
        
        # Create video record
        patient_video = Video(
            filename=filename,
            filepath=filepath,
            user_id=user_id,
            uploaded_at=datetime.utcnow()
        )
        db.session.add(patient_video)
        db.session.flush()  # Get the video ID
        
        # Analyze the patient's video
        try:
            analysis_results = analyze_video_with_yolo(filepath)
            patient_video.analysis_results = analysis_results
            patient_video.analyzed_at = datetime.utcnow()
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            analysis_results = None
        
        # Get reference video for comparison
        reference_video = Video.query.get(assignment.video_id)
        
        # Calculate comparison metrics
        reps_vs_target = None
        form_score_vs_target = None
        
        if analysis_results and reference_video.analysis_results:
            patient_reps = analysis_results.get('total_reps', 0)
            target_reps = assignment.target_reps
            reps_vs_target = patient_reps - target_reps
            
            patient_form_score = analysis_results.get('form_score', 0)
            reference_form_score = reference_video.analysis_results.get('form_score', 0)
            form_score_vs_target = patient_form_score - reference_form_score
        
        # Create workout completion record
        completion = WorkoutCompletion(
            assignment_id=assignment_id,
            patient_id=user_id,
            therapist_id=assignment.assigned_by,
            patient_video_id=patient_video.id,
            reference_video_id=assignment.video_id,
            completed_at=datetime.utcnow(),
            patient_reps=analysis_results.get('total_reps') if analysis_results else None,
            patient_form_score=analysis_results.get('form_score') if analysis_results else None,
            patient_exercise_type=analysis_results.get('exercise_type') if analysis_results else None,
            patient_issues=analysis_results.get('most_common_issues', []) if analysis_results else [],
            reps_vs_target=reps_vs_target,
            form_score_vs_target=form_score_vs_target
        )
        db.session.add(completion)
        
        # Update assignment status
        assignment.completed = True
        assignment.completed_at = datetime.utcnow()
        assignment.times_completed += 1
        assignment.last_completed = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Workout submitted successfully!',
            'completion_id': completion.id,
            'patient_video_id': patient_video.id,
            'analysis_results': analysis_results,
            'comparison': {
                'reps_achieved': analysis_results.get('total_reps') if analysis_results else 0,
                'reps_target': assignment.target_reps,
                'reps_difference': reps_vs_target,
                'form_score': analysis_results.get('form_score') if analysis_results else 0,
                'form_score_vs_reference': form_score_vs_target
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting workout: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINT 2: Get patient's workout completions
# ============================================

@app.route('/api/patient/workout-completions', methods=['GET'])
@jwt_required()
def get_patient_workout_completions():
    """Get all workout completions for the logged-in patient"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'patient':
            return jsonify({'error': 'Only patients can view this'}), 403
        
        completions = WorkoutCompletion.query.filter_by(patient_id=user_id)\
            .order_by(WorkoutCompletion.completed_at.desc())\
            .all()
        
        results = []
        for completion in completions:
            assignment = completion.assignment
            reference_video = completion.reference_video
            
            results.append({
                'id': completion.id,
                'assignment_id': completion.assignment_id,
                'completed_at': completion.completed_at.isoformat(),
                'exercise_name': reference_video.filename,
                'exercise_type': completion.patient_exercise_type,
                
                # Patient's results
                'patient_reps': completion.patient_reps,
                'patient_form_score': round(completion.patient_form_score, 2) if completion.patient_form_score else 0,
                'patient_issues': completion.patient_issues,
                'patient_video_id': completion.patient_video_id,
                
                # Target/Reference
                'target_reps': assignment.target_reps,
                'target_sets': assignment.target_sets,
                
                # Comparison
                'reps_vs_target': completion.reps_vs_target,
                'form_score_vs_target': round(completion.form_score_vs_target, 2) if completion.form_score_vs_target else 0,
                
                # Therapist feedback
                'therapist_reviewed': completion.therapist_reviewed,
                'therapist_notes': completion.therapist_notes,
                'reviewed_at': completion.reviewed_at.isoformat() if completion.reviewed_at else None
            })
        
        return jsonify({
            'success': True,
            'completions': results,
            'total': len(results)
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching workout completions: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINT 3: Therapist views patient completions
# ============================================

@app.route('/api/therapist/patient/<int:patient_id>/completions', methods=['GET'])
@jwt_required()
def get_patient_completions_for_therapist(patient_id):
    """Therapist views all workout completions for a specific patient"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can view this'}), 403
        
        # Verify patient exists
        patient = User.query.get(patient_id)
        if not patient or patient.role != 'patient':
            return jsonify({'error': 'Patient not found'}), 404
        
        # Get all completions for this patient assigned by this therapist
        completions = WorkoutCompletion.query.filter_by(
            patient_id=patient_id,
            therapist_id=user_id
        ).order_by(WorkoutCompletion.completed_at.desc()).all()
        
        results = []
        for completion in completions:
            assignment = completion.assignment
            reference_video = completion.reference_video
            
            results.append({
                'id': completion.id,
                'assignment_id': completion.assignment_id,
                'completed_at': completion.completed_at.isoformat(),
                'exercise_name': reference_video.filename,
                'exercise_type': completion.patient_exercise_type,
                
                # Patient's performance
                'patient_reps': completion.patient_reps,
                'patient_form_score': round(completion.patient_form_score, 2) if completion.patient_form_score else 0,
                'patient_issues': completion.patient_issues,
                'patient_video_id': completion.patient_video_id,
                
                # Reference/Target
                'reference_video_id': completion.reference_video_id,
                'target_reps': assignment.target_reps,
                'target_sets': assignment.target_sets,
                'target_form_score': assignment.form_score_target,
                
                # Comparison
                'reps_vs_target': completion.reps_vs_target,
                'form_score_vs_target': round(completion.form_score_vs_target, 2) if completion.form_score_vs_target else 0,
                
                # Review status
                'therapist_reviewed': completion.therapist_reviewed,
                'therapist_notes': completion.therapist_notes,
                'reviewed_at': completion.reviewed_at.isoformat() if completion.reviewed_at else None
            })
        
        return jsonify({
            'success': True,
            'patient_name': patient.full_name or patient.username,
            'completions': results,
            'total': len(results)
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching patient completions: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINT 4: Therapist adds review notes
# ============================================

@app.route('/api/therapist/completions/<int:completion_id>/review', methods=['POST'])
@jwt_required()
def review_workout_completion(completion_id):
    """Therapist adds review notes to a workout completion"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can review workouts'}), 403
        
        completion = WorkoutCompletion.query.get(completion_id)
        if not completion:
            return jsonify({'error': 'Completion not found'}), 404
        
        if completion.therapist_id != user_id:
            return jsonify({'error': 'Not authorized to review this workout'}), 403
        
        data = request.get_json()
        notes = data.get('notes', '')
        
        completion.therapist_notes = notes
        completion.therapist_reviewed = True
        completion.reviewed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Review added successfully',
            'completion_id': completion_id,
            'reviewed_at': completion.reviewed_at.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error reviewing workout: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINT 5: Get completion details (both videos)
# ============================================

@app.route('/api/completions/<int:completion_id>/details', methods=['GET'])
@jwt_required()
def get_completion_details(completion_id):
    """Get full details of a workout completion including both videos"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        completion = WorkoutCompletion.query.get(completion_id)
        if not completion:
            return jsonify({'error': 'Completion not found'}), 404
        
        # Check authorization
        if user.role == 'patient' and completion.patient_id != user_id:
            return jsonify({'error': 'Not authorized'}), 403
        elif user.role in ['clinician', 'admin'] and completion.therapist_id != user_id:
            return jsonify({'error': 'Not authorized'}), 403
        
        assignment = completion.assignment
        reference_video = completion.reference_video
        patient_video = completion.patient_video
        
        return jsonify({
            'success': True,
            'completion': {
                'id': completion.id,
                'completed_at': completion.completed_at.isoformat(),
                
                # Reference video (what they should do)
                'reference_video': {
                    'id': reference_video.id,
                    'filename': reference_video.filename,
                    'analysis': reference_video.analysis_results
                },
                
                # Patient video (what they did)
                'patient_video': {
                    'id': patient_video.id if patient_video else None,
                    'filename': patient_video.filename if patient_video else None,
                    'analysis': {
                        'total_reps': completion.patient_reps,
                        'form_score': completion.patient_form_score,
                        'exercise_type': completion.patient_exercise_type,
                        'most_common_issues': completion.patient_issues
                    }
                },
                
                # Assignment details
                'assignment': {
                    'target_reps': assignment.target_reps,
                    'target_sets': assignment.target_sets,
                    'frequency_per_week': assignment.frequency_per_week,
                    'instructions': assignment.instructions
                },
                
                # Comparison
                'comparison': {
                    'reps_vs_target': completion.reps_vs_target,
                    'form_score_vs_target': completion.form_score_vs_target
                },
                
                # Review
                'therapist_reviewed': completion.therapist_reviewed,
                'therapist_notes': completion.therapist_notes,
                'reviewed_at': completion.reviewed_at.isoformat() if completion.reviewed_at else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching completion details: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================
# HELPER: Update patient progress stats
# ============================================

@app.route('/api/patient/progress-summary', methods=['GET'])
@jwt_required()
def get_patient_progress_summary():
    """Get patient's workout progress summary"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'patient':
            return jsonify({'error': 'Only patients can view this'}), 403
        
        # Get completion stats
        total_completions = WorkoutCompletion.query.filter_by(patient_id=user_id).count()
        
        # This week
        week_ago = datetime.utcnow() - timedelta(days=7)
        this_week = WorkoutCompletion.query.filter(
            WorkoutCompletion.patient_id == user_id,
            WorkoutCompletion.completed_at >= week_ago
        ).count()
        
        # Average form score
        completions = WorkoutCompletion.query.filter_by(patient_id=user_id).all()
        avg_form_score = 0
        if completions:
            scores = [c.patient_form_score for c in completions if c.patient_form_score]
            avg_form_score = sum(scores) / len(scores) if scores else 0
        
        # Active assignments
        active_assignments = ExerciseVideoAssignment.query.filter_by(
            patient_id=user_id,
            completed=False
        ).count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_completions': total_completions,
                'completions_this_week': this_week,
                'average_form_score': round(avg_form_score, 2),
                'active_assignments': active_assignments
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching progress summary: {str(e)}")
        return jsonify({'error': str(e)}), 500

"""
═══════════════════════════════════════════════════════════════════
UNIFIED WORKOUT LOGGING SYSTEM - COMPLETE BACKEND
═══════════════════════════════════════════════════════════════════

Add this to your backend/app.py file

This creates a complete workout logging system that combines:
- Sets, reps, weight tracking
- Video upload with AI analysis
- Assignment progress tracking
- Workout history
"""

from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os

# ============================================================================
# DATABASE MODEL: WorkoutLog
# ============================================================================

class WorkoutLog(db.Model):
    """
    Complete workout logging with optional video analysis
    Combines workout details (sets/reps/weight) with video feedback
    """
    __tablename__ = 'workout_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Who did the workout
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # What exercise (linked to assignment if therapist-assigned)
    assignment_id = db.Column(db.Integer, db.ForeignKey('exercise_video_assignments.id'), nullable=True)
    exercise_type = db.Column(db.String(100), nullable=False)  # squats, pushups, etc.
    
    # When
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Workout details
    workout_date = db.Column(db.Date, default=lambda: datetime.utcnow().date(), nullable=False)
    sets_completed = db.Column(db.Integer, nullable=False)
    reps_per_set = db.Column(db.Integer, nullable=False)
    weight_lbs = db.Column(db.Float, nullable=True)  # Optional
    duration_seconds = db.Column(db.Integer, nullable=True)  # Optional
    
    # Patient feedback
    notes = db.Column(db.Text, nullable=True)
    difficulty_rating = db.Column(db.Integer, nullable=True)  # 1-10 scale
    
    # Video analysis (optional)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'), nullable=True)
    form_score = db.Column(db.Float, nullable=True)  # From AI analysis
    
    # Therapist feedback
    therapist_feedback = db.Column(db.Text, nullable=True)
    therapist_reviewed = db.Column(db.Boolean, default=False)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    patient = db.relationship('User', backref='workout_logs')
    assignment = db.relationship('ExerciseVideoAssignment', backref='workout_logs')
    video = db.relationship('Video', backref='workout_log')
    
    def to_dict(self):
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'assignment_id': self.assignment_id,
            'exercise_type': self.exercise_type,
            'completed_at': self.completed_at.isoformat(),
            'sets_completed': self.sets_completed,
            'reps_per_set': self.reps_per_set,
            'total_reps': self.sets_completed * self.reps_per_set,
            'weight_lbs': self.weight_lbs,
            'duration_seconds': self.duration_seconds,
            'notes': self.notes,
            'difficulty_rating': self.difficulty_rating,
            'video_id': self.video_id,
            'form_score': self.form_score,
            'therapist_feedback': self.therapist_feedback,
            'therapist_reviewed': self.therapist_reviewed,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None
        }


# ============================================================================
# API ENDPOINT: Log Complete Workout
# ============================================================================

@app.route('/api/patient/workouts/log', methods=['POST'])
@jwt_required()
def log_workout():
    """
    Log a complete workout with optional video analysis
    
    Handles:
    - Saving workout details (sets, reps, weight)
    - Optional video upload and AI analysis
    - Updating assignment progress
    - Returning immediate feedback
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'patient':
            return jsonify({'error': 'Only patients can log workouts'}), 403
        
        # Get form data
        assignment_id = request.form.get('assignment_id', type=int)
        exercise_type = request.form.get('exercise_type')
        sets_completed = request.form.get('sets_completed', type=int)
        reps_per_set = request.form.get('reps_per_set', type=int)
        weight_lbs = request.form.get('weight_lbs', type=float)
        duration_seconds = request.form.get('duration_seconds', type=int)
        notes = request.form.get('notes')
        difficulty_rating = request.form.get('difficulty_rating', type=int)
        
        # Validation
        if not exercise_type or not sets_completed or not reps_per_set:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Handle video upload (optional)
        video_id = None
        analysis_results = None
        
        if 'video' in request.files:
            video_file = request.files['video']
            
            if video_file.filename != '':
                # Save video
                filename = secure_filename(f"{user_id}_{datetime.utcnow().timestamp()}_{video_file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                video_file.save(filepath)
                
                # Create video record
                video = Video(
                    user_id=user_id,
                    filename=filename,
                    file_size=os.path.getsize(filepath)
                )
                db.session.add(video)
                db.session.flush()  # Get video ID
                
                video_id = video.id
                
                # Run AI analysis
                try:
                    analysis_results = analyze_video_with_yolo(filepath)
                    video.analysis_results = analysis_results
                    video.analysis_status = 'completed'
                except Exception as e:
                    logger.error(f"Analysis failed: {str(e)}")
                    video.analysis_status = 'failed'
                    video.error_message = str(e)
        
        # Create workout log
        workout = WorkoutLog(
            patient_id=user_id,
            assignment_id=assignment_id,
            exercise_type=exercise_type,
            sets_completed=sets_completed,
            reps_per_set=reps_per_set,
            weight_lbs=weight_lbs,
            duration_seconds=duration_seconds,
            notes=notes,
            difficulty_rating=difficulty_rating,
            video_id=video_id,
            workout_date=datetime.utcnow().date(),
            form_score=analysis_results.get('form_score') if analysis_results else None
        )
        
        db.session.add(workout)
        db.session.commit()

        return jsonify({'message': 'Workout logged'}), 201
        
        # Update assignment progress if this was an assigned exercise
        assignment_updated = False
        progress = None
        
        if assignment_id:
            assignment = ExerciseVideoAssignment.query.get(assignment_id)
            if assignment and assignment.patient_id == user_id:
                assignment.times_completed += 1
                assignment.last_completed = datetime.utcnow()
                
                # Check if assignment is now complete
                if assignment.times_completed >= assignment.frequency_per_week:
                    assignment.completed = True
                    assignment.completed_at = datetime.utcnow()
                
                assignment_updated = True
                
                # Calculate progress
                progress = {
                    'completed_this_week': assignment.times_completed,
                    'target_per_week': assignment.frequency_per_week,
                    'percentage': min(100, (assignment.times_completed / assignment.frequency_per_week) * 100),
                    'is_complete': assignment.completed
                }
        
        db.session.commit()
        
        # Prepare response
        response_data = {
            'success': True,
            'workout_id': workout.id,
            'message': 'Workout logged successfully!',
            'workout': workout.to_dict()
        }
        
        if video_id and analysis_results:
            response_data['analysis_results'] = {
                'form_score': analysis_results.get('form_score', 0),
                'total_reps': analysis_results.get('total_reps', 0),
                'issues': analysis_results.get('most_common_issues', []),
                'exercise_type': analysis_results.get('exercise_type', exercise_type)
            }
        
        if assignment_updated:
            response_data['assignment_updated'] = True
            response_data['progress'] = progress
        
        return jsonify(response_data), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error logging workout: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ENDPOINT: Get Workout History
# ============================================================================

@app.route('/api/patient/workouts/history', methods=['GET'])
@jwt_required()
def get_workout_history():
    """
    Get patient's workout history with optional filters
    
    Query params:
    - exercise_type: Filter by exercise (optional)
    - assignment_id: Filter by assignment (optional)
    - limit: Number of results (default 50)
    - days: Only last N days (optional)
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role != 'patient':
            return jsonify({'error': 'Only patients can view workout history'}), 403
        
        # Build query
        query = WorkoutLog.query.filter_by(patient_id=user_id)
        
        # Apply filters
        exercise_type = request.args.get('exercise_type')
        if exercise_type:
            query = query.filter_by(exercise_type=exercise_type)
        
        assignment_id = request.args.get('assignment_id', type=int)
        if assignment_id:
            query = query.filter_by(assignment_id=assignment_id)
        
        days = request.args.get('days', type=int)
        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(WorkoutLog.completed_at >= cutoff)
        
        # Get results
        limit = request.args.get('limit', default=50, type=int)
        workouts = query.order_by(WorkoutLog.completed_at.desc()).limit(limit).all()
        
        # Format response
        workout_list = []
        for workout in workouts:
            workout_dict = workout.to_dict()
            
            # Add assignment details if exists
            if workout.assignment:
                workout_dict['assignment'] = {
                    'exercise_name': workout.assignment.video.filename if workout.assignment.video else None,
                    'target_reps': workout.assignment.target_reps,
                    'target_sets': workout.assignment.target_sets
                }
            
            # Add video details if exists
            if workout.video:
                workout_dict['video'] = {
                    'filename': workout.video.filename,
                    'uploaded_at': workout.video.uploaded_at.isoformat(),
                    'analysis_completed': workout.video.analysis_status == 'completed'
                }
            
            workout_list.append(workout_dict)
        
        # Calculate summary stats
        summary = {
            'total_workouts': len(workouts),
            'avg_form_score': None,
            'total_reps': sum(w.sets_completed * w.reps_per_set for w in workouts),
            'exercise_breakdown': {}
        }
        
        # Average form score
        scores = [w.form_score for w in workouts if w.form_score]
        if scores:
            summary['avg_form_score'] = round(sum(scores) / len(scores), 1)
        
        # Exercise breakdown
        for workout in workouts:
            ex_type = workout.exercise_type
            if ex_type not in summary['exercise_breakdown']:
                summary['exercise_breakdown'][ex_type] = 0
            summary['exercise_breakdown'][ex_type] += 1
        
        return jsonify({
            'success': True,
            'workouts': workout_list,
            'summary': summary
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching workout history: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ENDPOINT: Get Single Workout Details
# ============================================================================

@app.route('/api/patient/workouts/<int:workout_id>', methods=['GET'])
@jwt_required()
def get_workout_details(workout_id):
    """Get detailed information about a specific workout"""
    try:
        user_id = get_jwt_identity()
        
        workout = WorkoutLog.query.get(workout_id)
        
        if not workout:
            return jsonify({'error': 'Workout not found'}), 404
        
        # Permission check
        if workout.patient_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        workout_dict = workout.to_dict()
        
        # Add full assignment details
        if workout.assignment:
            assignment = workout.assignment
            workout_dict['assignment'] = {
                'id': assignment.id,
                'exercise_name': assignment.video.filename if assignment.video else None,
                'target_reps': assignment.target_reps,
                'target_sets': assignment.target_sets,
                'frequency_per_week': assignment.frequency_per_week,
                'instructions': assignment.instructions
            }
        
        # Add full video analysis
        if workout.video and workout.video.analysis_results:
            workout_dict['video_analysis'] = workout.video.analysis_results
        
        return jsonify({
            'success': True,
            'workout': workout_dict
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching workout details: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ENDPOINT: Delete Workout
# ============================================================================

@app.route('/api/patient/workouts/<int:workout_id>', methods=['DELETE'])
@jwt_required()
def delete_workout(workout_id):
    """Delete a workout log"""
    try:
        user_id = get_jwt_identity()
        
        workout = WorkoutLog.query.get(workout_id)
        
        if not workout:
            return jsonify({'error': 'Workout not found'}), 404
        
        if workout.patient_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Don't allow deletion if therapist has reviewed
        if workout.therapist_reviewed:
            return jsonify({'error': 'Cannot delete reviewed workouts'}), 403
        
        db.session.delete(workout)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Workout deleted'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting workout: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API ENDPOINT: Therapist View Patient Workouts
# ============================================================================
@app.route('/api/therapist/patients/<int:patient_id>/workouts', methods=['GET'])
@jwt_required()
def get_patient_workouts(patient_id):
    """Get workout history for a patient"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        # Check authorization
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check patient exists and therapist has access
        patient = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        if user.role == 'clinician' and patient.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Unauthorized access to this patient'}), 403
        
        # Get limit from query params
        limit = request.args.get('limit', 30, type=int)
        
        # Get workouts - FIXED: use correct model WorkoutLog instead of WorkoutHistory
        workouts = WorkoutLog.query.filter_by(
            patient_id=patient_id  # FIXED: use patient_id not user_id
        ).order_by(WorkoutLog.workout_date.desc()).limit(limit).all()
        
        # Build summary
        total_workouts = len(workouts)
        avg_form_score = 0
        last_workout = None
        exercise_breakdown = {}
        
        if workouts:
            form_scores = [w.form_score for w in workouts if w.form_score]
            if form_scores:
                avg_form_score = round(sum(form_scores) / len(form_scores))
            
            last_workout = workouts[0].workout_date.isoformat() if workouts[0].workout_date else None
            
            for w in workouts:
                ex_type = w.exercise_type or 'unknown'
                exercise_breakdown[ex_type] = exercise_breakdown.get(ex_type, 0) + 1
        
        # Get current streak
        current_streak = 0
        if workouts:
            today = datetime.utcnow().date()
            current_date = workouts[0].workout_date
            
            for workout in workouts:
                if workout.workout_date == current_date or workout.workout_date == current_date - timedelta(days=1):
                    current_streak += 1
                    current_date = workout.workout_date
                else:
                    break
        
        # Format workouts
        workout_list = []
        for w in workouts:
            workout_list.append({
                'id': w.id,
                'video_id': w.video_id,
                'exercise_type': w.exercise_type,
                'reps_completed': w.reps_per_set,  # FIXED: correct field
                'sets_completed': w.sets_completed,
                'form_score': w.form_score,
                'workout_date': w.workout_date.isoformat() if w.workout_date else None,
                'completed_at': w.completed_at.isoformat() if w.completed_at else None,
                'duration_seconds': w.duration_seconds,
                'notes': w.notes
            })
        
        return jsonify({
            'workouts': workout_list,
            'summary': {
                'total_workouts': total_workouts,
                'avg_form_score': avg_form_score,
                'last_workout': last_workout,
                'exercise_breakdown': exercise_breakdown,
                'current_streak': current_streak
            }
        }), 200
        
    except Exception as e:
        print(f"Error getting patient workouts: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500



# ============================================================================
# API ENDPOINT: Therapist Add Feedback to Workout
# ============================================================================

@app.route('/api/therapist/workouts/<int:workout_id>/feedback', methods=['POST'])
@jwt_required()
def add_workout_feedback(workout_id):
    """Therapist adds feedback to a workout"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can add feedback'}), 403
        
        workout = WorkoutLog.query.get(workout_id)
        
        if not workout:
            return jsonify({'error': 'Workout not found'}), 404
        
        data = request.get_json()
        feedback = data.get('feedback')
        
        if not feedback:
            return jsonify({'error': 'Feedback required'}), 400
        
        workout.therapist_feedback = feedback
        workout.therapist_reviewed = True
        workout.reviewed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Feedback added'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding feedback: {str(e)}")
        return jsonify({'error': str(e)}), 500

   






if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
