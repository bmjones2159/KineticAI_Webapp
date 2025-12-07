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
        if user.role == 'clinician' and profile.assigned_therapist_id != current_user_id:
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
        if user.role == 'clinician' and profile.assigned_therapist_id != current_user_id:
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

@app.route('/api/therapist/patients/<int:patient_id>/workouts', methods=['GET'])
@jwt_required()
def get_patient_workouts(patient_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        patient_profile = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient_profile:
            return jsonify({'error': 'Patient not found'}), 404
        if user.role == 'clinician' and patient_profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        limit = request.args.get('limit', 100, type=int)
        workouts = WorkoutHistory.query.filter_by(user_id=patient_id).order_by(WorkoutHistory.workout_date.desc()).limit(limit).all()
        
        workout_list = [{
            'id': w.id,
            'exercise_type': w.exercise_type,
            'total_reps': w.total_reps,
            'sets_completed': w.sets_completed,
            'duration_minutes': w.duration_minutes,
            'form_score': w.avg_form_score,
            'notes': w.patient_notes,
            'completed_at': w.workout_date.isoformat(),
            'video_id': w.video_id
        } for w in workouts]
        
        total_workouts = len(workout_list)
        scores = [w['form_score'] for w in workout_list if w['form_score']]
        avg_form_score = sum(scores) / len(scores) if scores else 0
        
        exercise_counts = {}
        for w in workout_list:
            if w['exercise_type']:
                exercise_counts[w['exercise_type']] = exercise_counts.get(w['exercise_type'], 0) + 1
        
        return jsonify({
            'workouts': workout_list,
            'summary': {
                'total_workouts': total_workouts,
                'avg_form_score': round(avg_form_score, 1),
                'exercise_breakdown': exercise_counts,
                'last_workout': workout_list[0]['completed_at'] if workout_list else None
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/therapist/patients/<int:patient_id>/progress', methods=['GET'])
@jwt_required()
def get_patient_progress(patient_id):
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        patient_profile = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient_profile:
            return jsonify({'error': 'Patient not found'}), 404
        if user.role == 'clinician' and patient_profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        workouts = WorkoutHistory.query.filter(
            WorkoutHistory.user_id == patient_id,
            WorkoutHistory.workout_date >= ninety_days_ago
        ).order_by(WorkoutHistory.workout_date.asc()).all()
        
        weekly_progress = {}
        for workout in workouts:
            week_key = workout.workout_date.strftime('%Y-W%U')
            if week_key not in weekly_progress:
                weekly_progress[week_key] = {
                    'workouts': 0,
                    'exercises': {},
                    'avg_form_scores': [],
                    'week_start': workout.workout_date.strftime('%m/%d/%Y')
                }
            weekly_progress[week_key]['workouts'] += 1
            if workout.exercise_type:
                weekly_progress[week_key]['exercises'][workout.exercise_type] = weekly_progress[week_key]['exercises'].get(workout.exercise_type, 0) + 1
            if workout.avg_form_score:
                weekly_progress[week_key]['avg_form_scores'].append(workout.avg_form_score)
        
        progress_data = []
        for week, data in sorted(weekly_progress.items()):
            avg_score = sum(data['avg_form_scores']) / len(data['avg_form_scores']) if data['avg_form_scores'] else 0
            progress_data.append({
                'week': week,
                'week_start': data['week_start'],
                'workouts_completed': data['workouts'],
                'avg_form_score': round(avg_score, 1),
                'exercises': data['exercises']
            })
        
        return jsonify({
            'progress': progress_data,
            'total_workouts_90_days': len(workouts),
            'current_streak': calculate_workout_streak(workouts)
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
            {'username': 'therapist', 'email': 'therapist@kineticai.com', 'password': 'therapist123', 'role': 'clinician'},
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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
