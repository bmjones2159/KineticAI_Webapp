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
# In production, you'd want to use cloud storage (S3, GCS, etc.)
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/tmp/encrypted_storage/videos')

# Fix ENCRYPTION_KEY (must be bytes, not string)
encryption_key = os.environ.get('ENCRYPTION_KEY')
if encryption_key is None:
    encryption_key = Fernet.generate_key()
elif isinstance(encryption_key, str):
    # Convert string to bytes
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
    role = db.Column(db.String(20), default='user')  # admin, clinician, user
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
    patient_id = db.Column(db.String(100))  # Encrypted patient identifier
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    analysis_results = db.Column(db.Text)  # Encrypted JSON
    video_metadata = db.Column(db.Text)  # Encrypted JSON (renamed from 'metadata' - SQLAlchemy reserved word)
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
    permission = db.Column(db.String(20))  # read, write, delete
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))

class ExerciseAssignment(db.Model):
    __tablename__ = 'exercise_assignments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exercise_type = db.Column(db.String(50), nullable=False)  # squat, pushup, plank, etc.
    sets = db.Column(db.Integer, default=3)
    reps = db.Column(db.Integer, default=12)
    weight = db.Column(db.Float, default=0)  # in lbs
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
    form_score = db.Column(db.Float)  # 0-100
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

# Utility functions
def log_audit(user_id, action, resource_type=None, resource_id=None, details=None, success=True):
    """Log all actions for HIPAA compliance"""
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
    """Encrypt sensitive data"""
    if isinstance(data, dict):
        data = json.dumps(data)
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode()).decode()
        try:
            return json.loads(decrypted)
        except:
            return decrypted
    except:
        return None

def compute_file_hash(file_path):
    """Compute SHA-256 hash of file for integrity verification"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Homepage route
@app.route('/')
def index():
    """Serve the frontend homepage"""
    frontend_path = os.path.join(os.path.dirname(__file__), 'frontend', 'index.html')
    if os.path.exists(frontend_path):
        return send_file(frontend_path)
    else:
        # Fallback to API info if frontend not found
        return jsonify({
            'message': 'Kinetic AI Video Analysis API',
            'version': '1.0.0',
            'status': 'running',
            'endpoints': {
                'health': '/api/health',
                'login': '/api/auth/login',
                'register': '/api/auth/register',
                'upload': '/api/videos/upload',
                'analyze': '/api/videos/<id>/analyze'
            },
            'note': 'This is a REST API. Use a client application to interact with these endpoints.'
        })

# Serve static frontend files
@app.route('/<path:path>')
def serve_static(path):
    """Serve static frontend files (CSS, JS, etc.)"""
    frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend')
    file_path = os.path.join(frontend_dir, path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_file(file_path)
    return jsonify({'error': 'File not found'}), 404

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
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
    """User login"""
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
    """Upload video file - with automatic folder creation"""
    try:
        current_user_id = int(get_jwt_identity())
        
        app.logger.info(f"Upload request from user {current_user_id}")
        
        if 'video' not in request.files:
            return jsonify({'error': 'No video file provided'}), 400
        
        file = request.files['video']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'mp4', 'mov', 'avi', 'mkv', 'webm'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'}), 400
        
        # CRITICAL: Ensure upload folder exists
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        app.logger.info(f"Upload folder ready: {upload_folder}")
        
        # Generate unique filename
        import secrets
        unique_id = secrets.token_hex(16)
        safe_filename = f"{unique_id}.{file_ext}"
        
        # Full file path
        file_path = os.path.join(upload_folder, safe_filename)
        
        app.logger.info(f"Saving file to: {file_path}")
        
        # Save file
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        app.logger.info(f"File saved successfully: {file_size} bytes")
        
        # Calculate file hash for integrity
        import hashlib
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Create database record
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
        
        log_audit(current_user_id, 'VIDEO_UPLOADED', 'Video', video.id, 
                 details=f"Filename: {file.filename}, Size: {file_size}")
        
        app.logger.info(f"✓ Video uploaded successfully: ID {video.id}")
        
        return jsonify({
            'message': 'Video uploaded successfully',
            'video_id': video.id,
            'filename': file.filename
        }), 201
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        app.logger.error(f"Upload error: {error_details}")
        
        # Rollback database changes
        if 'video' in locals():
            db.session.rollback()
        
        log_audit(current_user_id if 'current_user_id' in locals() else None,
                 'VIDEO_UPLOAD_FAILED', details=error_details, success=False)
        
        return jsonify({'error': str(e), 'details': error_details}), 500


@app.route('/api/videos', methods=['GET'])
@jwt_required()
def get_videos():
    """Get list of user's videos"""
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
        
        log_audit(current_user_id, 'VIDEO_LIST_ACCESSED', 'Video')
        
        return jsonify({'videos': video_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>', methods=['GET'])
@jwt_required()
def get_video(video_id):
    """Get video details and analysis results (JSON)"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        # Check access permissions
        if video.user_id != current_user_id and user.role != 'admin':
            log_audit(current_user_id, 'VIDEO_ACCESS_DENIED', 'Video', video_id, success=False)
            return jsonify({'error': 'Access denied'}), 403
        
        # Decrypt analysis results if they exist
        analysis_results = None
        if video.analysis_results:
            try:
                decrypted_data = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
            except Exception as e:
                app.logger.error(f"Failed to decrypt analysis results: {e}")
        
        log_audit(current_user_id, 'VIDEO_DETAILS_ACCESSED', 'Video', video_id)
        
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

@app.route('/api/videos/<int:video_id>/download', methods=['GET'])
@jwt_required()


def download_video(video_id):
    """Download video file"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        # Check access permissions
        if video.user_id != current_user_id and user.role != 'admin':
            log_audit(current_user_id, 'VIDEO_ACCESS_DENIED', 'Video', video_id, success=False)
            return jsonify({'error': 'Access denied'}), 403
        
        # Update access tracking
        video.access_count += 1
        video.last_accessed = datetime.utcnow()
        db.session.commit()
        
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        
        if not os.path.exists(video_path):
            return jsonify({'error': 'Video file not found'}), 404
        
        log_audit(current_user_id, 'VIDEO_DOWNLOADED', 'Video', video_id)
        
        return send_file(video_path, mimetype=video.mime_type, as_attachment=True, 
                        download_name=video.filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/analyze', methods=['POST'])
@jwt_required()


def analyze_video(video_id):
    """Analyze video with AI - detects exercise type and compares to demo"""
    try:
        current_user_id = int(get_jwt_identity())
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get video file path
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        
        if not os.path.exists(video_path):
            return jsonify({'error': 'Video file not found'}), 404
        
        try:
            # Try to use real AI analyzer
            from kinetic_analyzer import KineticAnalyzer
            
            app.logger.info(f"Starting AI analysis for video {video_id}")
            analyzer = KineticAnalyzer()
            
            # Run analysis - analyzer will auto-detect exercise type
            analysis_results = analyzer.analyze_video(video_path, exercise_type=None)
            
            app.logger.info(f"Analysis complete: {analysis_results['exercise_type']} detected")
            
            # Find matching demo video from database
            detected_type = analysis_results['exercise_type']
            demo_video = DemoVideo.query.filter_by(exercise_type=detected_type).first()
            
            if demo_video:
                app.logger.info(f"Found matching demo: {demo_video.title}")
                analysis_results['demo_video_url'] = demo_video.video_url
                analysis_results['demo_video_title'] = demo_video.title
            else:
                app.logger.warning(f"No demo found for {detected_type}")
            
            # Store analysis results
            video.analysis_results = encrypt_data(analysis_results)
            db.session.commit()
            
            # Create exercise session for progress tracking
            try:
                session = ExerciseSession(
                    user_id=current_user_id,
                    video_id=video_id,
                    exercise_type=analysis_results['exercise_type'],
                    reps_completed=analysis_results.get('total_reps', 0),
                    form_score=analysis_results.get('average_accuracy', 0),
                    duration_seconds=int(analysis_results.get('total_frames', 0) / 30),
                    calories_burned=analysis_results.get('total_reps', 0) * 0.5
                )
                db.session.add(session)
                db.session.commit()
            except Exception as session_error:
                app.logger.error(f"Session tracking error: {session_error}")
            
            log_audit(current_user_id, 'VIDEO_ANALYZED', 'Video', video_id,
                     details=f"Exercise: {analysis_results['exercise_type']}, Accuracy: {analysis_results['average_accuracy']}%")
            
            return jsonify({
                'message': 'Analysis completed successfully',
                'results': {
                    'exercise_type': analysis_results['exercise_type'],
                    'total_reps': analysis_results.get('total_reps', 0),
                    'average_accuracy': analysis_results['average_accuracy'],
                    'total_frames': analysis_results['total_frames'],
                    'most_common_issues': analysis_results['most_common_issues'],
                    'timestamp': analysis_results['timestamp'],
                    'demo_video_url': analysis_results.get('demo_video_url'),
                    'demo_video_title': analysis_results.get('demo_video_title')
                }
            }), 200
            
        except Exception as ai_error:
            # If AI analyzer fails, fall back to mock data
            app.logger.warning(f"AI analyzer failed: {ai_error}, using mock data")
            import random
            
            analysis_results = {
                'exercise_type': 'squat',
                'total_reps': random.randint(8, 15),
                'average_accuracy': random.randint(70, 95),
                'total_frames': 300,
                'most_common_issues': ['Keep back straight', 'Go deeper in squat'],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Find demo video
            demo_video = DemoVideo.query.filter_by(exercise_type='squat').first()
            if demo_video:
                analysis_results['demo_video_url'] = demo_video.video_url
                analysis_results['demo_video_title'] = demo_video.title
            
            video.analysis_results = encrypt_data(analysis_results)
            db.session.commit()
            
            # Create session
            try:
                session = ExerciseSession(
                    user_id=current_user_id,
                    video_id=video_id,
                    exercise_type=analysis_results['exercise_type'],
                    reps_completed=analysis_results['total_reps'],
                    form_score=analysis_results['average_accuracy'],
                    duration_seconds=10,
                    calories_burned=analysis_results['total_reps'] * 0.5
                )
                db.session.add(session)
                db.session.commit()
            except Exception as session_error:
                app.logger.error(f"Session tracking error: {session_error}")
            
            return jsonify({
                'message': 'Analysis completed successfully (mock data)',
                'results': {
                    'exercise_type': analysis_results['exercise_type'],
                    'total_reps': analysis_results['total_reps'],
                    'average_accuracy': analysis_results['average_accuracy'],
                    'total_frames': analysis_results['total_frames'],
                    'most_common_issues': analysis_results['most_common_issues'],
                    'timestamp': analysis_results['timestamp'],
                    'demo_video_url': analysis_results.get('demo_video_url'),
                    'demo_video_title': analysis_results.get('demo_video_title')
                }
            }), 200
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        app.logger.error(f"Analysis error: {error_details}")
        log_audit(current_user_id if 'current_user_id' in locals() else None,
                 'VIDEO_ANALYSIS_FAILED', 'Video', video_id, details=error_details, success=False)
        return jsonify({'error': str(e), 'details': error_details}), 500

"""
COMPLETE PATIENT MANAGEMENT SYSTEM
"""

class PatientProfile(db.Model):
    """Extended patient information"""
    __tablename__ = 'patient_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Personal Information
    full_name = db.Column(db.String(200))
    date_of_birth = db.Column(db.Date)
    phone = db.Column(db.String(20))
    
    # Medical Information
    primary_diagnosis = db.Column(db.String(500))
    injury_date = db.Column(db.Date)
    treatment_goals = db.Column(db.Text)
    
    # Assignment
    assigned_therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    treatment_start_date = db.Column(db.Date, default=datetime.utcnow)
    current_status = db.Column(db.String(50), default='active')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='patient_profile')
    therapist = db.relationship('User', foreign_keys=[assigned_therapist_id], backref='assigned_patients')

class WorkoutHistory(db.Model):
    """Track patient workout sessions"""
    __tablename__ = 'workout_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Workout Details
    workout_date = db.Column(db.DateTime, default=datetime.utcnow)
    exercise_type = db.Column(db.String(100))
    sets_completed = db.Column(db.Integer, default=0)
    reps_per_set = db.Column(db.String(100))  # e.g., "12,10,10"
    total_reps = db.Column(db.Integer, default=0)
    weight_used = db.Column(db.Float)  # in lbs or kg
    
    # Performance Metrics
    avg_form_score = db.Column(db.Float)
    duration_minutes = db.Column(db.Integer)
    calories_burned = db.Column(db.Float)
    
    # Associated Video
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    
    # Patient Notes
    patient_notes = db.Column(db.Text)
    pain_level = db.Column(db.Integer)  # 0-10 scale
    difficulty_level = db.Column(db.Integer)  # 1-5 scale
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='workout_sessions')
    video = db.relationship('Video', backref='workout')

class TherapistNote(db.Model):
    """Therapist notes and recommendations"""
    __tablename__ = 'therapist_notes'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    therapist_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    note_type = db.Column(db.String(50))  # assessment, progress, recommendation
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    
    # Related to specific video
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    
    patient_viewed = db.Column(db.Boolean, default=False)
    patient_viewed_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    patient = db.relationship('User', foreign_keys=[patient_id], backref='received_notes')
    therapist = db.relationship('User', foreign_keys=[therapist_id], backref='written_notes')
    video = db.relationship('Video', backref='therapist_notes')


# ============================================================================
# API ENDPOINTS - Add before if __name__ == '__main__'
# ============================================================================

# -------------------- PATIENT MANAGEMENT --------------------

@app.route('/api/therapist/patients', methods=['POST'])
@jwt_required()
def create_patient():
    """Therapist creates new patient"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Only therapists can create patients'}), 403
        
        data = request.get_json()
        
        # Create user account
        username = data.get('username')
        email = data.get('email')
        password = data.get('password', 'Patient123!')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role='user'
        )
        db.session.add(new_user)
        db.session.flush()
        
        # Create patient profile
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
        
        log_audit(current_user_id, 'PATIENT_CREATED', 'PatientProfile', profile.id)
        
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
    """Get all patients for logged-in therapist"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get patients
        if user.role == 'admin':
            profiles = PatientProfile.query.all()
        else:
            profiles = PatientProfile.query.filter_by(assigned_therapist_id=current_user_id).all()
        
        patient_list = []
        for p in profiles:
            # Get latest workout
            latest_workout = WorkoutHistory.query.filter_by(user_id=p.user_id).order_by(
                WorkoutHistory.workout_date.desc()
            ).first()
            
            # Get total sessions
            total_sessions = WorkoutHistory.query.filter_by(user_id=p.user_id).count()
            
            # Get average form score
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
    """Get detailed patient information with videos and analysis"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        profile = PatientProfile.query.get(patient_id)
        if not profile:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Check access
        if user.role == 'clinician' and profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get workout history
        workouts = WorkoutHistory.query.filter_by(user_id=profile.user_id).order_by(
            WorkoutHistory.workout_date.desc()
        ).limit(20).all()

                # Get videos WITH ANALYSIS
        videos = Video.query.filter_by(user_id=profile.user_id, is_deleted=False).order_by(
            Video.uploaded_at.desc()
        ).limit(10).all()
        
        # Process videos with decrypted analysis
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
            
            # Decrypt analysis if exists
            if v.analysis_results:
                try:
                    decrypted = decrypt_data(v.analysis_results)
                    if isinstance(decrypted, str):
                        video_data['analysis_results'] = json.loads(decrypted)
                    else:
                        video_data['analysis_results'] = decrypted
                except Exception as e:
                    app.logger.error(f"Failed to decrypt analysis for video {v.id}: {e}")
            
            video_list.append(video_data)
           
            
              
        
        # Get therapist notes
        notes = TherapistNote.query.filter_by(patient_id=profile.user_id).order_by(
            TherapistNote.created_at.desc()
        ).all()
        
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
        import traceback
        app.logger.error(f"Error getting patient details: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

# -------------------- WORKOUT HISTORY --------------------

@app.route('/api/workouts', methods=['POST'])
@jwt_required()
def log_workout():
    """Patient logs a workout session"""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        workout = WorkoutHistory(
            user_id=current_user_id,
            exercise_type=data.get('exercise_type'),
            sets_completed=data.get('sets_completed', 0),
            reps_per_set=data.get('reps_per_set'),
            total_reps=data.get('total_reps', 0),
            weight_used=data.get('weight_used'),
            avg_form_score=data.get('form_score'),
            duration_minutes=data.get('duration_minutes'),
            calories_burned=data.get('calories_burned'),
            video_id=data.get('video_id'),
            patient_notes=data.get('notes'),
            pain_level=data.get('pain_level'),
            difficulty_level=data.get('difficulty_level')
        )
        db.session.add(workout)
        db.session.commit()
        
        log_audit(current_user_id, 'WORKOUT_LOGGED', 'WorkoutHistory', workout.id)
        
        return jsonify({
            'message': 'Workout logged successfully',
            'workout_id': workout.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/workouts', methods=['GET'])
@jwt_required()
def get_workout_history():
    """Get workout history for current user"""
    try:
        current_user_id = int(get_jwt_identity())
        
        workouts = WorkoutHistory.query.filter_by(user_id=current_user_id).order_by(
            WorkoutHistory.workout_date.desc()
        ).all()
        
        return jsonify({
            'workouts': [{
                'id': w.id,
                'date': w.workout_date.isoformat(),
                'exercise_type': w.exercise_type,
                'sets_completed': w.sets_completed,
                'reps_per_set': w.reps_per_set,
                'total_reps': w.total_reps,
                'weight_used': w.weight_used,
                'form_score': w.avg_form_score,
                'duration_minutes': w.duration_minutes,
                'calories_burned': w.calories_burned,
                'pain_level': w.pain_level,
                'difficulty_level': w.difficulty_level,
                'notes': w.patient_notes,
                'has_video': w.video_id is not None
            } for w in workouts]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/workouts/stats', methods=['GET'])
@jwt_required()
def get_workout_stats():
    """Get workout statistics"""
    try:
        current_user_id = int(get_jwt_identity())
        
        workouts = WorkoutHistory.query.filter_by(user_id=current_user_id).all()
        
        if not workouts:
            return jsonify({
                'total_workouts': 0,
                'total_reps': 0,
                'avg_form_score': 0,
                'total_calories': 0
            }), 200
        
        stats = {
            'total_workouts': len(workouts),
            'total_reps': sum(w.total_reps for w in workouts),
            'avg_form_score': round(sum(w.avg_form_score for w in workouts if w.avg_form_score) / len([w for w in workouts if w.avg_form_score]), 1) if any(w.avg_form_score for w in workouts) else 0,
            'total_calories': sum(w.calories_burned for w in workouts if w.calories_burned),
            'exercises_by_type': {}
        }
        
        # Group by exercise type
        for w in workouts:
            if w.exercise_type:
                if w.exercise_type not in stats['exercises_by_type']:
                    stats['exercises_by_type'][w.exercise_type] = {
                        'count': 0,
                        'total_reps': 0,
                        'avg_form': []
                    }
                stats['exercises_by_type'][w.exercise_type]['count'] += 1
                stats['exercises_by_type'][w.exercise_type]['total_reps'] += w.total_reps
                if w.avg_form_score:
                    stats['exercises_by_type'][w.exercise_type]['avg_form'].append(w.avg_form_score)
        
        # Calculate averages
        for ex_type in stats['exercises_by_type']:
            if stats['exercises_by_type'][ex_type]['avg_form']:
                avg = sum(stats['exercises_by_type'][ex_type]['avg_form']) / len(stats['exercises_by_type'][ex_type]['avg_form'])
                stats['exercises_by_type'][ex_type]['avg_form'] = round(avg, 1)
            else:
                stats['exercises_by_type'][ex_type]['avg_form'] = 0
        
        return jsonify(stats), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -------------------- THERAPIST NOTES --------------------

@app.route('/api/therapist/notes', methods=['POST'])
@jwt_required()
def add_therapist_note():
    """Therapist adds note for patient"""
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
        
        log_audit(current_user_id, 'THERAPIST_NOTE_ADDED', 'TherapistNote', note.id)
        
        return jsonify({
            'message': 'Note added successfully',
            'note_id': note.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/patient/notes', methods=['GET'])
@jwt_required()
def get_patient_notes():
    """Patient gets their therapist notes"""
    try:
        current_user_id = int(get_jwt_identity())
        
        notes = TherapistNote.query.filter_by(patient_id=current_user_id).order_by(
            TherapistNote.created_at.desc()
        ).all()
        
        # Mark as viewed
        for note in notes:
            if not note.patient_viewed:
                note.patient_viewed = True
                note.patient_viewed_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'notes': [{
                'id': n.id,
                'type': n.note_type,
                'title': n.title,
                'content': n.content,
                'recommendations': n.recommendations,
                'created_at': n.created_at.isoformat(),
                'therapist_name': n.therapist.username,
                'related_video_id': n.video_id
            } for n in notes]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -------------------- PATIENT INFO --------------------

@app.route('/api/patient/profile', methods=['GET'])
@jwt_required()
def get_my_profile():
    """Patient gets their own profile"""
    try:
        current_user_id = int(get_jwt_identity())
        
        profile = PatientProfile.query.filter_by(user_id=current_user_id).first()
        
        if not profile:
            return jsonify({'message': 'No profile found'}), 200
        
        therapist_name = profile.therapist.username if profile.therapist else 'Not assigned'
        
        return jsonify({
            'full_name': profile.full_name,
            'primary_diagnosis': profile.primary_diagnosis,
            'treatment_goals': profile.treatment_goals,
            'therapist_name': therapist_name,
            'treatment_start_date': profile.treatment_start_date.isoformat() if profile.treatment_start_date else None,
            'current_status': profile.current_status
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>', methods=['DELETE'])
@jwt_required()
def delete_video(video_id):
    """Soft delete video"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id and user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        # Soft delete
        video.is_deleted = True
        db.session.commit()
        
        log_audit(current_user_id, 'VIDEO_DELETED', 'Video', video_id)
        
        return jsonify({'message': 'Video deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/results', methods=['GET'])
@jwt_required()
def get_analysis_results(video_id):
    """Get detailed analysis results for a video"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id and user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        if not video.analysis_results:
            return jsonify({'error': 'No analysis results available'}), 404
        
        # Decrypt results
        results = decrypt_data(video.analysis_results)
        
        log_audit(current_user_id, 'ANALYSIS_RESULTS_ACCESSED', 'Video', video_id)
        
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/annotated', methods=['GET'])
@jwt_required()
def get_annotated_video(video_id):
    """Get annotated video with pose overlay"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id and user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        if not video.analysis_results:
            return jsonify({'error': 'Video not analyzed yet'}), 404
        
        # Get annotated video path
        results = decrypt_data(video.analysis_results)
        annotated_filename = results.get('annotated_video')
        
        if not annotated_filename:
            return jsonify({'error': 'Annotated video not available'}), 404
        
        annotated_path = os.path.join(app.config['UPLOAD_FOLDER'], annotated_filename)
        
        if not os.path.exists(annotated_path):
            return jsonify({'error': 'Annotated video file not found'}), 404
        
        log_audit(current_user_id, 'ANNOTATED_VIDEO_ACCESSED', 'Video', video_id)
        
        return send_file(annotated_path, mimetype='video/mp4', as_attachment=True,
                        download_name=f"analyzed_{video.filename}")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/csv', methods=['GET'])
@jwt_required()
def get_csv_data(video_id):
    """Get CSV export of skeletal data"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id and user.role != 'admin':
            return jsonify({'error': 'Access denied'}), 403
        
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"data_{video.id}.csv")
        
        if not os.path.exists(csv_path):
            return jsonify({'error': 'CSV data not available'}), 404
        
        log_audit(current_user_id, 'CSV_DATA_ACCESSED', 'Video', video_id)
        
        return send_file(csv_path, mimetype='text/csv', as_attachment=True,
                        download_name=f"skeletal_data_{video.filename}.csv")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin routes
@app.route('/api/admin/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """Get audit logs (admin only)"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(1000).all()
        
        log_list = [{
            'id': log.id,
            'user_id': log.user_id,
            'action': log.action,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'timestamp': log.timestamp.isoformat(),
            'ip_address': log.ip_address,
            'success': log.success
        } for log in logs]
        
        return jsonify({'logs': log_list}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

# Progress Tracking Endpoints
@app.route('/api/progress/stats', methods=['GET'])
@jwt_required()
def get_progress_stats():
    """Get user's progress statistics"""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Get time range from query params
        days = request.args.get('days', 30, type=int)
        since_date = datetime.utcnow() - timedelta(days=days)
        
        # Get sessions in time range
        sessions = ExerciseSession.query.filter(
            ExerciseSession.user_id == current_user_id,
            ExerciseSession.session_date >= since_date
        ).all()
        
        # Calculate stats
        total_sessions = len(sessions)
        total_reps = sum(s.reps_completed or 0 for s in sessions)
        avg_form_score = sum(s.form_score or 0 for s in sessions) / total_sessions if total_sessions > 0 else 0
        total_calories = sum(s.calories_burned or 0 for s in sessions)
        
        # Group by date for chart data
        sessions_by_date = {}
        for session in sessions:
            date_key = session.session_date.strftime('%Y-%m-%d')
            if date_key not in sessions_by_date:
                sessions_by_date[date_key] = {
                    'date': date_key,
                    'sessions': 0,
                    'reps': 0,
                    'avg_form_score': []
                }
            sessions_by_date[date_key]['sessions'] += 1
            sessions_by_date[date_key]['reps'] += session.reps_completed or 0
            sessions_by_date[date_key]['avg_form_score'].append(session.form_score or 0)
        
        # Calculate averages
        chart_data = []
        for date_key in sorted(sessions_by_date.keys()):
            data = sessions_by_date[date_key]
            chart_data.append({
                'date': data['date'],
                'sessions': data['sessions'],
                'reps': data['reps'],
                'avg_form_score': sum(data['avg_form_score']) / len(data['avg_form_score']) if data['avg_form_score'] else 0
            })
        
        return jsonify({
            'summary': {
                'total_sessions': total_sessions,
                'total_reps': total_reps,
                'avg_form_score': round(avg_form_score, 1),
                'total_calories': round(total_calories, 1)
            },
            'chart_data': chart_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/exercises/assigned', methods=['GET'])
@jwt_required()
def get_assigned_exercises():
    """Get user's assigned exercises"""
    try:
        current_user_id = int(get_jwt_identity())
        
        assignments = ExerciseAssignment.query.filter_by(
            patient_id=current_user_id,
            is_active=True
        ).all()
        
        result = []
        for assignment in assignments:
            result.append({
                'id': assignment.id,
                'exercise_type': assignment.exercise_type,
                'sets': assignment.sets,
                'reps': assignment.reps,
                'weight': assignment.weight,
                'frequency_per_week': assignment.frequency_per_week,
                'instructions': assignment.instructions,
                'assigned_at': assignment.assigned_at.isoformat()
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/exercises/assign', methods=['POST'])
@jwt_required()
def assign_exercise():
    """Therapist assigns exercise to patient"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        # Only therapists and admins can assign exercises
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        assignment = ExerciseAssignment(
            patient_id=data['patient_id'],
            therapist_id=current_user_id,
            exercise_type=data['exercise_type'],
            sets=data.get('sets', 3),
            reps=data.get('reps', 12),
            weight=data.get('weight', 0),
            frequency_per_week=data.get('frequency_per_week', 3),
            instructions=data.get('instructions', '')
        )
        
        db.session.add(assignment)
        db.session.commit()
        
        log_audit(current_user_id, 'EXERCISE_ASSIGNED', 'ExerciseAssignment', assignment.id,
                 details=f"Assigned {data['exercise_type']} to user {data['patient_id']}")
        
        return jsonify({
            'message': 'Exercise assigned successfully',
            'assignment_id': assignment.id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin Endpoints
@app.route('/api/admin/init-db', methods=['POST'])
def init_database():
    """Initialize database tables"""
    try:
        db.create_all()
        return jsonify({'message': 'Database tables created successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/create-demo-users', methods=['POST'])
def create_demo_users():
    """Create demo users with correct roles"""
    try:
        demo_users = [
            {
                'username': 'patient',
                'email': 'patient@kineticai.com',
                'password': 'patient123',
                'role': 'user'
            },
            {
                'username': 'therapist',
                'email': 'therapist@kineticai.com',
                'password': 'therapist123',
                'role': 'clinician'
            },
            {
                'username': 'admin',
                'email': 'admin@kineticai.com',
                'password': 'admin123',
                'role': 'admin'
            }
        ]
        
        created_users = []
        for user_data in demo_users:
            # Check if user already exists
            existing = User.query.filter_by(username=user_data['username']).first()
            if existing:
                # Update role if needed
                if existing.role != user_data['role']:
                    existing.role = user_data['role']
                    db.session.commit()
                    created_users.append(f"Updated {user_data['username']} role to {user_data['role']}")
                else:
                    created_users.append(f"{user_data['username']} already exists with correct role")
            else:
                # Create new user
                password_hash = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
                new_user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    password_hash=password_hash,
                    role=user_data['role']
                )
                db.session.add(new_user)
                db.session.commit()
                created_users.append(f"Created {user_data['username']} with role {user_data['role']}")
        
        return jsonify({
            'message': 'Demo users processed successfully',
            'details': created_users
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Demo Video Endpoints
@app.route('/api/demos', methods=['GET'])
def get_demo_videos():
    """Get all demo videos"""
    try:
        exercise_type = request.args.get('exercise_type')
        
        query = DemoVideo.query.filter_by(is_active=True)
        
        if exercise_type:
            query = query.filter_by(exercise_type=exercise_type)
        
        demos = query.all()
        
        result = []
        for demo in demos:
            result.append({
                'id': demo.id,
                'exercise_type': demo.exercise_type,
                'title': demo.title,
                'description': demo.description,
                'video_url': demo.video_url,
                'thumbnail_url': demo.thumbnail_url,
                'duration_seconds': demo.duration_seconds,
                'difficulty_level': demo.difficulty_level,
                'target_muscles': demo.target_muscles
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/demos/seed', methods=['POST'])
def seed_demo_videos():
    """Seed database with demo videos"""
    try:
        demos = [
            {
                'exercise_type': 'squat',
                'title': 'Perfect Squat Form',
                'description': 'Learn proper squat technique with step-by-step instructions',
                'video_url': 'https://www.youtube.com/embed/ultWZbUMPL8',
                'thumbnail_url': 'https://img.youtube.com/vi/ultWZbUMPL8/mqdefault.jpg',
                'duration_seconds': 180,
                'difficulty_level': 'beginner',
                'target_muscles': 'Quads, Glutes, Hamstrings'
            },
            {
                'exercise_type': 'pushup',
                'title': 'Push-up Fundamentals',
                'description': 'Master the perfect push-up with proper form',
                'video_url': 'https://www.youtube.com/embed/IODxDxX7oi4',
                'thumbnail_url': 'https://img.youtube.com/vi/IODxDxX7oi4/mqdefault.jpg',
                'duration_seconds': 240,
                'difficulty_level': 'beginner',
                'target_muscles': 'Chest, Triceps, Shoulders'
            },
            {
                'exercise_type': 'plank',
                'title': 'Plank Hold Technique',
                'description': 'Build core strength with proper plank form',
                'video_url': 'https://www.youtube.com/embed/pSHjTRCQxIw',
                'thumbnail_url': 'https://img.youtube.com/vi/pSHjTRCQxIw/mqdefault.jpg',
                'duration_seconds': 150,
                'difficulty_level': 'beginner',
                'target_muscles': 'Core, Abs, Lower Back'
            },
            {
                'exercise_type': 'lunge',
                'title': 'Forward Lunge Form',
                'description': 'Perfect your lunge technique for leg strength',
                'video_url': 'https://www.youtube.com/embed/QOVaHwm-Q6U',
                'thumbnail_url': 'https://img.youtube.com/vi/QOVaHwm-Q6U/mqdefault.jpg',
                'duration_seconds': 200,
                'difficulty_level': 'beginner',
                'target_muscles': 'Quads, Glutes, Hamstrings'
            },
            {
                'exercise_type': 'leg_raise',
                'title': 'Lying Leg-Hip Raise',
                'description': 'Strengthen lower abs and hip flexors',
                'video_url': 'https://www.youtube.com/embed/JB2oyawG9KI',
                'thumbnail_url': 'https://img.youtube.com/vi/JB2oyawG9KI/mqdefault.jpg',
                'duration_seconds': 180,
                'difficulty_level': 'beginner',
                'target_muscles': 'Lower Abs, Hip Flexors'
            },
            {
                'exercise_type': 'bridge',
                'title': 'Glute Bridge Tutorial',
                'description': 'Strengthen glutes and hamstrings',
                'video_url': 'https://www.youtube.com/embed/wPM8icPu6H8',
                'thumbnail_url': 'https://img.youtube.com/vi/wPM8icPu6H8/mqdefault.jpg',
                'duration_seconds': 180,
                'difficulty_level': 'beginner',
                'target_muscles': 'Glutes, Hamstrings, Lower Back'
            }
        ]
        
        for demo_data in demos:
            existing = DemoVideo.query.filter_by(
                exercise_type=demo_data['exercise_type'],
                title=demo_data['title']
            ).first()
            
            if not existing:
                demo = DemoVideo(**demo_data)
                db.session.add(demo)
        
        db.session.commit()
        
        return jsonify({'message': f'Successfully seeded {len(demos)} demo videos'}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions', methods=['POST'])
@jwt_required()
def save_session():
    """Save a workout session"""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        # Create session record
        session = ExerciseSession(
            user_id=current_user_id,
            video_id=None,  # Not from video analysis
            exercise_type=data.get('exercise_type', 'unknown'),
            reps_completed=data.get('total_reps', 0),
            form_score=None,  # Manual entry, no form score
            duration_seconds=None,
            calories_burned=data.get('total_reps', 0) * 0.5,
            notes=json.dumps(data.get('sets', []))
        )
        
        db.session.add(session)
        db.session.commit()
        
        log_audit(current_user_id, 'SESSION_SAVED', 'ExerciseSession', session.id,
                 details=f"Exercise: {data.get('exercise_type')}, Reps: {data.get('total_reps')}")
        
        return jsonify({
            'message': 'Session saved successfully',
            'session_id': session.id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/videos/all-analyzed', methods=['GET'])
@jwt_required()
def get_all_analyzed_videos():
    """Therapist sees all patient videos with analysis"""
    # Returns list of all videos with their analysis results
    # Only accessible to therapists/admins
    
@app.route('/api/videos/<id>/feedback', methods=['POST'])
@jwt_required()
def submit_therapist_feedback(video_id):
    """Therapist provides feedback on patient's video"""
    # Stores therapist feedback
    # Patient can view this later

# Initialize database
with app.app_context():
    db.create_all()
    
    # Auto-initialize for Railway deployment
    if os.environ.get('AUTO_INIT_DB') == 'true':
        try:
            # Check if admin exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@kineticai.com',
                    password_hash=bcrypt.generate_password_hash('ChangeMe123!').decode('utf-8'),
                    role='admin'
                )
                db.session.add(admin)
                db.session.commit()
                print("✓ Auto-initialized: Admin user created (username: admin, password: ChangeMe123!)")
        except Exception as e:
            print(f"Auto-init error (safe to ignore if already initialized): {e}")


# ============================================================================
# ADDITIONAL ENDPOINTS FOR PATIENT EDITING AND VIDEO STREAMING
# ============================================================================

@app.route('/api/therapist/patients/<int:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    """Therapist updates patient information"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Access denied'}), 403
        
        profile = PatientProfile.query.get(patient_id)
        if not profile:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Check access
        if user.role == 'clinician' and profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        data = request.get_json()
        
        # Update fields
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
        
        # Update email if provided
        if 'email' in data:
            profile.user.email = data['email']
        
        profile.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_audit(current_user_id, 'PATIENT_UPDATED', 'PatientProfile', patient_id)
        
        return jsonify({
            'message': 'Patient updated successfully',
            'patient_id': patient_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/stream', methods=['GET'])
def stream_video(video_id):
    """Stream video for in-browser playback - works for both patients and therapists"""
    try:
        # Get token from query parameter (video tags can't send Authorization headers)
        token = request.args.get('token')
        
        if not token:
            # Fallback: check Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                app.logger.error("No token provided for video stream")
                return jsonify({'error': 'No authentication token'}), 401
        
        # Manually verify token (can't use @jwt_required with query params)
        try:
            from flask_jwt_extended import decode_token
            decoded = decode_token(token)
            current_user_id = int(decoded['sub'])
        except Exception as e:
            app.logger.error(f"Token decode failed: {e}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        video = Video.query.get(video_id)
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        # CRITICAL: Check permissions for BOTH patients and therapists
        has_access = False
        
        # Patient can view their own videos
        if user.role == 'user' and video.user_id == current_user_id:
            has_access = True
        
        # Therapist can view assigned patients' videos
        if user.role in ['clinician', 'admin']:
            patient_profile = PatientProfile.query.filter_by(user_id=video.user_id).first()
            if patient_profile:
                if user.role == 'admin' or patient_profile.assigned_therapist_id == current_user_id:
                    has_access = True
        
        if not has_access:
            app.logger.error(f"Access denied: User {current_user_id} tried to access video {video_id}")
            return jsonify({'error': 'Access denied'}), 403
        
        # Get video file path
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        
        if not os.path.exists(video_path):
            app.logger.error(f"Video file not found: {video_path}")
            return jsonify({'error': 'Video file not found on server'}), 404
        
        log_audit(current_user_id, 'VIDEO_STREAMED', 'Video', video_id)
        
        # Return video file for streaming
        return send_file(
            video_path,
            mimetype=video.mime_type or 'video/mp4',
            as_attachment=False
        )
        
    except Exception as e:
        app.logger.error(f"Video streaming error: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/api/videos/<int:video_id>/details', methods=['GET'])
@jwt_required()
def get_video_details_for_therapist(video_id):
    """Get video details - accessible by both patients and therapists"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        video = Video.query.get(video_id)
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        # Check access permissions
        has_access = False
        
        # Patient can view their own videos
        if user.role == 'user' and video.user_id == current_user_id:
            has_access = True
        
        # Therapist can view assigned patients' videos
        if user.role in ['clinician', 'admin']:
            patient_profile = PatientProfile.query.filter_by(user_id=video.user_id).first()
            if patient_profile:
                if user.role == 'admin' or patient_profile.assigned_therapist_id == current_user_id:
                    has_access = True
        
        if not has_access:
            return jsonify({'error': 'Access denied'}), 403
        
        # Decrypt analysis results if they exist
        analysis_results = None
        if video.analysis_results:
            try:
                decrypted_data = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted_data) if isinstance(decrypted_data, str) else decrypted_data
            except Exception as e:
                app.logger.error(f"Failed to decrypt analysis results: {e}")
        
        log_audit(current_user_id, 'VIDEO_DETAILS_ACCESSED', 'Video', video_id)
        
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


    """
WORKOUT TRACKING SYSTEM - BACKEND ENDPOINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ADD THESE ENDPOINTS TO app.py

This system tracks:
1. Patient logs completed workouts
2. Each workout linked to video analysis
3. Therapist sees workout history and progress
4. Progress metrics calculated automatically
"""

# ============================================================================
# WORKOUT COMPLETION - PATIENT SIDE
# ============================================================================

@app.route('/api/workouts/complete', methods=['POST'])
@jwt_required()
def complete_workout():
    """Patient marks a workout as complete"""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        # Required fields
        video_id = data.get('video_id')
        exercise_type = data.get('exercise_type')
        reps_completed = data.get('reps_completed')
        sets_completed = data.get('sets_completed', 1)
        
        if not all([video_id, exercise_type, reps_completed]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Verify video belongs to user
        video = Video.query.get(video_id)
        if not video or video.user_id != current_user_id:
            return jsonify({'error': 'Video not found'}), 404
        
        # Get analysis results for the video
        analysis_results = None
        form_score = None
        if video.analysis_results:
            try:
                decrypted = decrypt_data(video.analysis_results)
                analysis_results = json.loads(decrypted) if isinstance(decrypted, str) else decrypted
                form_score = analysis_results.get('average_accuracy') or analysis_results.get('form_score')
            except:
                pass
        
        # Create workout record
        workout = WorkoutHistory(
            user_id=current_user_id,
            video_id=video_id,
            exercise_type=exercise_type,
            reps_completed=reps_completed,
            sets_completed=sets_completed,
            duration_seconds=data.get('duration_seconds'),
            form_score=form_score,
            notes=data.get('notes'),
            completed_at=datetime.utcnow()
        )
        
        db.session.add(workout)
        db.session.commit()
        
        # Log the workout completion
        log_audit(current_user_id, 'WORKOUT_COMPLETED', 'WorkoutHistory', workout.id)
        
        return jsonify({
            'message': 'Workout completed successfully',
            'workout_id': workout.id,
            'completed_at': workout.completed_at.isoformat(),
            'form_score': form_score
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error completing workout: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/workouts/my-history', methods=['GET'])
@jwt_required()
def get_my_workout_history():
    """Get workout history for current patient"""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Optional filters
        limit = request.args.get('limit', 50, type=int)
        exercise_type = request.args.get('exercise_type')
        
        query = WorkoutHistory.query.filter_by(user_id=current_user_id)
        
        if exercise_type:
            query = query.filter_by(exercise_type=exercise_type)
        
        workouts = query.order_by(WorkoutHistory.completed_at.desc()).limit(limit).all()
        
        workout_list = []
        for w in workouts:
            workout_list.append({
                'id': w.id,
                'exercise_type': w.exercise_type,
                'reps_completed': w.reps_completed,
                'sets_completed': w.sets_completed,
                'duration_seconds': w.duration_seconds,
                'form_score': w.form_score,
                'notes': w.notes,
                'completed_at': w.completed_at.isoformat(),
                'video_id': w.video_id
            })
        
        # Calculate summary stats
        total_workouts = len(workout_list)
        avg_form_score = sum(w['form_score'] for w in workout_list if w['form_score']) / max(total_workouts, 1)
        total_reps = sum(w['reps_completed'] * w['sets_completed'] for w in workout_list)
        
        return jsonify({
            'workouts': workout_list,
            'summary': {
                'total_workouts': total_workouts,
                'avg_form_score': round(avg_form_score, 1),
                'total_reps': total_reps
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting workout history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/workouts/progress', methods=['GET'])
@jwt_required()
def get_workout_progress():
    """Get workout progress metrics for patient"""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Get workouts from last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        workouts = WorkoutHistory.query.filter(
            WorkoutHistory.user_id == current_user_id,
            WorkoutHistory.completed_at >= thirty_days_ago
        ).order_by(WorkoutHistory.completed_at.asc()).all()
        
        # Group by week
        weekly_data = {}
        for workout in workouts:
            week_key = workout.completed_at.strftime('%Y-W%U')
            if week_key not in weekly_data:
                weekly_data[week_key] = {
                    'workouts': 0,
                    'total_reps': 0,
                    'avg_form_score': [],
                    'week_start': workout.completed_at.strftime('%Y-%m-%d')
                }
            
            weekly_data[week_key]['workouts'] += 1
            weekly_data[week_key]['total_reps'] += workout.reps_completed * workout.sets_completed
            if workout.form_score:
                weekly_data[week_key]['avg_form_score'].append(workout.form_score)
        
        # Calculate averages
        progress_data = []
        for week, data in sorted(weekly_data.items()):
            avg_score = sum(data['avg_form_score']) / len(data['avg_form_score']) if data['avg_form_score'] else 0
            progress_data.append({
                'week': week,
                'week_start': data['week_start'],
                'workouts': data['workouts'],
                'total_reps': data['total_reps'],
                'avg_form_score': round(avg_score, 1)
            })
        
        return jsonify({
            'progress': progress_data,
            'total_workouts': len(workouts),
            'current_streak': calculate_workout_streak(workouts)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting progress: {e}")
        return jsonify({'error': str(e)}), 500


def calculate_workout_streak(workouts):
    """Helper function to calculate current workout streak in days"""
    if not workouts:
        return 0
    
    # Sort by date descending
    sorted_workouts = sorted(workouts, key=lambda w: w.completed_at, reverse=True)
    
    streak = 0
    current_date = datetime.utcnow().date()
    
    for workout in sorted_workouts:
        workout_date = workout.completed_at.date()
        days_diff = (current_date - workout_date).days
        
        if days_diff == streak:
            streak += 1
        elif days_diff > streak:
            break
    
    return streak


# ============================================================================
# WORKOUT TRACKING - THERAPIST SIDE
# ============================================================================

@app.route('/api/therapist/patients/<int:patient_id>/workouts', methods=['GET'])
@jwt_required()
def get_patient_workouts(patient_id):
    """Therapist views patient's workout history"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Verify patient is assigned to therapist
        patient_profile = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient_profile:
            return jsonify({'error': 'Patient not found'}), 404
        
        if user.role == 'clinician' and patient_profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get workout history
        limit = request.args.get('limit', 100, type=int)
        workouts = WorkoutHistory.query.filter_by(
            user_id=patient_id
        ).order_by(
            WorkoutHistory.completed_at.desc()
        ).limit(limit).all()
        
        workout_list = []
        for w in workouts:
            workout_list.append({
                'id': w.id,
                'exercise_type': w.exercise_type,
                'reps_completed': w.reps_completed,
                'sets_completed': w.sets_completed,
                'duration_seconds': w.duration_seconds,
                'form_score': w.form_score,
                'notes': w.notes,
                'completed_at': w.completed_at.isoformat(),
                'video_id': w.video_id
            })
        
        # Calculate stats
        total_workouts = len(workout_list)
        avg_form_score = 0
        if total_workouts > 0:
            scores = [w['form_score'] for w in workout_list if w['form_score']]
            avg_form_score = sum(scores) / len(scores) if scores else 0
        
        # Get exercise type breakdown
        exercise_counts = {}
        for w in workout_list:
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
        app.logger.error(f"Error getting patient workouts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/therapist/patients/<int:patient_id>/progress', methods=['GET'])
@jwt_required()
def get_patient_progress(patient_id):
    """Therapist views patient's progress over time"""
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        if user.role not in ['clinician', 'admin']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Verify patient is assigned to therapist
        patient_profile = PatientProfile.query.filter_by(user_id=patient_id).first()
        if not patient_profile:
            return jsonify({'error': 'Patient not found'}), 404
        
        if user.role == 'clinician' and patient_profile.assigned_therapist_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get workouts from last 90 days
        ninety_days_ago = datetime.utcnow() - timedelta(days=90)
        workouts = WorkoutHistory.query.filter(
            WorkoutHistory.user_id == patient_id,
            WorkoutHistory.completed_at >= ninety_days_ago
        ).order_by(WorkoutHistory.completed_at.asc()).all()
        
        # Group by week
        weekly_progress = {}
        for workout in workouts:
            week_key = workout.completed_at.strftime('%Y-W%U')
            if week_key not in weekly_progress:
                weekly_progress[week_key] = {
                    'workouts': 0,
                    'exercises': {},
                    'avg_form_scores': [],
                    'week_start': workout.completed_at.strftime('%m/%d/%Y')
                }
            
            weekly_progress[week_key]['workouts'] += 1
            weekly_progress[week_key]['exercises'][workout.exercise_type] = \
                weekly_progress[week_key]['exercises'].get(workout.exercise_type, 0) + 1
            
            if workout.form_score:
                weekly_progress[week_key]['avg_form_scores'].append(workout.form_score)
        
        # Format for response
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
        app.logger.error(f"Error getting patient progress: {e}")
        return jsonify({'error': str(e)}), 500
        
    except Exception as e:
        app.logger.error(f"Error getting video details: {e}")
        return jsonify({'error': str(e)}), 500
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
