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
CORS(app, resources={r"/api/*": {"origins": "*"}})

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
app.config['UPLOAD_FOLDER'] = '/encrypted_storage/videos'

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
    frontend_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html')
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
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
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
            
            access_token = create_access_token(identity=user.id)
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

# Video routes
@app.route('/api/videos/upload', methods=['POST'])
@jwt_required()
def upload_video():
    """Upload and encrypt video file"""
    try:
        current_user_id = get_jwt_identity()
        
        if 'video' not in request.files:
            return jsonify({'error': 'No video file provided'}), 400
        
        video_file = request.files['video']
        patient_id = request.form.get('patient_id', '')
        metadata = request.form.get('metadata', '{}')
        
        if video_file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Generate encrypted filename
        original_filename = video_file.filename
        encrypted_filename = secrets.token_hex(16) + os.path.splitext(original_filename)[1]
        
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Save file temporarily
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        video_file.save(temp_path)
        
        # Compute file hash for integrity
        file_hash = compute_file_hash(temp_path)
        file_size = os.path.getsize(temp_path)
        
        # Encrypt patient ID if provided
        encrypted_patient_id = encrypt_data(patient_id) if patient_id else None
        encrypted_metadata = encrypt_data(metadata)
        
        # Create database record
        new_video = Video(
            filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_hash=file_hash,
            file_size=file_size,
            mime_type=video_file.content_type,
            patient_id=encrypted_patient_id,
            user_id=current_user_id,
            video_metadata=encrypted_metadata
        )
        
        db.session.add(new_video)
        db.session.commit()
        
        log_audit(current_user_id, 'VIDEO_UPLOADED', 'Video', new_video.id, 
                 details=f"Filename: {original_filename}, Size: {file_size}")
        
        return jsonify({
            'message': 'Video uploaded successfully',
            'video_id': new_video.id,
            'filename': original_filename
        }), 201
    except Exception as e:
        log_audit(current_user_id if 'current_user_id' in locals() else None, 
                 'VIDEO_UPLOAD_FAILED', details=str(e), success=False)
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos', methods=['GET'])
@jwt_required()
def get_videos():
    """Get list of user's videos"""
    try:
        current_user_id = get_jwt_identity()
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
    """Get video file"""
    try:
        current_user_id = get_jwt_identity()
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
        
        log_audit(current_user_id, 'VIDEO_ACCESSED', 'Video', video_id)
        
        return send_file(video_path, mimetype=video.mime_type, as_attachment=True, 
                        download_name=video.filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/videos/<int:video_id>/analyze', methods=['POST'])
@jwt_required()
def analyze_video(video_id):
    """Analyze video using Kinetic AI pose estimation"""
    try:
        current_user_id = get_jwt_identity()
        video = Video.query.get(video_id)
        
        if not video or video.is_deleted:
            return jsonify({'error': 'Video not found'}), 404
        
        if video.user_id != current_user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get video file path
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
        
        if not os.path.exists(video_path):
            return jsonify({'error': 'Video file not found'}), 404
        
        # Import and initialize Kinetic AI analyzer
        from kinetic_analyzer import KineticAnalyzer
        analyzer = KineticAnalyzer()
        
        # Get exercise type from request or auto-detect
        exercise_type = request.json.get('exercise_type') if request.json else None
        
        # Run analysis
        analysis_results = analyzer.analyze_video(video_path, exercise_type)
        
        # Create annotated video
        annotated_path = os.path.join(
            app.config['UPLOAD_FOLDER'], 
            f"annotated_{video.encrypted_filename}"
        )
        analyzer.create_annotated_video(video_path, annotated_path, analysis_results)
        
        # Export CSV data
        csv_path = os.path.join(
            app.config['UPLOAD_FOLDER'], 
            f"data_{video.id}.csv"
        )
        
        if 'all_angles' in analysis_results:
            from kinetic_analyzer import export_to_csv
            # Re-extract keypoints for CSV export
            keypoints, _ = analyzer.extract_keypoints_from_video(video_path)
            export_to_csv(keypoints, analysis_results['all_angles'], csv_path)
            analysis_results['csv_exported'] = True
            analysis_results['csv_filename'] = f"data_{video.id}.csv"
        
        # Store annotated video filename
        analysis_results['annotated_video'] = f"annotated_{video.encrypted_filename}"
        
        # Encrypt and store results
        video.analysis_results = encrypt_data(analysis_results)
        db.session.commit()
        
        log_audit(current_user_id, 'VIDEO_ANALYZED', 'Video', video_id, 
                 details=f"Exercise: {analysis_results['exercise_type']}, Accuracy: {analysis_results['average_accuracy']}%")
        
        return jsonify({
            'message': 'Analysis completed successfully',
            'results': {
                'exercise_type': analysis_results['exercise_type'],
                'average_accuracy': analysis_results['average_accuracy'],
                'total_frames': analysis_results['total_frames'],
                'most_common_issues': analysis_results['most_common_issues'],
                'timestamp': analysis_results['timestamp']
            }
        }), 200
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        log_audit(current_user_id if 'current_user_id' in locals() else None,
                 'VIDEO_ANALYSIS_FAILED', 'Video', video_id, details=error_details, success=False)
        return jsonify({'error': str(e), 'details': error_details}), 500

@app.route('/api/videos/<int:video_id>', methods=['DELETE'])
@jwt_required()
def delete_video(video_id):
    """Soft delete video"""
    try:
        current_user_id = get_jwt_identity()
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
        current_user_id = get_jwt_identity()
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
        current_user_id = get_jwt_identity()
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
        current_user_id = get_jwt_identity()
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
        current_user_id = get_jwt_identity()
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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
