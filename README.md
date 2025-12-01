# Kinetic AI - HIPAA-Compliant Video Analysis Platform

<div align="center">

🏃 **AI-Powered Exercise Form Analysis**  
🔒 **HIPAA-Compliant Medical Video Platform**  
🎯 **YOLOv8 Pose Estimation**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

</div>

## 🎯 Overview

Kinetic AI is a production-ready, HIPAA-compliant web application for uploading, analyzing, and managing exercise videos using advanced AI pose estimation. Built for student projects and medical applications, it provides:

- **🤖 AI-Powered Analysis**: YOLOv8 pose estimation for real-time form feedback
- **🔐 HIPAA Compliance**: End-to-end encryption, audit logs, access controls
- **📊 Detailed Analytics**: Exercise type detection, form accuracy, joint angle analysis
- **💾 Data Export**: CSV export of skeletal data for research
- **🎬 Annotated Videos**: Downloadable videos with pose overlay
- **☁️ Cloud-Ready**: Deploy to Railway, Render, AWS, or GCP in minutes

## ✨ Features

### AI Analysis Engine
- Exercise type auto-detection (squat, pushup, plank, lunge)
- Real-time pose estimation with 17 body keypoints
- Form accuracy scoring (0-100%)
- Common issue detection (shallow squat, back rounding, etc.)
- Joint angle calculations for all major joints
- Frame-by-frame analysis

### Security & Compliance
- AES-256 encryption for stored videos
- Encrypted patient identifiers
- Comprehensive audit logging (7-year retention)
- Role-based access control (Admin, Clinician, User)
- JWT authentication with session timeout
- CORS protection and input validation
- Soft delete (HIPAA retention compliance)

### Data Export
- Annotated videos with pose skeleton overlay
- CSV export with all 17 keypoints per frame
- Joint angle data (elbow, knee, hip, shoulder)
- Analysis results in JSON format
- Progress tracking over time

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+ (for local development)
- 4GB+ RAM (for YOLOv8 model)

### Option 1: One-Line Setup (Recommended)

```bash
git clone <your-repo-url>
cd video_webapp
chmod +x setup.sh
./setup.sh
```

This will:
1. ✅ Generate secure encryption keys
2. ✅ Create data directories
3. ✅ Build Docker containers
4. ✅ Initialize database
5. ✅ Create admin user
6. ✅ Start all services

Access at: **http://localhost**

### Option 2: Manual Setup

```bash
# 1. Clone repository
git clone <your-repo-url>
cd video_webapp

# 2. Configure environment
cp .env.template .env

# 3. Generate secure keys
python3 << 'EOF'
import secrets
from cryptography.fernet import Fernet
print(f"SECRET_KEY={secrets.token_hex(32)}")
print(f"JWT_SECRET_KEY={secrets.token_hex(32)}")
print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")
EOF

# Add these to .env file

# 4. Create directories
mkdir -p data/{postgres,videos,logs}
chmod 700 data/videos

# 5. Start services
docker-compose up -d

# 6. Initialize database
docker-compose exec backend python << 'EOF'
from app import app, db
with app.app_context():
    db.create_all()
    print("✓ Database initialized!")
EOF
```

## 📖 Usage Guide

### 1. Register/Login
- Navigate to http://localhost
- Create account or use default admin:
  - Username: `admin`
  - Password: `Admin123!` (⚠️ change this!)

### 2. Upload Video
- Click upload area or drag & drop
- Add optional patient ID (encrypted)
- Add metadata (JSON format)
- Click "Upload & Encrypt"

### 3. Analyze Video
- Click "🔍 Analyze" on any video
- Wait for analysis (1-3 minutes depending on video length)
- View results when complete

### 4. View Results
- **📊 Results**: View detailed analysis
  - Exercise type detected
  - Overall accuracy percentage
  - Common form issues
  - Frame-by-frame data
  
- **🎬 Analyzed**: Download annotated video
  - Pose skeleton overlay
  - Real-time accuracy display
  
- **📄 CSV**: Download skeletal data
  - All 17 keypoints per frame
  - Joint angles (elbow, knee, hip, shoulder)
  - Timestamps and frame numbers

### 5. Export Data
All analysis data is exportable for research or progress tracking.

## 🏗️ Architecture

```
┌─────────────────┐
│   Frontend      │  HTML/CSS/JS
│   (Nginx)       │  User Interface
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐
│   Backend API   │  Flask + Python
│   (Gunicorn)    │  JWT Auth
└────────┬────────┘
         │
         ├─────────────┐
         │             │
         ▼             ▼
┌─────────────┐  ┌──────────────┐
│  PostgreSQL │  │  YOLOv8      │
│  Database   │  │  Analyzer    │
│  (Encrypted)│  │  (GPU Ready) │
└─────────────┘  └──────────────┘
         │
         ▼
┌─────────────────┐
│ Encrypted Files │
│ /videos/        │
└─────────────────┘
```

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Create new user
- `POST /api/auth/login` - Login (returns JWT)

### Videos
- `POST /api/videos/upload` - Upload encrypted video
- `GET /api/videos` - List user's videos
- `GET /api/videos/<id>` - Download original video
- `POST /api/videos/<id>/analyze` - Analyze video
- `GET /api/videos/<id>/results` - Get analysis results
- `GET /api/videos/<id>/annotated` - Download annotated video
- `GET /api/videos/<id>/csv` - Download skeletal data CSV
- `DELETE /api/videos/<id>` - Delete video (soft delete)

### Admin
- `GET /api/admin/audit-logs` - View audit logs

### Health
- `GET /api/health` - Health check

## 📊 Analysis Output

### Exercise Detection
Automatically detects:
- Squats
- Push-ups
- Planks
- Lunges

### Form Issues Detected
- Shallow squat (knees not bent enough)
- Deep squat (too low)
- Back rounding
- Shallow push-up
- Hips sagging (plank)
- Hips too high (plank)

### Joint Angles Calculated
- Left/Right Elbow (shoulder-elbow-wrist)
- Left/Right Knee (hip-knee-ankle)
- Left/Right Hip (shoulder-hip-knee)
- Left/Right Shoulder (hip-shoulder-elbow)

## 🌐 Deploy to Production

### Railway.app (Recommended for Students) - FREE

```bash
# 1. Push to GitHub
git init
git add .
git commit -m "Initial commit"
git push origin main

# 2. Deploy to Railway
# Go to https://railway.app
# Click "New Project" → "Deploy from GitHub"
# Select repository
# Railway auto-deploys!

# 3. Add PostgreSQL
# In Railway: New → Database → PostgreSQL

# 4. Set environment variables in Railway dashboard
```

**Cost**: FREE ($5 credit/month - enough for student projects)

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for detailed deployment guides for:
- Railway.app (recommended)
- Render.com
- Google Cloud Run
- AWS Elastic Beanstalk
- Heroku

## 🔒 HIPAA Compliance

### 1. **Data Encryption**
- **At Rest**: All video files and sensitive data encrypted using Fernet (AES-128)
- **In Transit**: SSL/TLS encryption for all communications
- **Database**: Encrypted patient identifiers and metadata
- **File Storage**: Videos stored with encrypted filenames

### 2. **Access Controls**
- Role-based access control (Admin, Clinician, User)
- JWT-based authentication with token expiration
- Password hashing using bcrypt
- Multi-factor authentication support (configurable)
- Session timeout enforcement

### 3. **Audit Logging**
- Complete audit trail of all system access and actions
- Logs include: user ID, action, timestamp, IP address, resource accessed
- Tamper-proof logging with rotation
- 7-year retention as per HIPAA requirements

### 4. **Data Integrity**
- SHA-256 file hashing for integrity verification
- Soft delete implementation (no permanent data loss)
- Version control for analysis results

### 5. **Security Features**
- SQL injection prevention via ORM
- XSS protection
- CORS configuration
- Rate limiting (configurable)
- Secure password policies

## Architecture

```
┌─────────────────┐
│   Frontend      │  (Nginx + HTML/JS)
│   (Port 80/443) │
└────────┬────────┘
         │
         │ HTTPS
         │
┌────────▼────────┐
│   Backend API   │  (Flask + JWT)
│   (Port 5000)   │
└────────┬────────┘
         │
         │ Encrypted
         │
┌────────▼────────┐     ┌──────────────┐
│   PostgreSQL    │     │   Encrypted  │
│   Database      │     │   File Store │
└─────────────────┘     └──────────────┘
```

## Installation & Setup

### Prerequisites
- Docker & Docker Compose
- Python 3.9+
- PostgreSQL 15+
- SSL certificates (for production)

### Quick Start

1. **Clone and Configure**
```bash
cd video_webapp
cp .env.template .env
# Edit .env with your secure values
```

2. **Generate Encryption Keys**
```bash
# Generate SECRET_KEY and JWT_SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate ENCRYPTION_KEY (Fernet)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

3. **Create Data Directories**
```bash
mkdir -p data/{postgres,videos,logs}
chmod 700 data/videos  # Restrict access
```

4. **Start Services**
```bash
docker-compose up -d
```

5. **Initialize Database**
```bash
docker-compose exec backend python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

6. **Access Application**
- Frontend: http://localhost (or https://localhost with SSL)
- Backend API: http://localhost:5000

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login (returns JWT)

### Videos
- `POST /api/videos/upload` - Upload encrypted video
- `GET /api/videos` - List user's videos
- `GET /api/videos/<id>` - Download specific video
- `POST /api/videos/<id>/analyze` - Analyze video
- `DELETE /api/videos/<id>` - Soft delete video

### Admin
- `GET /api/admin/audit-logs` - View audit logs (admin only)

### Health
- `GET /api/health` - Health check endpoint

## Integration with Your Colab Code

To integrate your video analysis code from Colab:

1. **Locate the analyze_video function** in `backend/app.py`
2. **Replace the placeholder** with your analysis logic:

```python
@app.route('/api/videos/<int:video_id>/analyze', methods=['POST'])
@jwt_required()
def analyze_video(video_id):
    current_user_id = get_jwt_identity()
    video = Video.query.get(video_id)
    
    # Get video file path
    video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.encrypted_filename)
    
    # YOUR COLAB ANALYSIS CODE HERE
    # Example:
    # import cv2
    # cap = cv2.VideoCapture(video_path)
    # results = your_analysis_function(cap)
    
    analysis_results = {
        'status': 'completed',
        'timestamp': datetime.utcnow().isoformat(),
        'results': your_analysis_results  # Your results here
    }
    
    # Encrypt and store
    video.analysis_results = encrypt_data(analysis_results)
    db.session.commit()
    
    return jsonify({'message': 'Analysis completed', 'results': analysis_results}), 200
```

## HIPAA Compliance Checklist

### Technical Safeguards ✅
- [x] Encryption at rest
- [x] Encryption in transit (SSL/TLS)
- [x] Access controls and authentication
- [x] Audit logging
- [x] Automatic logoff (session timeout)
- [x] Data integrity controls

### Administrative Safeguards 📋
- [ ] Security officer designation
- [ ] Workforce training
- [ ] Risk assessment documentation
- [ ] Incident response plan
- [ ] Business associate agreements

### Physical Safeguards 🏢
- [ ] Secure server location
- [ ] Access logs for physical access
- [ ] Workstation security
- [ ] Device and media controls

## Production Deployment Recommendations

### 1. SSL/TLS Configuration
```bash
# Generate SSL certificate (or use Let's Encrypt)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem
```

### 2. Database Encryption
- Enable PostgreSQL SSL connections
- Use encrypted volumes for database storage
- Implement database-level encryption

### 3. Network Security
- Use VPN for administrative access
- Implement firewall rules
- Use private networks for backend services
- Enable DDoS protection

### 4. Backup Strategy
```bash
# Automated daily backups
0 2 * * * docker-compose exec -T postgres pg_dump -U hipaa_user video_hipaa_db > backup_$(date +\%Y\%m\%d).sql
```

### 5. Monitoring
- Set up log aggregation (ELK stack, Splunk)
- Configure alerts for suspicious activity
- Monitor failed login attempts
- Track system performance

### 6. Access Reviews
- Quarterly access reviews
- Audit log analysis
- User activity monitoring

## Security Best Practices

1. **Strong Passwords**: Minimum 12 characters, complexity requirements
2. **MFA**: Enable multi-factor authentication for all users
3. **Regular Updates**: Keep all dependencies up to date
4. **Penetration Testing**: Conduct regular security audits
5. **Incident Response**: Have a documented incident response plan
6. **Data Retention**: Implement automated data retention policies
7. **User Training**: Train all users on HIPAA compliance

## Troubleshooting

### Database Connection Issues
```bash
# Check database status
docker-compose logs postgres

# Verify connection
docker-compose exec backend python -c "from app import db; db.engine.execute('SELECT 1')"
```

### File Upload Issues
```bash
# Check storage permissions
ls -la data/videos

# Verify encryption key
docker-compose exec backend python -c "from app import cipher_suite; print('Encryption working' if cipher_suite else 'Error')"
```

### Authentication Problems
```bash
# Reset user password
docker-compose exec backend python reset_password.py username
```

## License & Compliance

This application is designed to meet HIPAA technical safeguards requirements. However, **HIPAA compliance is not just technical** - it requires:
- Administrative policies and procedures
- Physical security controls
- Staff training and awareness
- Business associate agreements
- Regular risk assessments

Consult with a HIPAA compliance expert before deploying in a production healthcare environment.

## Support & Contact

For technical support or compliance questions, please contact your system administrator or security officer.

## Changelog

### Version 1.0.0 (Initial Release)
- User authentication and authorization
- Encrypted video upload and storage
- Video analysis framework
- Comprehensive audit logging
- HIPAA-compliant infrastructure
