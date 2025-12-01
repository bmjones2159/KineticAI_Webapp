# 24/7 Deployment Guide for Student Projects
# HIPAA-Compliant Video Analysis Platform

## Quick Start Options (Recommended for Students)

### Option 1: Railway.app (Easiest - Free Tier Available) ⭐ RECOMMENDED

**Cost**: Free with $5/month credit (enough for student projects)  
**Setup Time**: 5 minutes  
**HIPAA Ready**: Yes (with proper configuration)

#### Steps:

1. **Prepare Your Code**
```bash
cd video_webapp
git init
git add .
git commit -m "Initial commit"
```

2. **Push to GitHub**
```bash
# Create a new GitHub repository
# Then push your code
git remote add origin https://github.com/YOUR_USERNAME/kinetic-ai.git
git branch -M main
git push -u origin main
```

3. **Deploy to Railway**
   - Go to https://railway.app
   - Sign up with GitHub
   - Click "New Project"
   - Choose "Deploy from GitHub repo"
   - Select your repository
   - Railway will auto-detect the Dockerfile and deploy

4. **Configure Environment Variables**
   In Railway dashboard, add these variables:
   ```
   DATABASE_URL=<Railway will provide this>
   SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
   JWT_SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
   ENCRYPTION_KEY=<generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
   ```

5. **Add PostgreSQL Database**
   - In Railway, click "New" -> "Database" -> "PostgreSQL"
   - Railway will automatically link it to your service

6. **Access Your App**
   - Railway will provide a URL like: https://your-app.railway.app
   - Your API will be at: https://your-app.railway.app/api

---

### Option 2: Render.com (Also Easy & Free)

**Cost**: Free tier available  
**Setup Time**: 10 minutes

1. Go to https://render.com
2. Sign up with GitHub
3. Create new "Web Service"
4. Connect your GitHub repository
5. Configure:
   - Build Command: `pip install -r backend/requirements.txt`
   - Start Command: `cd backend && gunicorn app:app`
6. Add PostgreSQL database from Render dashboard
7. Set environment variables (same as Railway)

---

### Option 3: Google Cloud Run (Free Credits)

**Cost**: $300 free credits (lasts 12 months)  
**Setup Time**: 15 minutes

```bash
# Install Google Cloud SDK
# Then:
gcloud init
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/kinetic-ai ./backend
gcloud run deploy kinetic-ai --image gcr.io/YOUR_PROJECT_ID/kinetic-ai --platform managed
```

---

### Option 4: AWS (Free Tier)

**Cost**: Free tier for 12 months  
**Setup Time**: 20 minutes

Use AWS Elastic Beanstalk:
```bash
pip install awsebcli
eb init
eb create kinetic-ai-env
eb deploy
```

---

## Local Development Setup

### Quick Start:

```bash
cd video_webapp

# 1. Set up environment
cp .env.template .env
# Edit .env with your values

# 2. Generate keys
python3 << 'EOF'
import secrets
from cryptography.fernet import Fernet

print("Add these to your .env file:")
print(f"SECRET_KEY={secrets.token_hex(32)}")
print(f"JWT_SECRET_KEY={secrets.token_hex(32)}")
print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")
EOF

# 3. Start with Docker Compose
docker-compose up -d

# 4. Initialize database
docker-compose exec backend python << 'EOF'
from app import app, db
with app.app_context():
    db.create_all()
    print("✓ Database initialized!")
EOF

# 5. Access the app
# Frontend: http://localhost
# Backend API: http://localhost:5000
```

---

## Deployment Checklist for HIPAA Compliance

### Before Going Live:

- [ ] **SSL/TLS Certificate** - Get free cert from Let's Encrypt
- [ ] **Strong Passwords** - Generate secure encryption keys
- [ ] **Database Backups** - Enable automatic backups
- [ ] **Environment Variables** - Never commit secrets to Git
- [ ] **Access Logs** - Enable audit logging
- [ ] **Firewall Rules** - Restrict access to database
- [ ] **CORS Configuration** - Set allowed origins
- [ ] **Rate Limiting** - Prevent abuse
- [ ] **Session Timeout** - Configure JWT expiration
- [ ] **Data Retention Policy** - Configure automatic cleanup

### Post-Deployment:

- [ ] Test user registration and login
- [ ] Test video upload (try different file sizes)
- [ ] Test video analysis (verify YOLOv8 is working)
- [ ] Test download features (annotated video, CSV)
- [ ] Monitor server logs
- [ ] Set up uptime monitoring (e.g., UptimeRobot)
- [ ] Document any issues

---

## Cost Estimation (Monthly)

### Free Tier / Student Budget:

**Railway.app (Recommended)**:
- Free tier: $5 credit/month
- Typical usage: $3-5/month
- **Cost: FREE or $0-3/month**

**Render.com**:
- Free tier: 750 hours/month
- **Cost: FREE**

**Google Cloud**:
- $300 free credits (12 months)
- **Cost: FREE for first year**

**AWS Free Tier**:
- 750 hours/month EC2 (12 months)
- **Cost: FREE for first year**

### Production Deployment:

**Small Scale (100 users)**:
- Railway: ~$10/month
- Render: ~$15/month
- AWS: ~$20/month

**Medium Scale (1000 users)**:
- Railway: ~$30/month
- AWS/GCP: ~$50-100/month

---

## Monitoring & Maintenance

### Set Up Free Monitoring:

1. **UptimeRobot** (https://uptimerobot.com)
   - Free tier: 50 monitors
   - Checks every 5 minutes
   - Email alerts

2. **Sentry** (https://sentry.io)
   - Free tier: 5,000 events/month
   - Error tracking
   - Performance monitoring

3. **Google Analytics**
   - Free
   - Track usage
   - User analytics

### Health Check Endpoint:

Test if your app is running:
```bash
curl https://your-app-url.com/api/health
```

Should return:
```json
{
  "status": "healthy",
  "timestamp": "2024-11-30T12:00:00.000000"
}
```

---

## Troubleshooting Common Issues

### 1. Video Upload Fails

**Problem**: "Request Entity Too Large"  
**Solution**: Increase max upload size in nginx/load balancer

For Railway/Render:
```python
# In app.py, already set:
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
```

### 2. Video Analysis Times Out

**Problem**: Analysis takes too long  
**Solution**: Increase timeout in deployment config

For Railway:
```yaml
# In railway.yml (already configured):
healthcheck:
  timeout: 300  # 5 minutes
```

### 3. Database Connection Error

**Problem**: "could not connect to server"  
**Solution**: Check DATABASE_URL environment variable

```bash
# Test database connection:
docker-compose exec backend python << 'EOF'
from app import db
try:
    db.engine.execute('SELECT 1')
    print("✓ Database connected!")
except Exception as e:
    print(f"✗ Database error: {e}")
EOF
```

### 4. Out of Memory

**Problem**: "Killed" or "OOM"  
**Solution**: 
- Reduce YOLOv8 model size (use yolov8n-pose.pt instead of yolov8m-pose.pt)
- Process videos in batches
- Increase server memory allocation

### 5. Slow Performance

**Solutions**:
- Enable video compression before upload
- Use smaller YOLOv8 model
- Add caching for analysis results
- Optimize database queries

---

## Security Best Practices

1. **Never commit .env file**
```bash
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
```

2. **Rotate encryption keys regularly**
```python
# Generate new keys monthly
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

3. **Enable 2FA for deployment platforms**
   - Railway: Settings -> Security
   - GitHub: Settings -> Security -> 2FA

4. **Use strong database passwords**
```python
# Generate secure password:
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

5. **Regular backups**
```bash
# Manual backup:
docker-compose exec postgres pg_dump -U hipaa_user video_hipaa_db > backup.sql

# Restore:
docker-compose exec -T postgres psql -U hipaa_user video_hipaa_db < backup.sql
```

---

## Getting Help

### Resources:
- Railway Docs: https://docs.railway.app
- Render Docs: https://render.com/docs
- Flask Docs: https://flask.palletsprojects.com
- YOLOv8 Docs: https://docs.ultralytics.com

### Support Channels:
- Railway Discord: https://discord.gg/railway
- GitHub Issues: Create issue in your repo
- Stack Overflow: Tag with `flask`, `yolov8`, `deployment`

---

## Quick Reference Commands

```bash
# View logs
docker-compose logs -f backend

# Restart services
docker-compose restart

# Stop everything
docker-compose down

# Rebuild and restart
docker-compose up -d --build

# Check database
docker-compose exec postgres psql -U hipaa_user -d video_hipaa_db

# Create admin user
docker-compose exec backend python << 'EOF'
from app import app, db, User, bcrypt
with app.app_context():
    admin = User(
        username='admin',
        email='admin@example.com',
        password_hash=bcrypt.generate_password_hash('SecurePassword123!').decode('utf-8'),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    print("✓ Admin user created!")
EOF
```

---

## Success Checklist

After deployment, verify:

- ✅ Can access frontend at your URL
- ✅ Can register new user account
- ✅ Can login successfully
- ✅ Can upload a video file
- ✅ Can view uploaded videos
- ✅ Can analyze video (wait for completion)
- ✅ Can view analysis results
- ✅ Can download annotated video
- ✅ Can download CSV data
- ✅ Can logout and login again
- ✅ Videos persist after restart

---

## Your App is Now Live! 🎉

**Next Steps**:
1. Share the URL with your team/professor
2. Test with sample exercise videos
3. Monitor usage and performance
4. Iterate based on feedback

**For Student Projects**:
- Document your deployment process
- Take screenshots for your report
- Note any challenges and solutions
- Measure performance metrics

Good luck with your project! 🚀
