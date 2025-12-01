# 🚀 QUICK START GUIDE - Kinetic AI

## For Students: Get Your Project Online in 15 Minutes

### What You're Getting
✅ **HIPAA-compliant video analysis platform**  
✅ **YOLOv8 AI pose estimation** (from your Colab notebook)  
✅ **User authentication & database**  
✅ **Exercise form analysis** (squats, pushups, planks, lunges)  
✅ **CSV data export** for research  
✅ **Annotated videos** with pose skeleton  
✅ **24/7 hosting options** (FREE for students)

---

## 🎯 THREE OPTIONS TO GET STARTED

### OPTION 1: Test Locally First (5 minutes) ⚡

```bash
# 1. Unzip the project
cd video_webapp

# 2. Run setup script
chmod +x setup.sh
./setup.sh

# 3. Open browser
# Go to: http://localhost
# Login: admin / Admin123!
```

**That's it!** Your app is running locally.

---

### OPTION 2: Deploy to Railway (FREE Hosting) 🚂

**Best for**: Student projects that need to stay online 24/7

1. **Create GitHub Account** (if you don't have one)
   - Go to https://github.com
   - Sign up for free

2. **Create New Repository**
   - Click "New repository"
   - Name: `kinetic-ai` (or anything you want)
   - Make it Private or Public
   - Click "Create repository"

3. **Upload Your Code**
   ```bash
   cd video_webapp
   git init
   git add .
   git commit -m "Kinetic AI - Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/kinetic-ai.git
   git branch -M main
   git push -u origin main
   ```

4. **Deploy to Railway**
   - Go to https://railway.app
   - Click "Login with GitHub"
   - Click "New Project"
   - Click "Deploy from GitHub repo"
   - Select your `kinetic-ai` repository
   - Railway will start deploying automatically!

5. **Add Database**
   - In Railway dashboard, click "New"
   - Select "Database"
   - Choose "PostgreSQL"
   - It will automatically connect to your app

6. **Set Environment Variables**
   - Click on your service
   - Go to "Variables" tab
   - Add these (generate new values):
   
   ```
   SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">
   JWT_SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">
   ENCRYPTION_KEY=<run: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
   ```

7. **Get Your URL**
   - Railway will give you a URL like: `https://your-app.railway.app`
   - Your app is now LIVE! 🎉

**Cost**: FREE (Railway gives $5/month credit)

---

### OPTION 3: Deploy to Render.com (Also FREE) 🔵

**Alternative to Railway**

1. Go to https://render.com
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Connect GitHub repository
5. Configure:
   - **Name**: kinetic-ai
   - **Root Directory**: backend
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
6. Add PostgreSQL:
   - Dashboard → "New +" → "PostgreSQL"
7. Set environment variables (same as Railway)
8. Click "Create Web Service"

**Done!** Your app is live.

---

## 📱 HOW TO USE YOUR APP

### 1️⃣ First Login
- Go to your app URL
- Login with:
  - Username: `admin`
  - Password: `Admin123!`
- **⚠️ CHANGE THIS PASSWORD IMMEDIATELY**

### 2️⃣ Upload a Video
- Click the upload area
- Select an exercise video (squat, pushup, plank, or lunge)
- Optionally add:
  - Patient ID (will be encrypted)
  - Metadata (JSON format)
- Click "Upload & Encrypt"

### 3️⃣ Analyze the Video
- Click "🔍 Analyze" button on your video
- Wait 1-3 minutes (depending on video length)
- The AI will:
  - Detect exercise type
  - Calculate form accuracy
  - Find common mistakes
  - Track all joint angles

### 4️⃣ View Results
Click on analyzed video to:
- **📊 Results**: See accuracy score and form issues
- **🎬 Analyzed**: Download video with pose skeleton
- **📄 CSV**: Download all skeletal data

---

## 🎓 FOR YOUR PROJECT PRESENTATION

### Screenshots to Take
1. Login page
2. Video upload interface
3. Video list with analysis status
4. Analysis results popup
5. Annotated video playing
6. CSV data in Excel

### Demo Flow
1. Show login (security)
2. Upload sample video
3. Start analysis
4. Show results
5. Download annotated video
6. Show CSV data

### Technical Highlights
- "HIPAA-compliant with encryption"
- "AI-powered using YOLOv8"
- "Real-time pose estimation"
- "Cloud deployment on Railway/Render"
- "Full-stack application (Flask + PostgreSQL)"

---

## 🐛 TROUBLESHOOTING

### Video Upload Fails
**Problem**: File too large  
**Solution**: Video must be under 500MB. Compress it first.

### Analysis Takes Forever
**Problem**: Long video  
**Solution**: Try shorter video (30-60 seconds) first

### Can't Login
**Problem**: Wrong password  
**Solution**: Default is `Admin123!` - case sensitive

### Railway Says "Out of Credit"
**Problem**: Free tier limit reached  
**Solution**: 
- Wait until next month (credit resets)
- OR upgrade to paid plan ($5/month)
- OR switch to Render.com (also free)

### Database Connection Error
**Problem**: DATABASE_URL not set  
**Solution**: Make sure you added PostgreSQL in Railway/Render

---

## 📚 WHAT'S INCLUDED

### Files You'll Use:
- `backend/app.py` - Main Flask application
- `backend/kinetic_analyzer.py` - YOLOv8 pose analysis (your Colab code!)
- `frontend/index.html` - Web interface
- `docker-compose.yml` - Local development setup
- `README.md` - Full documentation
- `DEPLOYMENT.md` - Detailed hosting guide

### Features:
✅ User authentication (login/register)  
✅ Video upload with encryption  
✅ AI pose estimation (YOLOv8)  
✅ Exercise type detection  
✅ Form accuracy scoring  
✅ Issue detection  
✅ Annotated video export  
✅ CSV data export  
✅ Audit logging (HIPAA)  
✅ Access controls  
✅ Database encryption  

---

## 💡 TIPS FOR SUCCESS

1. **Test Locally First**
   - Always test on your computer before deploying
   - Use the `setup.sh` script
   - Make sure everything works

2. **Use Good Sample Videos**
   - Clear view of person
   - Good lighting
   - 30-60 seconds long
   - Obvious exercise movements

3. **Keep Secrets Secret**
   - NEVER commit .env file to GitHub
   - Generate new keys for production
   - Change default admin password

4. **Monitor Your App**
   - Check Railway/Render dashboard
   - View logs if something breaks
   - Set up email alerts

5. **Document Everything**
   - Take screenshots
   - Note any issues you solved
   - Keep track of deployment steps

---

## 🎯 SUCCESS CHECKLIST

Before your presentation:

- [ ] App is deployed and accessible via URL
- [ ] Can register new users
- [ ] Can upload videos
- [ ] Video analysis works
- [ ] Can download annotated videos
- [ ] Can export CSV data
- [ ] Have screenshots ready
- [ ] Tested on different browsers
- [ ] Changed admin password
- [ ] Prepared demo script

---

## 🆘 NEED HELP?

### Resources:
- **Full Docs**: See `README.md`
- **Deployment Guide**: See `DEPLOYMENT.md`
- **Railway Docs**: https://docs.railway.app
- **Render Docs**: https://render.com/docs
- **Flask Docs**: https://flask.palletsprojects.com
- **YOLOv8 Docs**: https://docs.ultralytics.com

### Common Commands:
```bash
# View logs
docker-compose logs -f

# Restart app
docker-compose restart

# Stop app
docker-compose down

# Rebuild from scratch
docker-compose up -d --build
```

---

## 🎉 YOU'RE READY!

Your Kinetic AI platform is ready to:
- Analyze exercise videos
- Detect form issues
- Export data for research
- Run 24/7 in the cloud
- Impress your professor!

**Good luck with your project! 🚀**

---

## 📞 QUICK REFERENCE

**Local App**: http://localhost  
**Default Login**: admin / Admin123!  
**Railway**: https://railway.app  
**Render**: https://render.com  

**Generate Keys**:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Setup Command**:
```bash
./setup.sh
```

**That's it! Now go build something amazing! 💪**
