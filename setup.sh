#!/bin/bash

# Kinetic AI - Quick Setup Script
# For local development and testing

echo "=================================================="
echo "🏃 Kinetic AI - HIPAA Video Analysis Platform"
echo "=================================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install it first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file with secure keys..."
    cp .env.template .env
    
    # Generate secure keys using Python
    python3 << 'EOF'
import secrets
from cryptography.fernet import Fernet
import re

# Read template
with open('.env', 'r') as f:
    content = f.read()

# Generate keys
secret_key = secrets.token_hex(32)
jwt_key = secrets.token_hex(32)
encryption_key = Fernet.generate_key().decode()
db_password = secrets.token_urlsafe(24)

# Replace placeholders
content = re.sub(r'your_secure_database_password_here', db_password, content)
content = re.sub(r'generate_a_random_secret_key_here', secret_key, content)
content = re.sub(r'generate_a_random_jwt_secret_here', jwt_key, content)
content = re.sub(r'generate_a_fernet_key_here', encryption_key, content)

# Write back
with open('.env', 'w') as f:
    f.write(content)

print("✅ Secure keys generated and saved to .env")
EOF
else
    echo "✅ .env file already exists"
fi

echo ""

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/{postgres,videos,logs}
chmod 700 data/videos
echo "✅ Data directories created"
echo ""

# Build and start containers
echo "🐳 Building and starting Docker containers..."
echo "   This may take several minutes on first run..."
docker-compose build
docker-compose up -d

echo ""
echo "⏳ Waiting for services to start..."
sleep 10

# Initialize database
echo "🗄️  Initializing database..."
docker-compose exec -T backend python << 'EOF'
from app import app, db, User, bcrypt
import sys

try:
    with app.app_context():
        # Create tables
        db.create_all()
        print("✅ Database tables created")
        
        # Create default admin user
        existing_admin = User.query.filter_by(username='admin').first()
        if not existing_admin:
            admin = User(
                username='admin',
                email='admin@kineticai.com',
                password_hash=bcrypt.generate_password_hash('Admin123!').decode('utf-8'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created")
            print("   Username: admin")
            print("   Password: Admin123!")
            print("   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!")
        else:
            print("✅ Admin user already exists")
except Exception as e:
    print(f"❌ Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF

echo ""
echo "=================================================="
echo "✅ Setup Complete! Your app is running!"
echo "=================================================="
echo ""
echo "📍 Access your application:"
echo "   Frontend:  http://localhost"
echo "   Backend:   http://localhost:5000"
echo "   API Docs:  http://localhost:5000/api/health"
echo ""
echo "👤 Default Admin Credentials:"
echo "   Username: admin"
echo "   Password: Admin123!"
echo "   ⚠️  CHANGE THIS PASSWORD!"
echo ""
echo "📚 Next Steps:"
echo "   1. Open http://localhost in your browser"
echo "   2. Login with admin credentials"
echo "   3. Upload a video to test"
echo "   4. Run analysis and view results"
echo ""
echo "📋 Useful Commands:"
echo "   View logs:     docker-compose logs -f"
echo "   Stop app:      docker-compose down"
echo "   Restart:       docker-compose restart"
echo "   Rebuild:       docker-compose up -d --build"
echo ""
echo "📖 Documentation:"
echo "   README.md      - Full documentation"
echo "   DEPLOYMENT.md  - 24/7 hosting guide"
echo ""
echo "🚀 Happy analyzing!"
echo "=================================================="
