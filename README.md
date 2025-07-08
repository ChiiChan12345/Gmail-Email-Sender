# 🚀 Gmail Emailer Web App

A professional email automation tool with OAuth2 authentication, spam prevention, and modern web interface.

## ✨ Features

- **OAuth2 Authentication** - Secure Google login, no app passwords needed
- **Spam Prevention** - Built-in delays and rate limiting
- **Bulk Email Support** - Send to multiple recipients with personalization
- **Modern Web Interface** - Clean, responsive Bootstrap UI
- **Campaign Tracking** - Monitor sent emails and statistics
- **Recipient Management** - Add manually or upload CSV files
- **Email Templates** - Quick templates for common scenarios
- **Cloud-Ready** - Configured for Railway, Vercel, Heroku deployment

## 🛠️ Quick Deploy to Railway

1. **Deploy to Railway:**
   - Go to [Railway](https://railway.app/)
   - Click "Deploy from GitHub repo"
   - Select this repository

2. **Set Environment Variables:**
   ```
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   REDIRECT_URI=https://your-app.railway.app/callback
   SECRET_KEY=your_secure_random_key
   ```

3. **Configure Google OAuth2:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create OAuth2 credentials
   - Add your Railway URL + `/callback` as authorized redirect URI

4. **Access Your App:**
   - Visit your Railway URL
   - Sign in with Google
   - Start sending emails!

## 📋 Files Structure

```
gmail-emailer-webapp/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile              # Railway/Heroku deployment
├── railway.toml          # Railway configuration
├── runtime.txt           # Python version
├── .gitignore            # Git ignore rules
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── compose.html
│   ├── recipients.html
│   ├── add_recipient.html
│   └── campaigns.html
├── RAILWAY_SETUP.md      # Detailed deployment guide
└── WEBAPP_SETUP.md       # Local development guide
```

## 🔧 Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables:**
   ```bash
   export GOOGLE_CLIENT_ID=your_client_id
   export GOOGLE_CLIENT_SECRET=your_client_secret
   export REDIRECT_URI=http://localhost:5000/callback
   export SECRET_KEY=your_secret_key
   ```

3. **Run the app:**
   ```bash
   python app.py
   ```

4. **Visit:** `http://localhost:5000`

## 🌐 Cloud Deployment

This app is configured for multiple cloud services:

- **Railway** (recommended) - See `RAILWAY_SETUP.md`
- **Vercel** - Set environment variables in dashboard
- **Heroku** - Uses included `Procfile`
- **Render** - Auto-deploys from GitHub
- **DigitalOcean** - App Platform compatible

## 🛡️ Security Features

- OAuth2 authentication (no passwords stored)
- Environment variables for secrets
- Rate limiting to prevent spam flagging
- Session management
- HTTPS required for production

## 📊 Anti-Spam Protection

- 30-60 second delays between emails
- Maximum 50 emails per hour
- Maximum 500 emails per day
- Randomized send intervals

## 🎯 Usage

1. **Login** with Google OAuth2
2. **Add Recipients** manually or via CSV upload
3. **Compose Email** with personalization variables
4. **Send Campaign** with built-in spam protection
5. **Track Results** on dashboard

## 🔄 Personalization

Use `{name}` in your email subject and body to automatically personalize with recipient names.

## 📚 Documentation

- `RAILWAY_SETUP.md` - Complete Railway deployment guide
- `WEBAPP_SETUP.md` - Local development and OAuth2 setup

## 🆘 Support

For issues:
1. Check the setup guides
2. Verify environment variables are set
3. Ensure OAuth2 redirect URIs match your domain
4. Check application logs for error messages

## 📝 License

This project is open source and available under the MIT License.

---

**Ready to deploy?** Follow the Railway setup guide and have your professional email sender running in minutes! 🚀 