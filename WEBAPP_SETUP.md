# 🚀 Gmail Emailer Web App - Setup Guide

## ✨ Features

- **No app passwords needed** - Uses secure OAuth2 authentication
- **Web-based interface** - Easy to use dashboard
- **Spam prevention** - Built-in delays and limits
- **Bulk email support** - Send to multiple recipients
- **Campaign tracking** - Monitor sent emails
- **Personalization** - Use {name} variables in emails
- **Modern UI** - Clean, responsive design

## 🛠️ Quick Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Up Google OAuth2

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API:
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API" and enable it
4. Create OAuth2 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client ID"
   - Choose "Web application"
   - Add `http://localhost:5000/callback` to "Authorized redirect URIs"
5. Download the credentials JSON file

### 3. Configure the App

Edit `app.py` and update these settings:

```python
# ===== PERSONALIZE THESE SETTINGS =====
GOOGLE_CLIENT_ID = 'your-google-client-id'
GOOGLE_CLIENT_SECRET = 'your-google-client-secret'
app.secret_key = 'your-secret-key-here'  # Change to a secure random key
```

### 4. Run the App

```bash
python app.py
```

Visit `http://localhost:5000` in your browser!

## 📋 What You Need to Personalize

### Required Settings (in `app.py`):

```python
# OAuth2 credentials from Google Cloud Console
GOOGLE_CLIENT_ID = 'your-google-client-id'
GOOGLE_CLIENT_SECRET = 'your-google-client-secret'

# Secure secret key for Flask sessions
app.secret_key = 'your-secret-key-here'
```

### Optional Settings (in `app.py`):

```python
# Anti-spam settings
SPAM_PREVENTION = {
    'min_delay': 30,     # Minimum seconds between emails
    'max_delay': 60,     # Maximum seconds between emails
    'max_per_hour': 50,  # Maximum emails per hour
    'max_per_day': 500   # Maximum emails per day
}
```

## 🎯 How to Use

### 1. Login
- Click "Sign in with Google"
- Authorize the app to send emails on your behalf

### 2. Add Recipients
- Go to "Recipients" in the sidebar
- Add recipients manually or upload a CSV file
- CSV format: `name,email,custom_message`

### 3. Compose Email
- Go to "Compose Email"
- Write your subject and message
- Use `{name}` for personalization
- Choose to send to all recipients or selected ones

### 4. Send & Track
- Click "Send Email"
- Monitor progress in real-time
- View campaign history in "Campaigns"

## 📊 Dashboard Features

- **Statistics Cards**: Today's email count, total recipients, campaigns
- **Quick Actions**: Fast access to compose, recipients, campaigns
- **Spam Prevention Status**: Visual progress bars for daily limits
- **Recent Campaigns**: Overview of recent email campaigns

## 🔧 Advanced Features

### Email Templates
The compose page includes quick templates for:
- Greeting emails
- Business outreach
- Follow-up messages

### Personalization Variables
- `{name}` - Recipient's name
- More variables can be added easily

### Database
Uses SQLite database to store:
- Email campaigns
- Sent email logs
- Recipient lists

## 🛡️ Security Features

- **OAuth2 Authentication**: No need for app passwords
- **Rate Limiting**: Prevents spam flag triggers
- **Session Management**: Secure user sessions
- **Database Security**: Local SQLite storage

## 📁 Project Structure

```
gmail-emailer-webapp/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── emailer.db            # SQLite database (created automatically)
├── templates/            # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── compose.html
│   ├── recipients.html
│   └── campaigns.html
└── static/               # CSS/JS files (optional)
```

## 🚨 Troubleshooting

### OAuth2 Issues
- Make sure redirect URI is exactly `http://localhost:5000/callback`
- Check that Gmail API is enabled in Google Cloud Console
- Verify client ID and secret are correct

### Database Issues
- Database is created automatically on first run
- Delete `emailer.db` to reset all data

### Rate Limiting
- The app includes built-in spam prevention
- Adjust limits in `SPAM_PREVENTION` settings

## 🎨 Customization

### Change UI Colors
Edit the CSS in `templates/base.html`:

```css
.btn-primary {
    background-color: #your-color;
    border-color: #your-color;
}
```

### Add New Templates
Edit the `templates` object in `templates/compose.html`:

```javascript
const templates = {
    your_template: {
        subject: "Your Subject",
        body: "Your message template"
    }
};
```

### Modify Spam Prevention
Edit `SPAM_PREVENTION` in `app.py`:

```python
SPAM_PREVENTION = {
    'min_delay': 60,     # Longer delays
    'max_delay': 120,    # Up to 2 minutes
    'max_per_hour': 25,  # More conservative
    'max_per_day': 250   # Lower daily limit
}
```

## ⚖️ Legal Compliance

Always ensure compliance with:
- Gmail's Terms of Service
- CAN-SPAM Act (US)
- GDPR (EU)
- Local privacy laws
- Recipient consent requirements

## 🆘 Support

For issues:
1. Check the troubleshooting section
2. Verify all setup steps are completed
3. Check console logs for error messages
4. Ensure all dependencies are installed

## 🚀 Deployment

For production deployment:
1. Use a production WSGI server (gunicorn, uwsgi)
2. Set up a reverse proxy (nginx, Apache)
3. Use environment variables for secrets
4. Consider using PostgreSQL instead of SQLite
5. Enable HTTPS 