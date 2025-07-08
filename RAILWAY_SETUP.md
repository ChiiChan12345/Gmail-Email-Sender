# 🚀 Railway Deployment Guide - Gmail Emailer

## ✅ Benefits of Railway Deployment

- **Always Online** - Your app runs 24/7 without keeping your computer on
- **Professional URL** - Get a custom domain like `your-app.railway.app`
- **HTTPS Support** - Secure connections (required for OAuth2 production)
- **Easy Scaling** - Handle more users and emails
- **No Localhost Issues** - Accessible from anywhere

## 🛠️ Complete Railway Setup

### Step 1: Prepare Your Files

Your webapp is already configured for Railway! The following files have been created:
- `Procfile` - Tells Railway how to run your app
- `railway.toml` - Railway configuration
- `runtime.txt` - Python version specification
- `app.py` - Modified to use environment variables

### Step 2: Set Up Google OAuth2 for Railway

1. **Go to Google Cloud Console:**
   - Visit: https://console.cloud.google.com/

2. **Create/Select Project:**
   - Create a new project: "Gmail Emailer"
   - Enable Gmail API (APIs & Services → Library → Gmail API)

3. **Configure OAuth Consent Screen:**
   - APIs & Services → OAuth consent screen
   - Choose "External"
   - Fill in basic info (app name, email, etc.)

4. **Create OAuth2 Credentials:**
   - APIs & Services → Credentials
   - Create Credentials → OAuth 2.0 Client ID
   - Application type: "Web application"
   - **Authorized redirect URIs:** `https://your-app-name.railway.app/callback`
   - (You'll update this with your actual Railway URL)

### Step 3: Deploy to Railway

1. **Create Railway Account:**
   - Go to https://railway.app/
   - Sign up with GitHub/Google

2. **Deploy Your App:**
   - Click "Deploy from GitHub repo"
   - Or use Railway CLI:
     ```bash
     npm install -g @railway/cli
     railway login
     railway init
     railway up
     ```

3. **Get Your Railway URL:**
   - After deployment, Railway will give you a URL like:
   - `https://your-app-name.railway.app`

### Step 4: Set Environment Variables in Railway

In your Railway dashboard, go to Variables tab and add:

```
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
REDIRECT_URI=https://your-app-name.railway.app/callback
SECRET_KEY=your_secure_random_secret_key
```

### Step 5: Update Google OAuth2 with Railway URL

1. Go back to Google Cloud Console
2. Edit your OAuth2 credentials
3. Update "Authorized redirect URIs" to:
   ```
   https://your-app-name.railway.app/callback
   ```

### Step 6: Test Your Deployment

1. Visit your Railway URL
2. Click "Sign in with Google"
3. Authorize the app
4. Start using your Gmail emailer!

## 🔧 Alternative Cloud Services

### Vercel
- Add `vercel.json` configuration
- Set environment variables in Vercel dashboard
- Update OAuth2 redirect URI to Vercel URL

### Heroku
- Use `Procfile` (already created)
- Set environment variables in Heroku dashboard
- Update OAuth2 redirect URI to Heroku URL

### Render
- Connect GitHub repo
- Set environment variables in Render dashboard
- Update OAuth2 redirect URI to Render URL

### DigitalOcean App Platform
- Use `app.yaml` configuration
- Set environment variables in DO dashboard
- Update OAuth2 redirect URI to DO URL

## 📋 Environment Variables You Need

For ANY cloud service, you'll need these environment variables:

```
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
REDIRECT_URI=https://your-domain.com/callback
SECRET_KEY=your_secure_random_secret_key
```

## 🚨 Important Notes

1. **HTTPS Required:** OAuth2 requires HTTPS in production (all cloud services provide this)
2. **Secret Key:** Generate a secure random string for SECRET_KEY
3. **Redirect URI:** Must match exactly in Google Console and your environment variable
4. **Domain Updates:** If you change domains, update both environment variables and Google Console

## 🎯 Quick Railway Deploy Commands

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Deploy
railway up

# Check deployment
railway status

# View logs
railway logs

# Set environment variables
railway variables set GOOGLE_CLIENT_ID=your_id
railway variables set GOOGLE_CLIENT_SECRET=your_secret
railway variables set REDIRECT_URI=https://your-app.railway.app/callback
railway variables set SECRET_KEY=your_secure_key
```

## 💡 Pro Tips

1. **Custom Domain:** Railway supports custom domains in paid plans
2. **Database:** Railway offers PostgreSQL databases if you want to upgrade from SQLite
3. **Monitoring:** Use Railway's built-in monitoring to track your app
4. **Scaling:** Railway auto-scales based on usage
5. **SSL:** Railway automatically provides SSL certificates

## 🆘 Troubleshooting

**"Redirect URI mismatch"**
- Make sure your Railway URL matches the OAuth2 redirect URI exactly
- Include `/callback` at the end

**"Invalid client"**
- Check that environment variables are set correctly in Railway
- Verify Google Client ID and Secret are correct

**"App not loading"**
- Check Railway logs: `railway logs`
- Verify all environment variables are set
- Check that requirements.txt includes all dependencies

**"OAuth2 not working"**
- Ensure you're using HTTPS (Railway provides this automatically)
- Check that OAuth consent screen is published
- Verify redirect URI in Google Console matches your Railway URL

## 🎉 Success!

Once deployed, you'll have:
- ✅ Professional email sender running 24/7
- ✅ Secure HTTPS connection  
- ✅ Custom domain (your-app.railway.app)
- ✅ No localhost limitations
- ✅ Scalable infrastructure
- ✅ Easy updates via GitHub integration

Your Gmail emailer is now ready for production use! 