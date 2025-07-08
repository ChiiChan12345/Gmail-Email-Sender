from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import os
import json
import base64
import time
import random
from datetime import datetime, timedelta
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import csv
import io

# Force HTTPS for OAuth2 on Railway
if 'railway.app' in os.environ.get('REDIRECT_URI', ''):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow OAuth over HTTP proxy
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'   # Relax token scope validation

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable

# Session configuration for Railway HTTPS deployment
if 'localhost' not in os.environ.get('REDIRECT_URI', ''):
    # Production settings (Railway)
    app.config['SESSION_COOKIE_SECURE'] = True  # Require HTTPS for cookies
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS attacks
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow OAuth redirects
else:
    # Development settings (localhost)
    app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP for local development
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS attacks
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow OAuth redirects

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Session expires in 24 hours

# ===== PERSONALIZE THESE SETTINGS =====
# OAuth2 settings - You'll need to set these up in Google Console
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'your-google-client-id')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your-google-client-secret')

# For Railway deployment, use environment variable or localhost for development
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:5000/callback')

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# Anti-spam settings
SPAM_PREVENTION = {
    'min_delay': 30,  # Minimum seconds between emails
    'max_delay': 60,  # Maximum seconds between emails
    'max_per_hour': 50,  # Maximum emails per hour
    'max_per_day': 500  # Maximum emails per day
}

# Database setup
def init_db():
    """Initialize the database"""
    conn = sqlite3.connect('emailer.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'draft',
            total_recipients INTEGER DEFAULT 0,
            sent_count INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            completed_at TIMESTAMP NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sent_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            recipient_email TEXT NOT NULL,
            recipient_name TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'sent',
            error_message TEXT NULL,
            FOREIGN KEY (campaign_id) REFERENCES email_campaigns (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recipient_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            company TEXT,
            position TEXT,
            phone TEXT,
            group_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES recipient_groups (id)
        )
    ''')
    
    # Add missing columns to existing tables
    try:
        cursor.execute('ALTER TABLE email_campaigns ADD COLUMN status TEXT DEFAULT "draft"')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE email_campaigns ADD COLUMN total_recipients INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE email_campaigns ADD COLUMN sent_count INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE email_campaigns ADD COLUMN error_count INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE email_campaigns ADD COLUMN completed_at TIMESTAMP NULL')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE sent_emails ADD COLUMN error_message TEXT NULL')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE recipients ADD COLUMN company TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE recipients ADD COLUMN position TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE recipients ADD COLUMN phone TEXT')
    except sqlite3.OperationalError:
        pass
    
    try:
        cursor.execute('ALTER TABLE recipients ADD COLUMN group_id INTEGER')
    except sqlite3.OperationalError:
        pass
    
    # Clean up any recipients with blank or invalid email addresses
    cursor.execute('''
        DELETE FROM recipients 
        WHERE email IS NULL OR email = '' OR name IS NULL OR name = ''
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('emailer.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Main homepage - shows landing page for non-authenticated users, dashboard for authenticated users"""
    print(f"DEBUG: Index route - credentials in session: {bool(session.get('credentials'))}")
    print(f"DEBUG: Session keys: {list(session.keys())}")
    
    if 'credentials' not in session:
        print("DEBUG: No credentials found, showing homepage")
        return render_template('index.html')
    
    print("DEBUG: Credentials found, showing dashboard")
    # Get statistics for authenticated users
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recent campaigns
    cursor.execute('SELECT * FROM email_campaigns ORDER BY created_at DESC LIMIT 5')
    campaigns = cursor.fetchall()
    
    # Get today's email count
    cursor.execute('''
        SELECT COUNT(*) FROM sent_emails 
        WHERE DATE(sent_at) = DATE('now')
    ''')
    today_count = cursor.fetchone()[0]
    
    # Get total recipients
    cursor.execute('SELECT COUNT(*) FROM recipients')
    total_recipients = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         campaigns=campaigns, 
                         today_count=today_count,
                         total_recipients=total_recipients)

@app.route('/login')
def login():
    """Start OAuth2 login process"""
    # Force HTTPS for Railway deployments
    if 'railway.app' in request.host:
        request.environ['wsgi.url_scheme'] = 'https'
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI
    
    print(f"DEBUG: Login - Redirect URI: {flow.redirect_uri}")
    print(f"DEBUG: Login - Request scheme: {request.scheme}")
    print(f"DEBUG: Login - Request host: {request.host}")
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account'
    )
    
    print(f"DEBUG: Login - Authorization URL: {authorization_url}")
    print(f"DEBUG: Login - State: {state}")
    
    session['state'] = state
    session.permanent = True
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """Handle OAuth2 callback"""
    # Force HTTPS for the current request URL on Railway
    if 'railway.app' in request.host:
        request.environ['wsgi.url_scheme'] = 'https'
    
    print(f"DEBUG: Callback received - URL: {request.url}")
    print(f"DEBUG: Host: {request.host}")
    print(f"DEBUG: Scheme: {request.scheme}")
    print(f"DEBUG: Session state: {session.get('state')}")
    print(f"DEBUG: Request args: {request.args}")
    
    state = session.get('state')
    
    if not state:
        print("DEBUG: No state found in session")
        flash('Authentication failed: No state found in session. Please try again.', 'error')
        return redirect(url_for('index'))
    
    # Check if we have the authorization code
    if 'code' not in request.args:
        print("DEBUG: No authorization code received")
        flash('Authentication failed: No authorization code received.', 'error')
        return redirect(url_for('index'))
    
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [REDIRECT_URI]
                }
            },
            scopes=SCOPES,
            state=state
        )
        flow.redirect_uri = REDIRECT_URI
        
        print(f"DEBUG: Using redirect URI: {flow.redirect_uri}")
        
        # Fetch the token
        flow.fetch_token(authorization_response=request.url.replace('http://', 'https://'))
        
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        session.permanent = True
        
        print(f"DEBUG: Credentials saved to session: {bool(session.get('credentials'))}")
        print(f"DEBUG: Session ID: {session.get('_id', 'No ID')}")
        print(f"DEBUG: Credentials dict: {session.get('credentials', {}).keys()}")
        
        # Test session persistence immediately
        test_session = session.get('credentials')
        print(f"DEBUG: Can retrieve credentials immediately: {bool(test_session)}")
        
        flash('Successfully logged in!', 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"DEBUG: OAuth Error: {str(e)}")
        print(f"Request URL: {request.url}")
        print(f"Redirect URI: {REDIRECT_URI}")
        flash(f'Authentication failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/recipients')
def recipients():
    """View all recipients"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all recipients with group information
    cursor.execute('''
        SELECT r.*, g.name as group_name 
        FROM recipients r 
        LEFT JOIN recipient_groups g ON r.group_id = g.id 
        ORDER BY r.created_at DESC
    ''')
    recipients = cursor.fetchall()
    
    # Get all groups
    cursor.execute('SELECT * FROM recipient_groups ORDER BY name')
    groups = cursor.fetchall()
    
    conn.close()
    
    return render_template('recipients.html', recipients=recipients, groups=groups)

@app.route('/recipients/add', methods=['GET', 'POST'])
def add_recipient():
    """Add new recipient"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO recipients (name, email) VALUES (?, ?)', 
                         (name, email))
            conn.commit()
            flash('Recipient added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('recipients'))
    
    return render_template('add_recipient.html')

@app.route('/recipients/upload', methods=['POST'])
def upload_recipients():
    """Upload recipients from CSV"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    if 'file' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('recipients'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('recipients'))
    
    if file and file.filename and file.filename.endswith('.csv'):
        try:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.DictReader(stream)
            
            conn = get_db()
            cursor = conn.cursor()
            
            # Create a group for this CSV upload
            group_name = f"CSV Upload - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            cursor.execute('INSERT INTO recipient_groups (name) VALUES (?)', (group_name,))
            group_id = cursor.lastrowid
            
            added_count = 0
            skipped_count = 0
            
            for row in csv_input:
                # Get data with fallback checks for different column name formats
                name = row.get('name', row.get('Name', '')).strip()
                email = row.get('email', row.get('Email', '')).strip()
                company = row.get('company', row.get('Company', '')).strip()
                position = row.get('position', row.get('Position', row.get('job_title', row.get('Job Title', '')))).strip()
                phone = row.get('phone', row.get('Phone', row.get('phone_number', row.get('Phone Number', '')))).strip()
                
                # Validate that both name and email are not empty
                if not name or not email:
                    skipped_count += 1
                    continue
                
                # Basic email validation
                if '@' not in email or '.' not in email:
                    skipped_count += 1
                    continue
                
                try:
                    cursor.execute('''
                        INSERT INTO recipients (name, email, company, position, phone, group_id) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (name, email, company, position, phone, group_id))
                    added_count += 1
                except sqlite3.IntegrityError:
                    skipped_count += 1  # Skip duplicates
            
            conn.commit()
            conn.close()
            
            if added_count > 0:
                flash(f'Added {added_count} recipients to group "{group_name}"! Skipped {skipped_count} invalid/duplicate entries.', 'success')
            else:
                flash(f'No valid recipients found in CSV. Skipped {skipped_count} entries.', 'warning')
                
        except Exception as e:
            flash(f'Error processing CSV file: {str(e)}', 'error')
    else:
        flash('Please upload a CSV file!', 'error')
    
    return redirect(url_for('recipients'))

@app.route('/compose')
def compose():
    """Compose email"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    return render_template('compose.html')

@app.route('/send', methods=['POST'])
def send_email():
    """Send email"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    subject = request.form['subject']
    body = request.form['body']
    send_to = request.form['send_to']  # 'all' or 'selected'
    
    # Validate subject and body
    if not subject.strip() or not body.strip():
        flash('Subject and message cannot be empty!', 'error')
        return redirect(url_for('compose'))
    
    # Create campaign
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recipients first to count total
    if send_to == 'all':
        cursor.execute('SELECT * FROM recipients WHERE email IS NOT NULL AND email != ""')
    else:
        recipient_ids = request.form.getlist('recipient_ids')
        if recipient_ids:
            placeholders = ','.join(['?' for _ in recipient_ids])
            cursor.execute(f'SELECT * FROM recipients WHERE id IN ({placeholders}) AND email IS NOT NULL AND email != ""', 
                         recipient_ids)
        else:
            flash('No recipients selected!', 'error')
            conn.close()
            return redirect(url_for('compose'))
    
    recipients = cursor.fetchall()
    
    if not recipients:
        flash('No valid recipients found!', 'error')
        conn.close()
        return redirect(url_for('compose'))
    
    # Create campaign with total count
    campaign_name = f"Campaign {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    cursor.execute('''
        INSERT INTO email_campaigns (name, subject, body, status, total_recipients) 
        VALUES (?, ?, ?, ?, ?)
    ''', (campaign_name, subject, body, 'sending', len(recipients)))
    campaign_id = cursor.lastrowid
    conn.commit()
    
    # Send emails
    credentials = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)
    
    success_count = 0
    error_count = 0
    
    for recipient in recipients:
        try:
            # Validate recipient email
            if not recipient['email'] or not recipient['email'].strip():
                error_count += 1
                continue
                
            recipient_email = recipient['email'].strip()
            recipient_name = recipient['name'] or 'Friend'
            recipient_company = recipient.get('company', '') or 'Your Company'
            recipient_position = recipient.get('position', '') or 'Valued Customer'
            recipient_phone = recipient.get('phone', '') or ''
            
            # Validate email format
            if '@' not in recipient_email or '.' not in recipient_email:
                error_count += 1
                continue
            
            # Enhanced personalization - replace multiple variables
            personalized_subject = subject
            personalized_body = body
            
            personalization_vars = {
                '{name}': recipient_name,
                '{email}': recipient_email,
                '{company}': recipient_company,
                '{position}': recipient_position,
                '{phone}': recipient_phone,
                '{first_name}': recipient_name.split()[0] if recipient_name else 'Friend',
                '{last_name}': recipient_name.split()[-1] if len(recipient_name.split()) > 1 else '',
                '{date}': datetime.now().strftime('%B %d, %Y'),
                '{time}': datetime.now().strftime('%I:%M %p'),
                '{day}': datetime.now().strftime('%A'),
                '{month}': datetime.now().strftime('%B'),
                '{year}': datetime.now().strftime('%Y')
            }
            
            for var, value in personalization_vars.items():
                personalized_subject = personalized_subject.replace(var, value)
                personalized_body = personalized_body.replace(var, value)
            
            # Create message
            message = create_message(
                sender='me',
                to=recipient_email,
                subject=personalized_subject,
                body=personalized_body
            )
            
            # Send message
            service.users().messages().send(userId='me', body=message).execute()
            
            # Log sent email
            log_sent_email(campaign_id, recipient_email, recipient_name, 'sent')
            
            success_count += 1
            
            # Anti-spam delay (30-60 seconds random)
            delay = random.randint(SPAM_PREVENTION['min_delay'], SPAM_PREVENTION['max_delay'])
            print(f"DEBUG: Waiting {delay} seconds before next email...")
            time.sleep(delay)
            
        except HttpError as error:
            error_message = str(error)
            log_sent_email(campaign_id, recipient.get("email", "unknown"), recipient.get("name", ""), 'error', error_message)
            flash(f'Failed to send to {recipient.get("email", "unknown")}: {error}', 'error')
            error_count += 1
        except Exception as error:
            error_message = str(error)
            log_sent_email(campaign_id, recipient.get("email", "unknown"), recipient.get("name", ""), 'error', error_message)
            flash(f'Unexpected error sending to {recipient.get("email", "unknown")}: {error}', 'error')
            error_count += 1
    
    # Update campaign completion status
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE email_campaigns 
        SET status = ?, sent_count = ?, error_count = ?, completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', ('completed', success_count, error_count, campaign_id))
    conn.commit()
    conn.close()
    
    if success_count > 0:
        flash(f'Campaign completed! Successfully sent {success_count} emails!', 'success')
    if error_count > 0:
        flash(f'{error_count} emails failed to send.', 'warning')
        
    return redirect(url_for('campaigns'))

def create_message(sender, to, subject, body):
    """Create email message"""
    message = MIMEText(body)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def log_sent_email(campaign_id, recipient_email, recipient_name, status='sent', error_message=''):
    """Log sent email to database"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sent_emails (campaign_id, recipient_email, recipient_name, status, error_message) 
        VALUES (?, ?, ?, ?, ?)
    ''', (campaign_id, recipient_email, recipient_name, status, error_message))
    conn.commit()
    conn.close()

def credentials_to_dict(credentials):
    """Convert credentials to dictionary"""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/api/recipients')
def api_recipients():
    """API endpoint to get recipients as JSON"""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email FROM recipients ORDER BY name')
    recipients = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries
    recipients_list = []
    for recipient in recipients:
        recipients_list.append({
            'id': recipient['id'],
            'name': recipient['name'],
            'email': recipient['email']
        })
    
    return jsonify(recipients_list)

@app.route('/campaigns')
def campaigns():
    """View campaigns"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all campaigns with statistics
    cursor.execute('''
        SELECT c.*, COUNT(s.id) as sent_count 
        FROM email_campaigns c 
        LEFT JOIN sent_emails s ON c.id = s.campaign_id AND s.status = 'sent'
        GROUP BY c.id 
        ORDER BY c.created_at DESC
    ''')
    campaigns = cursor.fetchall()
    
    # Calculate summary statistics
    total_sent = 0
    total_errors = 0
    active_campaigns = 0
    
    for campaign in campaigns:
        total_sent += campaign.get('sent_count', 0) or 0
        total_errors += campaign.get('error_count', 0) or 0
        if campaign.get('status') in ['sending', 'draft']:
            active_campaigns += 1
    
    conn.close()
    
    return render_template('campaigns.html', 
                         campaigns=campaigns,
                         total_sent=total_sent,
                         total_errors=total_errors,
                         active_campaigns=active_campaigns)

@app.route('/api/campaigns/<int:campaign_id>')
def api_campaign_details(campaign_id):
    """API endpoint to get campaign details"""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get campaign details
    cursor.execute('SELECT * FROM email_campaigns WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()
    
    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    
    # Get email results
    cursor.execute('''
        SELECT recipient_email, recipient_name, status, sent_at, error_message
        FROM sent_emails 
        WHERE campaign_id = ? 
        ORDER BY sent_at DESC
    ''', (campaign_id,))
    emails = cursor.fetchall()
    
    conn.close()
    
    # Convert to dictionaries
    campaign_dict = dict(campaign)
    emails_list = [dict(email) for email in emails]
    
    return jsonify({
        'campaign': campaign_dict,
        'emails': emails_list
    })

@app.route('/privacy')
def privacy():
    """Privacy Policy page"""
    return render_template('privacy.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/terms')
def terms():
    """Terms of Service page"""
    return render_template('terms.html', current_date=datetime.now().strftime('%B %d, %Y'))

@app.route('/download-template')
def download_template():
    """Download CSV template"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    # Create CSV template content
    csv_content = """name,email,company,position,phone
John Doe,john.doe@example.com,Acme Corp,Marketing Manager,+1-555-0123
Jane Smith,jane.smith@example.com,Tech Solutions,Sales Director,+1-555-0124
Bob Johnson,bob.johnson@example.com,Innovation Inc,Product Manager,+1-555-0125
Alice Brown,alice.brown@example.com,Digital Agency,Creative Director,+1-555-0126
Mike Wilson,mike.wilson@example.com,StartupXYZ,CEO,+1-555-0127"""
    
    # Create response with proper headers for file download
    
    response = Response(
        csv_content,
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=recipients_template.csv'
        }
    )
    
    return response

# Debug endpoint to check session state
@app.route('/debug-session')
def debug_session():
    """Debug endpoint to check session state"""
    session_info = {
        'credentials_exists': 'credentials' in session,
        'session_keys': list(session.keys()),
        'session_id': session.get('_id', 'No ID'),
        'redirect_uri': REDIRECT_URI,
        'secret_key_set': bool(app.secret_key),
        'cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
        'session_permanent': session.permanent
    }
    
    if 'credentials' in session:
        creds_info = session['credentials']
        session_info['credentials_keys'] = list(creds_info.keys()) if isinstance(creds_info, dict) else 'Not a dict'
        session_info['has_token'] = 'token' in creds_info if isinstance(creds_info, dict) else False
    
    return f"<h1>Session Debug Info</h1><pre>{json.dumps(session_info, indent=2)}</pre>"

if __name__ == '__main__':
    init_db()
    
    print("🚀 Gmail Emailer Web App")
    print("=" * 50)
    print("⚠️  IMPORTANT: Before running, set up Google OAuth2:")
    print("1. Go to https://console.cloud.google.com/")
    print("2. Create a new project or select existing")
    print("3. Enable Gmail API")
    print("4. Create OAuth2 credentials")
    print("5. Add your deployment URL + /callback to authorized redirect URIs")
    print("6. Set environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI")
    print("7. Configure OAuth consent screen with privacy policy and terms")
    print("8. Add yourself as a test user")
    print(f"\n🌐 Redirect URI should be: {REDIRECT_URI}")
    print(f"🌐 Privacy Policy: {REDIRECT_URI.replace('/callback', '/privacy')}")
    print(f"🌐 Terms of Service: {REDIRECT_URI.replace('/callback', '/terms')}")
    print(f"🌐 Server will run on port: {os.environ.get('PORT', 5000)}")
    
    # Debug session configuration
    print(f"\n🔧 SESSION CONFIGURATION:")
    print(f"SECRET_KEY: {'SET' if os.environ.get('SECRET_KEY') else 'NOT SET'}")
    print(f"SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE')}")
    print(f"SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY')}")
    print(f"SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    
    # Railway automatically provides PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true') 