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
import google.oauth2.credentials
import google.auth.transport.requests
import threading
import queue
import time
from datetime import datetime, timedelta

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
        CREATE TABLE IF NOT EXISTS recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            company TEXT,
            position TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        prompt='consent'  # Force consent to ensure refresh token
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
        
        # Debug the credentials object
        print(f"DEBUG: Flow credentials token: {bool(credentials.token)}")
        print(f"DEBUG: Flow credentials refresh_token: {bool(credentials.refresh_token)}")
        print(f"DEBUG: Flow credentials refresh_token value: '{credentials.refresh_token}'")
        
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': 'https://oauth2.googleapis.com/token',
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'scopes': list(credentials.scopes) if credentials.scopes else SCOPES
        }
        session.permanent = True
        
        # Debug what we actually saved
        saved_creds = session['credentials']
        print(f"DEBUG: Saved token: {bool(saved_creds.get('token'))}")
        print(f"DEBUG: Saved refresh_token: {bool(saved_creds.get('refresh_token'))}")
        print(f"DEBUG: Saved refresh_token value: '{saved_creds.get('refresh_token')}'")
        print(f"DEBUG: Saved client_id: {bool(saved_creds.get('client_id'))}")
        print(f"DEBUG: Saved client_secret: {bool(saved_creds.get('client_secret'))}")
        
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
    """View and manage recipients"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all recipients
    cursor.execute('''
        SELECT * FROM recipients 
        ORDER BY name
    ''')
    recipients = cursor.fetchall()
    
    conn.close()
    
    return render_template('recipients.html', recipients=recipients)

@app.route('/recipients/add', methods=['GET', 'POST'])
def add_recipient():
    """Add new recipient"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        company = request.form.get('company', '').strip()
        position = request.form.get('position', '').strip()
        phone = request.form.get('phone', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO recipients (name, email, company, position, phone) 
                VALUES (?, ?, ?, ?, ?)
            ''', (name, email, company, position, phone))
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
                        INSERT INTO recipients (name, email, company, position, phone) 
                        VALUES (?, ?, ?, ?, ?)
                    ''', (name, email, company, position, phone))
                    added_count += 1
                except sqlite3.IntegrityError:
                    skipped_count += 1  # Skip duplicates
            
            conn.commit()
            conn.close()
            
            if added_count > 0:
                flash(f'Added {added_count} recipients! Skipped {skipped_count} invalid/duplicate entries.', 'success')
            else:
                flash(f'No valid recipients found in CSV. Skipped {skipped_count} entries.', 'warning')
                
        except Exception as e:
            flash(f'Error processing CSV file: {str(e)}', 'error')
    else:
        flash('Please upload a CSV file!', 'error')
    
    return redirect(url_for('recipients'))

@app.route('/recipients/delete/<int:recipient_id>', methods=['POST'])
def delete_recipient(recipient_id):
    """Delete a recipient"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM recipients WHERE id = ?', (recipient_id,))
    conn.commit()
    conn.close()
    
    flash('Recipient deleted successfully!', 'success')
    return redirect(url_for('recipients'))

@app.route('/compose', methods=['GET', 'POST'])
def compose():
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    preselected_recipients = []
    
    # Handle POST request with preselected recipients
    if request.method == 'POST':
        preselected_ids = request.form.getlist('preselected_recipients')
        if preselected_ids:
            placeholders = ','.join(['?' for _ in preselected_ids])
            cursor = get_db().cursor() # Get a new cursor for the compose page
            cursor.execute(f'SELECT * FROM recipients WHERE id IN ({placeholders})', preselected_ids)
            preselected_recipients = cursor.fetchall()
    
    return render_template('compose.html', preselected_recipients=preselected_recipients)

def get_gmail_service():
    """Get Gmail service with automatic token refresh"""
    try:
        if 'credentials' not in session:
            raise Exception("No credentials in session")
        
        # Get credentials from session
        creds_data = session['credentials']
        print(f"DEBUG: Credentials data keys: {list(creds_data.keys())}")
        
        # Validate required fields
        token = creds_data.get('token')
        refresh_token = creds_data.get('refresh_token')
        client_id = creds_data.get('client_id')
        client_secret = creds_data.get('client_secret')
        
        print(f"DEBUG: token exists: {bool(token)}, length: {len(token) if token else 0}")
        print(f"DEBUG: refresh_token exists: {bool(refresh_token)}, length: {len(refresh_token) if refresh_token else 0}")
        print(f"DEBUG: client_id exists: {bool(client_id)}")
        print(f"DEBUG: client_secret exists: {bool(client_secret)}")
        
        if not token or not token.strip():
            raise Exception("No access token in credentials")
        if not refresh_token or not refresh_token.strip():
            # If no refresh token, try to work with current token but warn user
            print("WARNING: No refresh token available - token cannot be refreshed")
            # Don't fail completely, just proceed without refresh capability
        if not client_id or not client_id.strip():
            raise Exception("No client_id in credentials")
        if not client_secret or not client_secret.strip():
            raise Exception("No client_secret in credentials")
        
        # Create credentials object
        credentials = google.oauth2.credentials.Credentials(
            token=token,
            refresh_token=refresh_token if refresh_token and refresh_token.strip() else None,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=client_id,
            client_secret=client_secret,
            scopes=creds_data.get('scopes', ['https://www.googleapis.com/auth/gmail.send'])
        )
        
        print(f"DEBUG: Credentials created successfully")
        
        # Try to refresh if we have a refresh token
        if credentials.refresh_token and credentials.refresh_token.strip():
            try:
                print("Attempting token refresh...")
                request = google.auth.transport.requests.Request()
                credentials.refresh(request)
                
                # Update session with new token
                session['credentials']['token'] = credentials.token
                print("Token refreshed successfully")
            except Exception as refresh_error:
                print(f"Token refresh failed: {refresh_error}")
                # If refresh fails, try with existing token
                pass
        else:
            print("No refresh token available - using existing access token")
        
        # Build and return service
        service = build('gmail', 'v1', credentials=credentials)
        return service
        
    except Exception as e:
        print(f"Error getting Gmail service: {str(e)}")
        
        # Only clear credentials for specific credential-related errors
        error_msg = str(e).lower()
        if any(keyword in error_msg for keyword in ['credentials', 'token', 'refresh', 'oauth', 'unauthorized']):
            print("Clearing invalid credentials due to auth error")
            if 'credentials' in session:
                del session['credentials']
            raise Exception(f"Authentication failed: {str(e)}. Please log in again.")
        else:
            # For other errors, don't clear credentials
            raise Exception(f"Gmail service error: {str(e)}. Please try again.")

@app.route('/send', methods=['POST'])
def send_email():
    """Send email using queue system"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    # Start queue processor if not running
    start_queue_processor()
    
    subject = request.form['subject']
    body = request.form['body']
    send_to = request.form['send_to']  # 'all' or 'selected'
    
    # Validate subject and body
    if not subject.strip() or not body.strip():
        flash('Subject and message cannot be empty!', 'error')
        return redirect(url_for('compose'))
    
    # Get recipients
    conn = get_db()
    cursor = conn.cursor()
    
    if send_to == 'all':
        cursor.execute('SELECT * FROM recipients WHERE email IS NOT NULL AND email != ""')
    else:
        recipient_ids = request.form.getlist('recipient_ids')
        if not recipient_ids:
            flash('No recipients selected!', 'error')
            conn.close()
            return redirect(url_for('compose'))
        
        placeholders = ','.join(['?' for _ in recipient_ids])
        cursor.execute(f'SELECT * FROM recipients WHERE id IN ({placeholders}) AND email IS NOT NULL AND email != ""', 
                     recipient_ids)
    
    recipients = cursor.fetchall()
    
    if not recipients:
        flash('No valid recipients found!', 'error')
        conn.close()
        return redirect(url_for('compose'))
    
    # Create campaign with queued status
    campaign_name = f"Campaign {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    cursor.execute('''
        INSERT INTO email_campaigns (name, subject, body, status, total_recipients) 
        VALUES (?, ?, ?, ?, ?)
    ''', (campaign_name, subject, body, 'queued', len(recipients)))
    campaign_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Get credentials for queue processing
    credentials_data = session['credentials']
    
    # Add all emails to queue
    for recipient in recipients:
        # Access SQLite row data properly
        recipient_email = recipient['email'] if recipient['email'] else ''
        recipient_name = recipient['name'] if recipient['name'] else 'Friend'
        recipient_company = recipient['company'] if recipient['company'] else 'Your Company'
        recipient_position = recipient['position'] if recipient['position'] else 'Valued Customer'
        recipient_phone = recipient['phone'] if recipient['phone'] else ''
        
        # Skip invalid emails
        if not recipient_email or not recipient_email.strip() or '@' not in recipient_email:
            continue
        
        # Create personalization variables
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
        
        # Create email task
        email_task = {
            'campaign_id': campaign_id,
            'recipient': dict(recipient),
            'subject': subject,
            'body': body,
            'personalization_vars': personalization_vars,
            'credentials': credentials_data
        }
        
        # Add to queue
        email_queue.put(email_task)
    
    flash(f'Email campaign queued! {len(recipients)} emails added to queue. Processing will begin immediately and respect the 50 emails/hour limit.', 'success')
    return redirect(url_for('campaigns', show_campaign=campaign_id))

def create_message(sender, to, subject, body):
    """Create email message"""
    # Create multipart message to support both text and HTML
    message = MIMEMultipart('alternative')
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    
    # Check if body contains HTML tags
    if '<' in body and '>' in body:
        # HTML content
        html_part = MIMEText(body, 'html')
        message.attach(html_part)
    else:
        # Plain text content
        text_part = MIMEText(body, 'plain')
        message.attach(text_part)
    
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

def credentials_from_dict(credentials_dict):
    """Convert dictionary to credentials with validation"""
    required_fields = ['token', 'token_uri', 'client_id', 'client_secret']
    
    for field in required_fields:
        if field not in credentials_dict or credentials_dict[field] is None:
            raise ValueError(f"Missing required credential field: {field}")
    
    return Credentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict.get('refresh_token'),
        token_uri=credentials_dict['token_uri'],
        client_id=credentials_dict['client_id'],
        client_secret=credentials_dict['client_secret'],
        scopes=credentials_dict.get('scopes', SCOPES)
    )

@app.route('/api/recipients')
def api_recipients():
    """API endpoint to get recipients as JSON"""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, email, company, position, phone
        FROM recipients 
        ORDER BY name
    ''')
    recipients = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries
    recipients_list = []
    for recipient in recipients:
        recipients_list.append({
            'id': recipient['id'],
            'name': recipient['name'],
            'email': recipient['email'],
            'company': recipient['company'],
            'position': recipient['position'],
            'phone': recipient['phone']
        })
    
    return jsonify(recipients_list)

@app.route('/api/recipients/bulk-delete', methods=['POST'])
def bulk_delete_recipients():
    try:
        data = request.get_json()
        recipient_ids = data.get('recipient_ids', [])
        
        if not recipient_ids:
            return jsonify({'success': False, 'message': 'No recipients selected'})
        
        # Delete recipients
        placeholders = ','.join(['?' for _ in recipient_ids])
        cursor = get_db().cursor() # Get a new cursor for the compose page
        cursor.execute(f'DELETE FROM recipients WHERE id IN ({placeholders})', recipient_ids)
        get_db().commit() # Commit the transaction
        
        return jsonify({'success': True, 'message': f'Deleted {len(recipient_ids)} recipients'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

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
        # Use bracket notation for SQLite Row objects
        total_sent += campaign['sent_count'] or 0
        total_errors += campaign['error_count'] or 0
        if campaign['status'] in ['sending', 'draft']:
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

@app.route('/api/campaigns/<int:campaign_id>/progress')
def api_campaign_progress(campaign_id):
    """Get real-time campaign progress"""
    try:
        progress = get_campaign_progress(campaign_id)
        if not progress:
            return jsonify({'error': 'Campaign not found'}), 404
        
        return jsonify(progress)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/campaigns/<int:campaign_id>/download-csv')
def download_campaign_csv(campaign_id):
    """Download campaign results as CSV"""
    if 'credentials' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get campaign details
    cursor.execute('SELECT * FROM email_campaigns WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()
    
    if not campaign:
        flash('Campaign not found!', 'error')
        conn.close()
        return redirect(url_for('campaigns'))
    
    # Get email results
    cursor.execute('''
        SELECT recipient_email, recipient_name, status, sent_at, error_message
        FROM sent_emails 
        WHERE campaign_id = ? 
        ORDER BY sent_at DESC
    ''', (campaign_id,))
    emails = cursor.fetchall()
    
    conn.close()
    
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Recipient Name', 'Email', 'Status', 'Sent At', 'Error Message'])
    
    # Write data
    for email in emails:
        writer.writerow([
            email['recipient_name'] or '',
            email['recipient_email'] or '',
            email['status'] or '',
            email['sent_at'] or '',
            email['error_message'] or ''
        ])
    
    # Prepare response
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=campaign_{campaign_id}_results.csv'
        }
    )

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
        session_info['has_refresh_token'] = 'refresh_token' in creds_info if isinstance(creds_info, dict) else False
        session_info['has_client_id'] = 'client_id' in creds_info if isinstance(creds_info, dict) else False
        session_info['has_client_secret'] = 'client_secret' in creds_info if isinstance(creds_info, dict) else False
    
    return f"<h1>Session Debug Info</h1><pre>{json.dumps(session_info, indent=2)}</pre>"

@app.route('/force-reauth')
def force_reauth():
    """Force re-authentication by clearing session"""
    session.clear()
    flash('Session cleared. Please log in again.', 'info')
    return redirect(url_for('index'))

# Email queue and processing
email_queue = queue.Queue()
queue_processor_running = False
queue_lock = threading.Lock()

def start_queue_processor():
    """Start the background email queue processor"""
    global queue_processor_running
    
    with queue_lock:
        if queue_processor_running:
            return
        queue_processor_running = True
    
    def process_queue():
        global queue_processor_running
        print("Email queue processor started")
        
        while queue_processor_running:
            try:
                # Check if we can send emails (hourly limit)
                if can_send_email():
                    try:
                        # Get next email from queue (timeout after 10 seconds)
                        email_task = email_queue.get(timeout=10)
                        
                        # Process the email
                        process_email_task(email_task)
                        
                        # Mark task as done
                        email_queue.task_done()
                        
                        # Wait between emails (30-60 seconds)
                        delay = random.randint(30, 60)
                        print(f"Queue processor waiting {delay} seconds...")
                        time.sleep(delay)
                        
                    except queue.Empty:
                        # No emails in queue, wait a bit
                        time.sleep(5)
                        continue
                else:
                    # Can't send emails due to hourly limit, wait 5 minutes
                    print("Hourly limit reached, queue processor waiting 5 minutes...")
                    time.sleep(300)  # 5 minutes
                    
            except Exception as e:
                print(f"Error in queue processor: {str(e)}")
                time.sleep(10)  # Wait before retrying
        
        print("Email queue processor stopped")
    
    # Start the processor in a background thread
    processor_thread = threading.Thread(target=process_queue, daemon=True)
    processor_thread.start()

def can_send_email():
    """Check if we can send an email based on hourly limit"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM sent_emails 
            WHERE sent_at >= datetime('now', '-1 hour') AND status = 'sent'
        ''')
        emails_this_hour = cursor.fetchone()[0]
        conn.close()
        
        return emails_this_hour < SPAM_PREVENTION['max_per_hour']
    except Exception as e:
        print(f"Error checking email limit: {str(e)}")
        return False

def process_email_task(email_task):
    """Process a single email task from the queue"""
    try:
        campaign_id = email_task['campaign_id']
        recipient = email_task['recipient']
        subject = email_task['subject']
        body = email_task['body']
        personalization_vars = email_task['personalization_vars']
        
        # Update campaign status to show it's being processed
        update_campaign_status(campaign_id, 'sending')
        
        # Get Gmail service
        credentials_data = email_task['credentials']
        service = create_gmail_service_from_data(credentials_data)
        
        # Personalize content
        personalized_subject = subject
        personalized_body = body
        
        for var, value in personalization_vars.items():
            personalized_subject = personalized_subject.replace(var, value)
            personalized_body = personalized_body.replace(var, value)
        
        # Create and send message
        message = create_message(
            sender='me',
            to=recipient['email'],
            subject=personalized_subject,
            body=personalized_body
        )
        
        service.users().messages().send(userId='me', body=message).execute()
        
        # Log successful send
        log_sent_email(campaign_id, recipient['email'], recipient['name'], 'sent')
        
        print(f"Email sent successfully to {recipient['email']}")
        
        # Check if campaign is complete
        check_campaign_completion(campaign_id)
        
    except Exception as e:
        # Log failed send
        error_message = str(e)
        log_sent_email(campaign_id, recipient['email'], recipient['name'], 'error', error_message)
        print(f"Failed to send email to {recipient['email']}: {error_message}")
        
        # Check if campaign is complete
        check_campaign_completion(campaign_id)

def create_gmail_service_from_data(credentials_data):
    """Create Gmail service from stored credentials data"""
    credentials = google.oauth2.credentials.Credentials(
        token=credentials_data['token'],
        refresh_token=credentials_data.get('refresh_token'),
        token_uri='https://oauth2.googleapis.com/token',
        client_id=credentials_data['client_id'],
        client_secret=credentials_data['client_secret'],
        scopes=credentials_data.get('scopes', ['https://www.googleapis.com/auth/gmail.send'])
    )
    
    # Try to refresh token if needed
    if credentials.refresh_token and credentials.expired:
        try:
            request = google.auth.transport.requests.Request()
            credentials.refresh(request)
        except Exception as e:
            print(f"Token refresh failed in queue processor: {e}")
    
    return build('gmail', 'v1', credentials=credentials)

def update_campaign_status(campaign_id, status):
    """Update campaign status"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE email_campaigns 
            SET status = ? 
            WHERE id = ?
        ''', (status, campaign_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating campaign status: {str(e)}")

def get_campaign_progress(campaign_id):
    """Get real-time campaign progress"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get campaign info
        cursor.execute('SELECT * FROM email_campaigns WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        
        if not campaign:
            return None
        
        # Get sent/error counts
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN status = 'sent' THEN 1 END) as sent_count,
                COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count,
                COUNT(*) as total_processed
            FROM sent_emails 
            WHERE campaign_id = ?
        ''', (campaign_id,))
        
        counts = cursor.fetchone()
        conn.close()
        
        return {
            'campaign': dict(campaign),
            'sent_count': counts['sent_count'] or 0,
            'error_count': counts['error_count'] or 0,
            'total_processed': counts['total_processed'] or 0,
            'remaining': (campaign['total_recipients'] or 0) - (counts['total_processed'] or 0),
            'queue_size': email_queue.qsize()
        }
        
    except Exception as e:
        print(f"Error getting campaign progress: {str(e)}")
        return None

def check_campaign_completion(campaign_id):
    """Check if a campaign is complete and update its status"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get campaign info
        cursor.execute('SELECT * FROM email_campaigns WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        
        if not campaign:
            conn.close()
            return
        
        # Get counts
        cursor.execute('''
            SELECT 
                COUNT(CASE WHEN status = 'sent' THEN 1 END) as sent_count,
                COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count,
                COUNT(*) as total_processed
            FROM sent_emails 
            WHERE campaign_id = ?
        ''', (campaign_id,))
        
        counts = cursor.fetchone()
        total_processed = counts['total_processed'] or 0
        sent_count = counts['sent_count'] or 0
        error_count = counts['error_count'] or 0
        
        # Check if campaign is complete
        if total_processed >= campaign['total_recipients']:
            # Determine final status
            if error_count == 0:
                final_status = 'completed'
            elif sent_count == 0:
                final_status = 'failed'
            else:
                final_status = 'completed'  # Partial success still counts as completed
            
            # Update campaign
            cursor.execute('''
                UPDATE email_campaigns 
                SET status = ?, sent_count = ?, error_count = ?, completed_at = datetime('now')
                WHERE id = ?
            ''', (final_status, sent_count, error_count, campaign_id))
            conn.commit()
            
            print(f"Campaign {campaign_id} completed: {sent_count} sent, {error_count} errors")
        else:
            # Update counts but keep sending status
            cursor.execute('''
                UPDATE email_campaigns 
                SET sent_count = ?, error_count = ?
                WHERE id = ?
            ''', (sent_count, error_count, campaign_id))
            conn.commit()
        
        conn.close()
        
    except Exception as e:
        print(f"Error checking campaign completion: {str(e)}")

if __name__ == '__main__':
    init_db()
    start_queue_processor()  # Start the email queue processor
    
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
    print("\n📧 EMAIL QUEUE PROCESSOR: Started")
    print("📧 Queue will process 50 emails per hour with 30-60 second delays")
    
    # Debug session configuration
    print(f"\n🔧 SESSION CONFIGURATION:")
    print(f"SECRET_KEY: {'SET' if os.environ.get('SECRET_KEY') else 'NOT SET'}")
    print(f"SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE')}")
    print(f"SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY')}")
    print(f"SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    
    # Railway automatically provides PORT environment variable
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('DEBUG', 'False').lower() == 'true') 