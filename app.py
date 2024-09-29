#V6 with email alert, dexcom integration, dinamic map, optional sms,
import uuid
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import json
import os
import re
from dotenv import load_dotenv
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import urllib.parse
import requests
from deep_translator import GoogleTranslator
import time
import psycopg2
from psycopg2.extras import RealDictCursor
from pydexcom import Dexcom
from datetime import date
from email.message import EmailMessage
from contextlib import closing
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from database import init_db, get_user, get_user_by_id, update_user


load_dotenv()

#Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_fallback_secret_key')
oauth = OAuth(app)
CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_fallback_secret_key')  # Replace with a real secret key
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_ADDRESS')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_ADDRESS')

# Infobip configuration
INFOBIP_API_KEY = os.getenv('INFOBIP_API_KEY')
INFOBIP_BASE_URL = os.getenv('INFOBIP_BASE_URL')
INFOBIP_SENDER = os.getenv('INFOBIP_SENDER')

# Ensure the base URL has a scheme
if INFOBIP_BASE_URL and not INFOBIP_BASE_URL.startswith(('http://', 'https://')):
    INFOBIP_BASE_URL = f'https://{INFOBIP_BASE_URL}'

#Configuracion de la base de datos
DATABASE_URL = os.getenv('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn, conn.cursor(cursor_factory=RealDictCursor)

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                emergency_message TEXT,
                emergency_contacts TEXT,
                alert_message TEXT,
                share_token VARCHAR(36) UNIQUE NOT NULL,
                is_diabetic BOOLEAN DEFAULT FALSE,
                uses_dexcom BOOLEAN DEFAULT FALSE,
                dexcom_username VARCHAR(80),
                dexcom_password VARCHAR(120)
            )
        ''')
        conn.commit()
        print("Database initialized successfully")
    except psycopg2.Error as e:
        print(f"An error occurred while initializing the database: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()


def create_email_message(subject, body, to_email):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email
    return msg

def send_email(msg):
    try:
        logging.debug("Attempting to send email")
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
        logging.debug("Email sent successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

@app.route('/about', methods=['GET', 'POST'])
def about():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        subject = "New Contact Form Submission"
        body = f"Name: {name}\nEmail: {email}\nMessage: {message}"
        to_email = app.config['MAIL_DEFAULT_SENDER']
        
        msg = create_email_message(subject, body, to_email)
        
        if send_email(msg):
            flash('Thank you for your message! We\'ll get back to you soon.', 'success')
        else:
            flash('An error occurred while sending your message. Please try again later.', 'error')
        
    return render_template('about.html', dyslexia_friendly=session.get('dyslexia_friendly', False))


google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_basic'
    },
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    token_url='https://oauth2.googleapis.com/token',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorized', _external=True)
    app.logger.debug(f"Initiating Google login. Redirect URI: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)

# In the authorized route, add these lines at the beginning:
app.logger.debug(f"Google client config: {google.client_kwargs}")
app.logger.debug(f"Google server metadata: {google.server_metadata}")

@app.route('/login/google/authorized')
def authorized():
    try:
        app.logger.debug("Entering authorized route")
        token = google.authorize_access_token()
        app.logger.debug(f"Received token: {token}")
        
        resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
        app.logger.debug(f"Userinfo response: {resp.json()}")
        
        if resp.ok:
            user_info = resp.json()
            email = user_info['email']
            app.logger.debug(f"Attempting to get or create user for email: {email}")
            
            # Try to get the user first
            user = get_user(email)
            app.logger.debug(f"Result of get_user: {user}")
            
            if not user:
                app.logger.debug(f"User not found, attempting to create new user")
                # If user doesn't exist, create a new one
                share_token = str(uuid.uuid4())
                try:
                    create_user(email, 'google_user', share_token)
                    app.logger.debug(f"New user created successfully")
                    user = get_user(email)
                    app.logger.debug(f"Fetched newly created user: {user}")
                except ValueError as e:
                    app.logger.error(f"Failed to create new user: {str(e)}")
                    flash('Failed to create new user account.', 'error')
                    return redirect(url_for('login'))
            
            if user:
                session['user_id'] = user['id']
                app.logger.debug(f"User logged in successfully. User ID: {user['id']}")
                flash('Logged in successfully with Google.', 'success')
                return redirect(url_for('dashboard'))
            else:
                app.logger.error(f"Failed to retrieve or create user for email: {email}")
                flash('Failed to retrieve or create user account.', 'error')
                return redirect(url_for('login'))
        else:
            app.logger.error(f"Failed to fetch user info: {resp.text}")
            flash('Failed to get user info from Google.', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Error in Google authorization: {str(e)}", exc_info=True)
        flash('An error occurred during Google login. Please try again.', 'error')
        return redirect(url_for('login'))


#Env variables
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
RECIPIENT_EMAILS = os.getenv('RECIPIENT_EMAILS').split(',')
EMERGENCY_MESSAGE = "My name is Irene and I have type1 diabetes. If you see that I am not doing well, probably I am having a low glucose episode. I always carry gels in case this happens. They are located in the right side of my backpack. Thank you so much, you are literally saving my life! :)"
COUNTRY_LANGUAGES = {
    'ES': ['es'],  # Spain
    'BE': ['nl', 'fr', 'de'],  # Belgium
    'CH': ['de', 'fr', 'it'],  # Switzerland
    'PL': ['pl']  # Poland
}


LANGUAGE_INFO = {
    'bg': {'name': 'Български', 'flag': '🇧🇬'},  # Bulgarian
    'hr': {'name': 'Hrvatski', 'flag': '🇭🇷'},  # Croatian
    'cs': {'name': 'Čeština', 'flag': '🇨🇿'},  # Czech
    'da': {'name': 'Dansk', 'flag': '🇩🇰'},  # Danish
    'nl': {'name': 'Nederlands', 'flag': '🇳🇱'},  # Dutch
    'en': {'name': 'English', 'flag': '🇬🇧'},  # English
    'et': {'name': 'Eesti', 'flag': '🇪🇪'},  # Estonian
    'fi': {'name': 'Suomi', 'flag': '🇫🇮'},  # Finnish
    'fr': {'name': 'Français', 'flag': '🇫🇷'},  # French
    'de': {'name': 'Deutsch', 'flag': '🇩🇪'},  # German
    'el': {'name': 'Ελληνικά', 'flag': '🇬🇷'},  # Greek
    'hu': {'name': 'Magyar', 'flag': '🇭🇺'},  # Hungarian
    'ga': {'name': 'Gaeilge', 'flag': '🇮🇪'},  # Irish
    'it': {'name': 'Italiano', 'flag': '🇮🇹'},  # Italian
    'lv': {'name': 'Latviešu', 'flag': '🇱🇻'},  # Latvian
    'lt': {'name': 'Lietuvių', 'flag': '🇱🇹'},  # Lithuanian
    'mt': {'name': 'Malti', 'flag': '🇲🇹'},  # Maltese
    'pl': {'name': 'Polski', 'flag': '🇵🇱'},  # Polish
    'pt': {'name': 'Português', 'flag': '🇵🇹'},  # Portuguese
    'ro': {'name': 'Română', 'flag': '🇷🇴'},  # Romanian
    'sk': {'name': 'Slovenčina', 'flag': '🇸🇰'},  # Slovak
    'sl': {'name': 'Slovenščina', 'flag': '🇸🇮'},  # Slovenian
    'es': {'name': 'Español', 'flag': '🇪🇸'},  # Spanish
    'sv': {'name': 'Svenska', 'flag': '🇸🇪'},  # Swedish
}


translations = {
    'en': {
        'title': 'Emergency Alert System',
        'subtitle': '⚠️',
        'description': "It does not matter who you are, your circumstances, or what you need help with. We all need assistance at some point, and that is why I created this web.",
        'how_it_works': 'How it works:',
        'step1': 'Register for an account.',
        'step2': 'Set up your emergency information and contacts.',
        'step3': 'In case you have diabetes and a dexcom sensor, enter your credentials.',
        'step4': 'Get a shareable emergency link on your view dashboard section.',
        'step5': 'In case of emergency, your link can be accessed to display vital information and alert your contacts.',
        'login': 'Login',
        'register': 'Register',
        'home': 'Home',
        'username': 'Username',
        'password': 'Password',
        'confirm_password': 'Confirm Password',
        'dont_have_account': "Don't have an account? Register",
        'already_have_account': "Already have an account? Login",
        'sign_in_with_google': 'Sign in with Google',
        'footer_made_with': 'Made with',
        'footer_for': '© 2024 IreAV. All rights reserved.'
    },
    'es': {
        'title': 'Sistema de Alerta de Emergencia',
        'subtitle': '⚠️',
        'description': "No importa quién seas, tus circunstancias o con que necesitas ayuda. Todos necesitamos asistencia en algún momento, y por eso he creado esta web.",
        'how_it_works': 'Cómo funciona:',
        'step1': 'Regístrate para obtener una cuenta.',
        'step2': 'Configura tu información de emergencia y contactos.',
        'step3': 'En caso de que tengas diabetes y un sensor Dexcom, ingresa tu usuario y contraseña.',
        'step4': 'Obtén el enlace de emergencia para compartir.',
        'step5': 'En caso de emergencia, se puede acceder a tu enlace para mostrar información vital y alertar a tus contactos.',
        'login': 'Iniciar sesión',
        'register': 'Registrarse',
        'home': 'Inicio',
        'username': 'Nombre de usuario',
        'password': 'Contraseña',
        'confirm_password': 'Confirmar contraseña',
        'dont_have_account': '¿No tienes una cuenta? Regístrate',
        'already_have_account': '¿Ya tienes una cuenta? Inicia sesión',
        'sign_in_with_google': 'Iniciar sesión con Google',
        'footer_made_with': 'Hecho con',
        'footer_for': '© 2024 IreAV. Todos los derechos reservados.'
    }
}


@app.route('/change_language/<lang>')
def change_language(lang):
    session['lang'] = lang
    return redirect(request.referrer or url_for('index'))


def get_google_maps_link(lat, lon):
    base_url = "https://www.google.com/maps"
    query = f"{lat},{lon}"
    return f"{base_url}?q={urllib.parse.quote(query)}"


def get_country_code(lat, lon):
    url = f"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}"
    headers = {
        'User-Agent': 'EmergencyAlertApp/1.0'
    }
    try:
        time.sleep(1)  # Add a 1-second delay to respect rate limits
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        country_code = data.get('address', {}).get('country_code', '').upper()
        logging.info(f"Detected country code: {country_code}")
        return country_code
    except Exception as e:
        logging.error(f"Error getting country code: {str(e)}")
        return None
    

def translate_message(message, target_languages):
    translations = {'en': message}  # Always include English
    logging.info(f"Translating message to languages: {target_languages}")
    for lang in target_languages:
        if lang != 'en':
            try:
                translated = GoogleTranslator(source='en', target=lang).translate(message)
                translations[lang] = translated
                logging.info(f"Translated to {lang}: {translated[:50]}...")  # Log first 50 chars
            except Exception as e:
                logging.error(f"Translation error for {lang}: {str(e)}")
    return translations



def create_user(username, password, share_token):
    conn, cur = get_db_connection()
    try:
        cur.execute(
            "INSERT INTO users (username, password, share_token) VALUES (%s, %s, %s)",
            (username, password, share_token)
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError("Username already exists")
    except psycopg2.Error as e:
        conn.rollback()
        raise ValueError(f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()


def get_user(username):
    conn, cur = get_db_connection()
    try:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user:
            # Convert the result to a dictionary for easier access
            user_dict = dict(user)
            return user_dict
        return None
    except Exception as e:
        print(f"Error fetching user data: {e}")
        return None
    finally:
        cur.close()
        conn.close()


def get_user_by_id(user_id):
    conn, cur = get_db_connection()
    try:
        cur.execute("SELECT id, username, emergency_message, emergency_contacts, emergency_contact_phone, is_diabetic, alert_message, is_diabetic, uses_dexcom, dexcom_username, dexcom_password, enable_sms_alerts FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        conn.close()


def update_user(user_id, emergency_message, emergency_contacts, emergency_contact_phones, alert_message, is_diabetic, uses_dexcom, dexcom_username, dexcom_password, enable_sms_alerts):
    conn, cur = get_db_connection()
    try:
        query = """
        UPDATE users SET 
            emergency_message = %s, 
            emergency_contacts = %s, 
            emergency_contact_phone = %s,
            alert_message = %s,
            is_diabetic = %s,
            uses_dexcom = %s,
            dexcom_username = %s,
            dexcom_password = %s,
            enable_sms_alerts = %s
        WHERE id = %s
        """
        cur.execute(query, (
            emergency_message,
            emergency_contacts, 
            emergency_contact_phones,
            alert_message,
            is_diabetic,
            uses_dexcom,
            dexcom_username,
            dexcom_password,
            enable_sms_alerts,
            user_id
        ))
        conn.commit()
        logging.info(f"User {user_id} updated successfully")
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating user {user_id}: {str(e)}")
        raise
    finally:
        cur.close()
        conn.close()


def get_dexcom_data(username, password):
    try:
        logging.debug(f"Attempting to create Dexcom instance for user: {username}")
        
        dexcom = Dexcom(username=username, password=password, ous=True)
        
        logging.debug("Dexcom instance created successfully. Fetching glucose readings.")
        glucose_readings = dexcom.get_glucose_readings(minutes=60)

        formatted_readings = []
        for bg_value in glucose_readings:
            formatted_readings.append({
                'time': bg_value.datetime.strftime('%Y-%m-%d %H:%M:%S'),
                'value': bg_value.value,
                'trend': bg_value.trend_arrow
            })

        logging.info(f"Successfully fetched {len(formatted_readings)} Dexcom readings")
        return formatted_readings, None
    except AttributeError as e:
        logging.error(f"AttributeError in get_dexcom_data: {str(e)}", exc_info=True)
        return None, f"The Pydexcom library interface has changed. Error: {str(e)}"
    except Exception as e:
        logging.error(f"Error in get_dexcom_data: {str(e)}", exc_info=True)
        return None, str(e)



@app.route('/')
def index():
    dyslexia_friendly = session.get('dyslexia_friendly', False)

    lang = request.args.get('lang', 'en')
    if lang not in translations:
        lang = 'en'
    user = {
        'is_diabetic': True,
        'uses_dexcom': False
    }
    return render_template('index.html', dyslexia_friendly=dyslexia_friendly, t=translations[lang], lang=lang)


@app.route('/toggle_dyslexia_friendly')
def toggle_dyslexia_friendly():
    session['dyslexia_friendly'] = not session.get('dyslexia_friendly', False)
    return redirect(request.referrer or url_for('index'))

def generate_emergency_token():
    return str(uuid.uuid4())

def update_user_emergency_token(user_id, token):
    conn, cur = get_db_connection()
    try:
        cur.execute("UPDATE users SET emergency_token = %s WHERE id = %s", (token, user_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()

def get_user_by_emergency_token(token):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE emergency_token = %s", (token,))
            user = cur.fetchone()
        return user
    finally:
        conn.close()

@app.route('/emergency_contact/<token>')
def emergency_contact(token):
    user = get_user_by_emergency_token(token)
    if not user:
        return "Invalid or expired emergency link", 404
    
    return render_template('emergency_contact.html',
                        user=user, 
                        is_emergency_contact=True,
                        emergency_token=token)


@app.route('/emergency')
def emergency():
    username = request.args.get('username')
    user = get_user(username)
    if not user:
        return "User not found", 404
    
    show_glucose_section = False
    glucose_data = None
    
    if user.get('is_diabetic'):
        show_glucose_section = True
        if user.get('uses_dexcom'):
            dexcom_username = user.get('dexcom_username')
            dexcom_password = user.get('dexcom_password')
            if dexcom_username and dexcom_password:
                logging.debug(f"Attempting to fetch Dexcom data for user {user['username']}")
                dexcom_readings, error = get_dexcom_data(dexcom_username, dexcom_password)
                if error:
                    flash(f'Error fetching Dexcom data: {error}', 'error')
                    logging.error(f"Dexcom data fetch error for user {user['username']}: {error}")
                elif dexcom_readings:
                    glucose_data = dexcom_readings[-12:]
            else:
                flash('Dexcom credentials are not set. Please update your profile.', 'warning')

    return render_template('emergency.html', 
                            user=user, 
                            show_glucose_section=show_glucose_section,
                            glucose_data=glucose_data,
                            is_emergency_contact=False)



@app.route('/get_emergency_info', methods=['POST'])
def get_emergency_info():
    try:
        data = request.json
        token = data.get('token')
        username = data.get('username')
        lat = data.get('latitude')
        lon = data.get('longitude')
        is_update = data.get('is_update', False)
        is_emergency_contact = token and not username

        user = get_user_by_emergency_token(token) if is_emergency_contact else get_user(username)
        if not user:
            return jsonify({"status": "error", "message": "Invalid user or token"}), 404

        emergency_message = user.get('emergency_message') or EMERGENCY_MESSAGE

        # If lat and lon are not provided in the request, get the last known location from the user data
        if lat is None or lon is None:
            lat = user.get('last_latitude')
            lon = user.get('last_longitude')
            logging.info(f"Using last known location for {username}: lat={lat}, lon={lon}")


        country_code = get_country_code(lat, lon)
        if not country_code:
            country_code = 'CH'  # Default to Switzerland if detection fails
        
        target_languages = COUNTRY_LANGUAGES.get(country_code, ['en'])
        if 'en' not in target_languages:
            target_languages.append('en')  # Always include English

        most_spoken_language = target_languages[0]

        emergency_message = user.get('emergency_message') or EMERGENCY_MESSAGE
        translations = translate_message(emergency_message, target_languages)
        
        if not translations:
            logging.error(f"Failed to get translations for languages: {target_languages}")
            return jsonify({"status": "error", "message": "Failed to get translations"}), 500

        translations_with_info = {}
        for lang, translation in translations.items():
            lang_info = LANGUAGE_INFO.get(lang, {'name': lang, 'flag': '🏳️'})
            translations_with_info[lang] = {
                'translation': translation,
                'name': lang_info['name'],
                'flag': lang_info['flag']
            }
        
        # Get Dexcom data if user is diabetic and uses Dexcom
        glucose_readings = None
        if user['is_diabetic'] and user['uses_dexcom']:
            glucose_readings, error = get_dexcom_data(user['dexcom_username'], user['dexcom_password'])
            if error:
                logging.error(f"Error fetching Dexcom data: {error}")
            else:
                logging.info(f"Successfully fetched Dexcom data: {glucose_readings}")

        # Send alert
        alert_sent = send_alert(user, lat, lon, is_update, glucose_readings)

        # Send SMS if user has opted for it
        sms_sent = False
        if user.get('enable_sms_alerts'):
            logging.info(f"SMS alerts enabled for user: {user['username']}")
            sms_sent = send_emergency_sms(user, lat, lon)
            if sms_sent:
                logging.info("SMS sent successfully")
            else:
                logging.error("Failed to send SMS")
        else:
            logging.info(f"SMS alerts not enabled for user: {user['username']}")
        
        response_data = {
            "status": "success", 
            "country_code": country_code,
            "latitude": lat,
            "longitude": lon,
            "translations": translations_with_info,
            "most_spoken_language": most_spoken_language,
            "is_diabetic": user['is_diabetic'],
            "uses_dexcom": user['uses_dexcom'],
            "glucose_readings": glucose_readings,
            "alert_sent": alert_sent,
            "status_message": " ☑️ Emergency information loaded successfully.",
            "alert_status": " ☑️ Alert sent successfully to emergency contacts." if alert_sent else "Failed to send alert to emergency contacts."
        }
        
        logging.info(f"Sending emergency info response: {response_data}")
        
        return jsonify(response_data)
    except Exception as e:
        logging.error(f"Error in get_emergency_info: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route('/update_location', methods=['POST'])
def update_location():
    data = request.json
    username = data['username']
    latitude = data['latitude']
    longitude = data['longitude']
    send_update = data.get('send_update', False)

    if not username or latitude is None or longitude is None:
        return jsonify({"status": "error", "message": "Missing required data"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"status": "error", "message": "Invalid user or token"}), 404

    if send_update:
        glucose_readings = None
        if user.get('is_diabetic') and user.get('uses_dexcom'):
            glucose_readings, error = get_dexcom_data(user.get('dexcom_username'), user.get('dexcom_password'))
            if error:
                logging.error(f"Error fetching Dexcom data for user {user['username']}: {error}")

        alert_sent = send_alert(user, latitude, longitude, is_update=True, glucose_readings=glucose_readings)

        if alert_sent:
            return jsonify({"status": "success", "message": "Location updated and alert sent"})
        else:
            return jsonify({"status": "error", "message": "Failed to send alert"}), 500
    else:
        # Only update the location without sending an alert
        return jsonify({"status": "success", "message": "Location updated"})
    

def send_emergency_sms(user, latitude, longitude):
    emergency_contact_phone = user.get('emergency_contact_phone')
    if not emergency_contact_phone:
        logging.error(f"Emergency contact phone not found for user: {user['username']}")
        return False

    alert_message = user.get('alert_message', "Emergency alert!")
    maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"

    # Construct the message, ensuring it doesn't exceed 160 characters
    message_body = f"{alert_message} Location: {maps_link}"
    if len(message_body) > 160:
        # If too long, truncate the alert message
        max_alert_length = 160 - len(f" Location: {maps_link}") - 3  # 3 for "..."
        alert_message = alert_message[:max_alert_length] + "..."
        message_body = f"{alert_message} Location: {maps_link}"

    logging.info(f"SMS message body (length {len(message_body)}): {message_body}")

    payload = {
        "messages": [
            {
                "from": INFOBIP_SENDER,
                "destinations": [{"to": emergency_contact_phone}],
                "text": message_body
            }
        ]
    }

    headers = {
        "Authorization": f"App {INFOBIP_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = requests.post(f"{INFOBIP_BASE_URL}/sms/2/text/advanced", json=payload, headers=headers)
        response.raise_for_status()
        logging.info(f"SMS sent successfully to {emergency_contact_phone} for user {user['username']}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending SMS: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            logging.error(f"Infobip API error response: {e.response.text}")
        return False


@app.route('/register', methods=['GET', 'POST'])
def register():
    dyslexia_friendly = session.get('dyslexia_friendly', False)
    lang = request.args.get('lang', 'en')
    if lang not in translations:
        lang = 'en'
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        share_token = str(uuid.uuid4())

        try:
            with closing(psycopg2.connect(DATABASE_URL)) as conn:
                with conn.cursor() as cur:
                    # Check if username already exists
                    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                    if cur.fetchone() is not None:
                        flash('Username already exists. Please choose a different one.', 'error')
                        return redirect(url_for('register'))
                    
                    # Insert new user
                    cur.execute("INSERT INTO users (username, password, share_token) VALUES (%s, %s, %s)", 
                                (username, hashed_password, share_token))
                conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash(f'Registration failed: {str(e)}', 'error')

    return render_template('register.html', lang=lang, t=translations[lang], dyslexia_friendly=dyslexia_friendly  )
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    dyslexia_friendly = session.get('dyslexia_friendly', False)
    lang = request.args.get('lang', 'en')
    if lang not in translations:
        lang = 'en'
    if request.method == 'GET':
    # Elimina los mensajes flash existentes cuando se accede de nuevo
        session.pop('_flashes', None)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
                app.logger.error(f"Login failed for user: {username}")
                if user:
                    app.logger.error(f"Stored hash: {user['password']}")
                    app.logger.error(f"Provided password hash: {generate_password_hash(password)}")
        except psycopg2.Error as e:
            flash(f'Login failed: {str(e)}', 'error')
            app.logger.error(f"Database error during login: {str(e)}")
        finally:
            cur.close()
            conn.close()
    
    return render_template('login.html', t=translations[lang], lang=lang, dyslexia_friendly=dyslexia_friendly)


@app.route('/logout')
def logout():
    session.clear() # Esto borra todos los datos de la sesion
    flash('You have been logged out. See you soon! ☺️', 'success')
    return redirect(url_for('index'))

def format_phone_numbers(phone_numbers):
    # Split the input by commas, strip whitespace, and filter out empty strings
    numbers = [num.strip() for num in phone_numbers.split(',') if num.strip()]
    
    # Ensure each number is in the correct format
    formatted_numbers = []
    for num in numbers:
        # Remove any non-digit characters except '+'
        num = ''.join(char for char in num if char.isdigit() or char == '+')
        # Ensure it starts with '+' if it doesn't already
        if not num.startswith('+'):
            num = '+' + num
        formatted_numbers.append(num)
    
    # Join the formatted numbers with commas
    return ','.join(formatted_numbers)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    dyslexia_friendly = session.get('dyslexia_friendly', False)
    user = get_user_by_id(session['user_id'])
    if user is None:
        session.pop('user_id', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    # Debug logging
    logging.debug(f"User data: {user}")
    logging.debug(f"Is diabetic: {user.get('is_diabetic')}")
    logging.debug(f"Uses Dexcom: {user.get('uses_dexcom')}")
    logging.debug(f"Dexcom username: {user.get('dexcom_username')}")
    logging.debug(f"Dexcom password: {'*****' if user.get('dexcom_password') else 'Not set'}")

    dexcom_readings = None
    if user.get('is_diabetic') and user.get('uses_dexcom'):
        dexcom_username = user.get('dexcom_username')
        dexcom_password = user.get('dexcom_password')
        if dexcom_username and dexcom_password:
            logging.debug(f"Attempting to fetch Dexcom data for user {user['username']}")
            dexcom_readings, error = get_dexcom_data(dexcom_username, dexcom_password)
            if error:
                flash(f'Error fetching Dexcom data: {error}', 'error')
                logging.error(f"Dexcom data fetch error for user {user['username']}: {error}")
            elif dexcom_readings:
                dexcom_readings = dexcom_readings[-12:]
        else:
            flash('Dexcom credentials are not set. Please update your profile.', 'warning')

    
    if request.method == 'POST':
        # Handle form submission
        emergency_message = request.form.get('emergency_message', '')
        emergency_contacts = ','.join(filter(None, [contact.strip() for contact in request.form.getlist('emergency_contacts')]))
        emergency_contact_phone = request.form.get('emergency_contact_phone', '').strip()
        alert_message = request.form.get('alert_message', '')
        is_diabetic = 'is_diabetic' in request.form
        uses_dexcom = 'uses_dexcom' in request.form
        dexcom_username = request.form.get('dexcom_username', '')
        dexcom_password = request.form.get('dexcom_password', '')
        enable_sms_alerts = 'enable_sms_alerts' in request.form

        
        # Debug logging for form submission
        logging.debug(f"Form data - is_diabetic: {is_diabetic}, uses_dexcom: {uses_dexcom}")
        logging.debug(f"Dexcom username provided: {'Yes' if dexcom_username else 'No'}")
        logging.debug(f"Dexcom password provided: {'Yes' if dexcom_password else 'No'}")
        
        try:
            update_user(user['id'], emergency_message, emergency_contacts, emergency_contact_phone, alert_message, is_diabetic, uses_dexcom, dexcom_username, dexcom_password, enable_sms_alerts)
            flash('Your information has been updated successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while updating your information: {str(e)}', 'error')
        
        return redirect(url_for('dashboard'))

    emergency_link = url_for('emergency', username=user['username'], _external=True)
    return render_template('dashboard.html', user=user, emergency_link=emergency_link, dexcom_readings=dexcom_readings)



@app.route('/get_location', methods=['POST'])
def get_location():
    data = request.json
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    if latitude is None or longitude is None:
        return jsonify({'error': 'Latitude and longitude are required'}), 400
    return jsonify({'latitude': latitude, 'longitude': longitude})


def get_or_create_emergency_token(user_id):
    conn, cur = get_db_connection()
    try:
        # First, try to retrieve an existing token
        cur.execute("SELECT emergency_token FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        
        if result and result['emergency_token']:
            return result['emergency_token']
        
        # If no token exists, create a new one
        new_token = str(uuid.uuid4())
        
        cur.execute("UPDATE users SET emergency_token = %s WHERE id = %s", (new_token, user_id))
        conn.commit()
        return new_token
    finally:
        cur.close()
        conn.close()



def get_user_by_emergency_token(token):
    conn, cur = get_db_connection()
    try:
        cur.execute("SELECT * FROM users WHERE emergency_token = %s", (token,))
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        conn.close()


def send_alert(user, lat, lon, is_update=False, glucose_readings=None):
    try:
        maps_link = get_google_maps_link(lat, lon)
        alert_message = f"{'UPDATED ' if is_update else ''}Emergency Alert: {user['username']} needs help.\n"
        if user['is_diabetic']:
            alert_message += "Type 1 Diabetes.\n"
        alert_message += f"Location: {lat}, {lon}\n"
        alert_message += f"Google Maps Link: {maps_link}\n"
        
        if glucose_readings:
            latest_reading = glucose_readings[0]
            alert_message += f"\nLatest glucose reading: {latest_reading['value']} mg/dL at {latest_reading['time']}\n"
        
        if not is_update and user['alert_message']:
            alert_message += f"\nCustom message: {user['alert_message']}"
        
        send_email_alert(alert_message, user['emergency_contacts'])
        
        logging.info(f"Alert sent successfully for user {user['username']}")
        return True
    except Exception as e:
        logging.error(f"Error in send_alert for user {user['username']}: {str(e)}")
        return False


def send_email_alert(message, emergency_contacts):
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            
            recipients = emergency_contacts.split(',') if emergency_contacts else RECIPIENT_EMAILS
            for recipient in recipients:
                msg = MIMEMultipart()
                msg['From'] = EMAIL_ADDRESS
                msg['To'] = recipient.strip()
                msg['Subject'] = "EMERGENCY ALERT"
                msg.attach(MIMEText(message, 'plain'))
                
                smtp.send_message(msg)
                logging.info(f"Email alert sent successfully to {recipient}")
        
        logging.info("Email alerts sent to all recipients")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        raise


app.secret_key = os.getenv('SECRET_KEY', 'your_fallback_secret_key')

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)

