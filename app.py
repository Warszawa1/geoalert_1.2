#V3 with only email alert
import uuid
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import urllib.parse
import requests
from deep_translator import GoogleTranslator
import time
from sqlalchemy import func



load_dotenv()

#Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


app = Flask(__name__)
app.config['SECRET_KEY'] = '12345'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


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

translations = {
    'en': {
        'title': 'Emergency Alert System',
        'subtitle': 'Be prepared, stay safe',
        'description': "It does not matter who you are, your circumstances, or what you need help with. We all need assistance at some point, and that is why I created this web.",
        'hope_message': "I hope you never need it, but in case you ever do, I wish it makes it all a bit easier.",
        'how_it_works': 'How it works:',
        'step1': 'Register for an account',
        'step2': 'Set up your emergency information and contacts',
        'step3': 'Get a shareable emergency link',
        'step4': 'In case of emergency, your link can be accessed to display vital information and alert your contacts',
        'login': 'Login',
        'register': 'Register',
        'footer_made_with': 'Made with',
        'footer_for': 'by IreAV'
    },
    'es': {
        'title': 'Sistema de Alerta de Emergencia',
        'subtitle': 'Esté preparado, manténgase seguro',
        'description': "No importa quién seas, tus circunstancias o con qué necesitas ayuda. Todos necesitamos asistencia en algún momento, y es por eso he creado esta web.",
        'hope_message': "Espero que nunca la necesites, pero en caso de que alguna vez lo hagas, deseo que te facilite un poco las cosas.",
        'how_it_works': 'Cómo funciona:',
        'step1': 'Regístrate para obtener una cuenta',
        'step2': 'Configura tu información de emergencia y contactos',
        'step3': 'Obtén el enlace de emergencia para compartir',
        'step4': 'En caso de emergencia, se puede acceder a tu enlace para mostrar información vital y alertar a tus contactos',
        'login': 'Iniciar sesión',
        'register': 'Registrarse',
        'footer_made_with': 'Hecho con',
        'footer_for': 'para quien lo necesite.'
    }
}




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    emergency_message = db.Column(db.Text)
    emergency_contacts = db.Column(db.Text)  # Store as JSON string
    alert_message = db.Column(db.Text)
    share_token = db.Column(db.String(36), unique=True, nullable=False)

    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        if not self.share_token:
            self.share_token = str(uuid.uuid4())


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
    


@app.route('/')
def index():
    lang = request.args.get('lang', 'en')
    if lang not in translations:
        lang = 'en'
    return render_template('index.html', t=translations[lang], lang=lang)

@app.route('/emergency')
def emergency():
    return render_template('emergency.html')


@app.route('/get_emergency_info', methods=['POST'])
def get_emergency_info():
    try:
        data = request.json
        username = data.get('username')
        lat = data['latitude']
        lon = data['longitude']

        app.logger.info(f"Received request for user: {username}, lat: {lat}, lon: {lon}")

        user = User.query.filter_by(username=username).first()
        if not user:
            app.logger.warning(f"Invalid username: {username}")
            return jsonify({"status": "error", "message": "Invalid username"}), 404

        logging.info(f"Fetching emergency info for user: {user.username}, location: {lat}, {lon}")
        
        country_code = get_country_code(lat, lon)
        if not country_code:
            country_code = 'CH'  # Default to Switzerland if detection fails
        
        target_languages = COUNTRY_LANGUAGES.get(country_code, ['en'])
        translations = translate_message(user.emergency_message or EMERGENCY_MESSAGE, target_languages)
        
        # Send alert
        send_alert(user, lat, lon)
        
        return jsonify({
            "status": "success", 
            "translations": translations,
            "country_code": country_code,
            "latitude": lat,
            "longitude": lon,
            "glucose_readings": GLUCOSE_READINGS  # You might want to make this user-specific too
        })
    except Exception as e:
        logging.error(f"Error in get_emergency_info: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
    


# Add this glucose data
GLUCOSE_READINGS = [
    {"time": "2024-07-12 19:25:43", "value": 120},
    {"time": "2024-07-12 19:20:43", "value": 119},
    {"time": "2024-07-12 19:15:43", "value": 116},
    {"time": "2024-07-12 19:10:43", "value": 115},
    {"time": "2024-07-12 19:05:43", "value": 114},
    {"time": "2024-07-12 19:00:44", "value": 113},
    {"time": "2024-07-12 18:55:43", "value": 114},
    {"time": "2024-07-12 18:50:44", "value": 116},
    {"time": "2024-07-12 18:45:43", "value": 118},
    {"time": "2024-07-12 18:40:43", "value": 124},
    {"time": "2024-07-12 18:35:43", "value": 129},
    {"time": "2024-07-12 18:30:43", "value": 130}
]

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')



@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user is None:
        session.pop('user_id', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user.emergency_message = request.form['emergency_message']
        emergency_contacts = request.form.getlist('emergency_contacts')
        user.emergency_contacts = ','.join(filter(None, [contact.strip() for contact in emergency_contacts]))
        user.alert_message = request.form['alert_message']
        db.session.commit()
        flash('Your information has been updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    emergency_link = url_for('emergency', username=user.username, _external=True)
    return render_template('dashboard.html', user=user, emergency_link=emergency_link)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

    

@app.route('/get_location', methods=['POST'])
def get_location():
    # TODO: Implement logic to get or receive user's location
    # This could involve getting data from the request if sent from the client
    # or implementing server-side geolocation
    latitude = 0  # placeholder
    longitude = 0  # placeholder
    return jsonify({'latitude': latitude, 'longitude': longitude})



@app.route('/send_alert', methods=['POST'])
def send_alert(user, lat, lon):
    try:
        maps_link = get_google_maps_link(lat, lon)
        alert_message = f"Emergency Alert: {user.username} needs help. Type 1 Diabetes.\nLocation: {lat}, {lon}\n"
        alert_message += f"Google Maps Link: {maps_link}"
        if user.alert_message:
            alert_message += f"\n\nCustom message: {user.alert_message}"
        
        send_email_alert(alert_message, user.emergency_contacts)
        
        logging.info(f"Alert sent successfully for user {user.username}")
    except Exception as e:
        logging.error(f"Error in send_alert for user {user.username}: {str(e)}")
        raise

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
    



def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

