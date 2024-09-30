# Emergency Alert System 🚨

## Overview
This Emergency Alert System is a web application designed to help people in distress quickly get assistance. It allows users to create a personalized emergency profile, which can be accessed via a QR code. When scanned, this code displays the user's location and emergency information in the local language and English, facilitating quick and effective help from nearby individuals or emergency services.

## Key Features
- User registration and profile creation
- Emergency link generation for emergency access
- Real-time geolocation
- Multi-language support based on location
- Integration with Dexcom for diabetes management
- Email and optional SMS alerts to emergency contacts
- Dynamic map for location confirmation


## QR for the web app deployed in render.com
   ![frame](https://github.com/user-attachments/assets/1ff94ab2-e0f3-4619-b896-bdbc53105b7a)

## QR for my emergency link deployed in render.com
   ![frame (1)](https://github.com/user-attachments/assets/bec77c41-947b-459d-938e-cc4eafc91d86)



## Technologies Used
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS (Tailwind), JavaScript
- **Database**: PostgreSQL
- **Authentication**: Werkzeug for password hashing, Authlib for OAuth
- **Geolocation**: Leaflet.js
- **Translation**: Google Translator API
- **SMS**: Infobip API (optional)
- **Continuous Glucose Monitoring**: Dexcom API
- **Email**: SMTP with SSL
- **Environment Variables**: python-dotenv
- **HTTP Requests**: Requests library
- **Logging**: Python's built-in logging module

## Setup and Installation
1. Clone the repository:
   git clone https://github.com/Warszawa1/geoalert_1.2
    
2. Set up a virtual environment:
   python -m venv venv
   source venv/bin/activate  # On Windows use venv\Scripts\activate
   
3. Install dependencies:
   pip install -r requirements.txt

4. Set up environment variables:
   Create a `.env` file in the root directory and add the following variables:

   SECRET_KEY=your_secret_key
   DATABASE_URL=your_postgres_database_url
   EMAIL_ADDRESS=your_email@example.com
   EMAIL_PASSWORD=your_email_password
   INFOBIP_API_KEY=your_infobip_api_key  # If using SMS feature
   INFOBIP_BASE_URL=https://api.infobip.com/
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret

5. Initialize the database:
   python
    from app import init_db
    init_db()

6. Run the application:
   flask run
   

## Usage
1. Register for an account and set up your emergency profile.
2. Add your emergency contacts and any relevant medical information.
3. If you use a Dexcom CGM, enter your Dexcom credentials.
4. Generate your emergency link from your dashboard.
5. In case of emergency, someone can scan your QR (working on the QR generation 🚧) code to access your emergency information and location. For now it works with the emergency link.   
6. Chat (working on that 🚧).

## Contributing
Contributions to improve the Emergency Alert System are welcome. Please feel free to submit pull requests or open issues to discuss potential enhancements.

## License
[MIT License](LICENSE)

---

Made with care ♥ by IreAV
