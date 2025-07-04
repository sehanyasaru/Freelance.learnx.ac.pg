import traceback
import json
import uuid
from werkzeug.utils import secure_filename
from io import BytesIO
import os
from flask import Flask, render_template, request, jsonify, session, redirect,send_file
import mysql.connector
from datetime import datetime
import tzlocal
import bcrypt
from google.oauth2 import id_token
from google.auth.transport import requests
import requests as external_requests
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer,Table,Frame, TableStyle,PageTemplate,Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from mysql.connector import Error
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

def get_database_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            database='png_db'
        )
        print(f"Connection Successfully")
        return connection
    except Error as e:
        print(f"Error in connecting with the database: {e}")
        return None


@app.route('/')
def show_user():
    connection = get_database_connection()
    if connection:
        connection.close()
    return render_template('splash_screen.html')

def get_current_time():
    local_tz = tzlocal.get_localzone()
    now = datetime.now(local_tz)
    return now.strftime("%I:%M %p %z on %A, %B %d, %Y")

def verify_token_with_skew(token, client_id, max_retries=3, delay=1):
    for _ in range(max_retries):
        try:
            id_info = id_token.verify_oauth2_token(token, requests.Request(), client_id)
            return id_info
        except ValueError as e:
            if "Token used too early" in str(e):
                time.sleep(delay)
            else:
                raise e
    raise ValueError("Token verification failed after retries due to clock skew.")

@app.route('/signup', methods=['GET','POST'])
def signup():

    connection =get_database_connection()
    if request.method == 'GET':
        connection = get_database_connection()
        if connection is None:
            return render_template('Sign_up.html', error="Database connection failed")
        connection.close()
        return render_template('Sign_up.html')

    try:
        data=request.form
        email=data.get('username')
        password=data.get('password')
        firstname=data.get('firstname')
        lastname=data.get('lastname')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM registration where username = %s",(email,))
        existing_user = cursor.fetchall()

        if existing_user:
            cursor.close()
            return jsonify({"error": "Account already exists. Please log in."}), 409


        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        query="INSERT INTO registration (username, password,first_name,last_name) VALUES (%s, %s,%s,%s)"
        cursor.execute(query,(email,hashed_password,firstname,lastname))
        connection.commit()
        cursor.close()
        return jsonify({"message": "Signup successful, verification email sent!"})
    except Error as e:
        return jsonify({"error": f"Failed to register: {str(e)}"}), 500

    finally:
        connection.close()

@app.route('/google-login')
def google_login():
    GOOGLE_CLIENT_ID = "941897744487-jjmihr02mbeid46977cak0dlfqrl7hrv.apps.googleusercontent.com"
    REDIRECT_URI = "http://localhost:5000/google-callback"
    google_login_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        "response_type=code&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent"
    )
    return redirect(google_login_url)

@app.route('/google-callback')
def google_callback():
    GOOGLE_CLIENT_ID = "941897744487-jjmihr02mbeid46977cak0dlfqrl7hrv.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = "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"
    REDIRECT_URI = "http://localhost:5000/google-callback"

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        code = request.args.get('code')
        if not code:
            return jsonify({"error": "Authorization code not found"}), 400

        token_response = external_requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'
            }
        )

        if token_response.status_code != 200:
            return jsonify({"error": "Failed to exchange code for token"}), 400

        tokens = token_response.json()


        id_info = verify_token_with_skew(tokens['id_token'], GOOGLE_CLIENT_ID)

        email = id_info['email']
        firstname = id_info.get('given_name', 'GoogleUser')
        lastname = id_info.get('family_name', '')

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM registration WHERE username = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            session['username'] = existing_user['username']
            cursor.close()
            return render_template('Personal_information.html')
        else:
            cursor.execute("SELECT * FROM registration WHERE username = %s", (email,))
            if cursor.fetchone():
                cursor.close()
                return jsonify({"error": "Email already registered with a non-Google account. Please log in."}), 409

            query = "INSERT INTO registration (username,password, first_name, last_name) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (email,"google User",firstname, lastname))
            connection.commit()
            cursor.execute("SELECT username FROM registration WHERE username = %s", (email,))
            user = cursor.fetchone()
            session['username'] = user['username']
            cursor.close()
            return render_template('Personal_information.html')

    except ValueError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 400
    except Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        connection.close()

@app.route('/check_google_user', methods=['POST'])
def check_google_user():
    connection = get_database_connection()
    if connection is None:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.get_json()
        username = data.get('username')

        if not username:
            logger.warning("Missing username in check_google_user")
            return jsonify({"error": "Username is required"}), 400

        cursor = connection.cursor()
        query = "SELECT password FROM registration WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        cursor.fetchall()

        if result is None:
            logger.debug(f"No user found for username: {username}")
            return jsonify({"is_google_user": False})

        is_google_user = result[0] == "google User"
        logger.debug(f"Checking Google user status for {username}: {is_google_user}")
        return jsonify({"is_google_user": is_google_user})

    except Exception as e:
        logger.error(f"Error checking Google user for {username}: {str(e)}")
        return jsonify({"error": f"Error: {str(e)}"}), 500

    finally:
        cursor.close()
        connection.close()

@app.route('/signin', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'GET':
        return render_template('Sign_in.html')

    connection = get_database_connection()
    if connection is None:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.form
        email = data.get('username')
        password = data.get('password')

        if not email:
            logger.warning("Missing email")
            return jsonify({"error": "Email is required"}), 400

        cursor = connection.cursor()
        query = "SELECT password FROM registration WHERE username = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        cursor.fetchall()

        if result is None:
            logger.warning(f"No user found for email: {email}")
            return jsonify({"error": "Invalid email or password"}), 401

        stored_password = result[0]

        is_google_user = stored_password == "google User"

        if is_google_user:
            logger.info(f"Google user {email} authenticated successfully without password check")
        elif not password or not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            logger.warning(f"Password mismatch or missing for non-Google user {email}")
            return jsonify({"error": "Invalid email or password"}), 401
        else:
            logger.info(f"Non-Google user {email} authenticated successfully with bcrypt password")

        session["working_email"] = email


        tables = [
            'academic_qualifications',
            'additional_notes',
            'availability',
            'identification',
            'payment_information',
            'personal_information',
            'professional_experience',
            'sample_teaching_materials',
            'teaching_areas'
        ]

        all_tables_have_data = True
        missing_tables = []
        for table in tables:
            query = f"SELECT COUNT(*) FROM {table} WHERE username = %s"
            cursor.execute(query, (email,))
            count = cursor.fetchone()[0]
            logger.debug(f"Table {table} has {count} entries for username {email}")
            if count == 0:
                all_tables_have_data = False
                missing_tables.append(table)

        if all_tables_have_data:
            logger.info(f"All tables contain username {email}. Redirecting to /dashboard")
        else:
            logger.warning(f"Username {email} missing in tables: {', '.join(missing_tables)}. Redirecting to /personal_information")

        cursor.close()


        redirect_url = '/dashboard' if all_tables_have_data else '/personal_information'
        return jsonify({"message": "Login successful!", "redirect": redirect_url})

    except Exception as e:
        logger.error(f"Login failed for {email}: {str(e)}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

    finally:
        connection.close()

@app.route('/check-username', methods=['GET','POST'])
def check_username():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.form
        username = data.get('username')

        if not username:
            return jsonify({"error": "Username is required"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as count FROM registration WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        return jsonify({"exists": result['count'] > 0})
    except Error as e:
        return jsonify({"error": f"Error checking username: {str(e)}"}), 500
    finally:
        connection.close()

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.form
        username = data.get('username')
        new_password = data.get('newPassword')

        if not username or not new_password:
            return jsonify({"error": "Username and new password are required"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM registration WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Username not found."}), 404

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("UPDATE registration SET password = %s WHERE username = %s", (hashed_password, username))
        connection.commit()
        cursor.close()
        return jsonify({"message": "Password reset successful!"})
    except Error as e:
        return jsonify({"error": f"Failed to reset password: {str(e)}"}), 500
    finally:
        connection.close()

@app.route('/personal_information', methods=['GET', 'POST'])
def personal_information():
    if request.method == 'GET':
        return render_template('Personal_information.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = None
    try:

        title = request.form.get('title')
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        phone_number = request.form.get('phone_number')
        dob = request.form.get('dob')
        nationality = request.form.get('nationality')
        country = request.form.get('country')
        languages = request.form.get('language')
        profile_link = request.form.get('profile_link')
        conference_id = request.form.get('conference_id')
        work_permit = request.form.get('work_permit')
        engagement_type = request.form.get('engagement_type')
        preferred_teaching = request.form.get('preferred_teaching')
        picture = request.files.get('picture')
        nic_passport_image = request.files.get('nic_passport_image')


        required_fields = {
            'title': title,
            'full_name': full_name,
            'username': username,
            'phone_number': phone_number,
            'dob': dob,
            'nationality': nationality,
            'country': country,
            'language': languages,
            'profile_link': profile_link,
            'conference_id': conference_id,
            'work_permit': work_permit,
            'engagement_type': engagement_type,
            'preferred_teaching': preferred_teaching,
            'picture': picture,
            'nic_passport_image': nic_passport_image
        }
        missing_fields = [key for key, value in required_fields.items() if not value or (isinstance(value, str) and value.strip() == '')]
        if missing_fields:
            return jsonify({"error": f"Missing or invalid required fields: {', '.join(missing_fields)}"}), 400

        if picture and picture.filename:
            if not picture.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({"error": "Picture must be PNG, JPG, or JPEG"}), 400
        if nic_passport_image and nic_passport_image.filename:
            if not nic_passport_image.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({"error": "NIC/Passport image must be PNG, JPG, or JPEG"}), 400

        upload_folder = 'static/uploads'
        os.makedirs(upload_folder, exist_ok=True)

        picture_path = None
        if picture and picture.filename:
            picture_filename = f"{uuid.uuid4()}_{picture.filename}"
            picture_path = os.path.join(upload_folder, picture_filename)
            picture.save(picture_path)

        nic_passport_image_path = None
        if nic_passport_image and nic_passport_image.filename:
            nic_passport_image_filename = f"{uuid.uuid4()}_{nic_passport_image.filename}"
            nic_passport_image_path = os.path.join(upload_folder, nic_passport_image_filename)
            nic_passport_image.save(nic_passport_image_path)

        session["working_email"] = username
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT username FROM personal_information WHERE username = %s", (session["working_email"],))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return jsonify({"error": "Information already exists with this username", "redirect": '/academic_qualifications'}), 409


        if not connection.autocommit:
            try:
                connection.rollback()
            except Error:
                pass
            connection.autocommit = False


        personal_insert_query = """
            INSERT INTO personal_information (
                title, full_name, username, phone_number, dob, Nationality, country,
                Language, profile_link, conference_id, work_permit, engagement_type, preffered_teaching
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(personal_insert_query, (
            title, full_name, username, phone_number, dob, nationality, country,
            languages, profile_link, conference_id, work_permit, engagement_type, preferred_teaching
        ))


        cursor.execute("SELECT username FROM identification WHERE username = %s", (username,))
        existing_identification = cursor.fetchone()

        if not existing_identification:
            identification_insert_query = """
                INSERT INTO identification (
                    username, picture_path, nic_passport_image_path
                ) VALUES (%s,%s, %s)
            """
            cursor.execute(identification_insert_query, (
                username, picture_path, nic_passport_image_path
            ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Personal information submitted successfully!"}), 200

    except Error as e:
        if connection and not connection.autocommit:
            connection.rollback()
        return jsonify({"error": f"Failed to submit personal information: {str(e)}"}), 500

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

@app.route('/academic_qualifications', methods=['GET', 'POST'])
def academic_qualifications():
    if request.method == 'GET':
        return render_template('academic-qualifications.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.get_json()
        username = session.get("working_email")
        degrees = data.get('degrees')
        thesis = data.get('thesis', '')
        certifications = data.get('certifications')
        online_courses = data.get('online_courses')
        degrees_json = json.dumps(degrees)
        if not username:
            return jsonify({"error": "Session expired or invalid. Please submit personal information first."}), 401

        if not degrees or not isinstance(degrees, list) or not all(isinstance(deg, dict) for deg in degrees):
            return jsonify({"error": "Degrees must be a non-empty list of objects"}), 400

        required_degree_fields = ['degree', 'field', 'institution', 'year','grade']
        for deg in degrees:
            if not all(deg.get(field) for field in required_degree_fields):
                return jsonify({"error": "All degree fields degree are required"}), 400

        required_fields = [certifications, online_courses]
        if not all(required_fields):
            return jsonify({"error": "certifications, and online courses are required"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM academic_qualifications WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return jsonify({"error": "Academic qualifications already exist for this username", "redirect": "/teaching_areas"}), 409

        cursor = connection.cursor(dictionary=True)
        insert_query = """
            INSERT INTO academic_qualifications (
                username, degree, thesis, certifications, online_courses
            ) VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
                username,
                degrees_json,
                thesis,
                certifications,
                online_courses
        ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Academic qualifications submitted successfully!", "redirect": "/teaching_areas"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit academic qualifications: {str(e)}"}), 500

    finally:
        if connection:
            connection.close()

@app.route('/teaching_areas', methods=['GET', 'POST'])
def teaching_areas():
    if request.method == 'GET':
        return render_template('teaching_areas.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.get_json()
        username = session.get("working_email")
        teaching_areas = data.get('teachingAreas')
        subjects_topics = data.get('subjectsTopics')
        level_of_expertise = data.get('levelOfExpertise')
        years_of_experience = data.get('yearsOfExperience')
        preferred_student_level = data.get('preferredStudentLevel')
        sample_topics = data.get('sampleTopics')
        teaching_methodology = data.get('teachingMethodology')
        availability = data.get('availability')
        preferred_student_level_json = json.dumps(preferred_student_level)

        if not username:
            return jsonify({"error": "Session expired or invalid. Please submit personal information first."}), 401

        required_fields = [
            teaching_areas,
            subjects_topics,
            level_of_expertise,
            years_of_experience,
            preferred_student_level,
            sample_topics,
            teaching_methodology,
            availability
        ]
        if not all(required_fields):
            return jsonify({"error": "All fields are required"}), 400

        if not isinstance(preferred_student_level, list) or len(preferred_student_level) == 0:
            return jsonify({"error": "Preferred student level must be a non-empty list"}), 400

        if not isinstance(years_of_experience, str) or not years_of_experience.isdigit() or int(years_of_experience) <= 0:
            return jsonify({"error": "Years of experience must be a positive number"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM teaching_areas WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return jsonify({"error": "Teaching areas already exist for this username", "redirect": "/professional_experience"}), 409

        insert_query = """
            INSERT INTO teaching_areas (
                username, teaching_areas, subjects_topics, level_of_expertise, years_of_experience,
                preferred_student_level, sample_topics, teaching_methodology, availability
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            username,
            teaching_areas,
            subjects_topics,
            level_of_expertise,
            years_of_experience,
            preferred_student_level_json,
            sample_topics,
            teaching_methodology,
            availability
        ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Teaching areas submitted successfully!", "redirect": "/professional_experience"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit teaching areas: {str(e)}"}), 500

    finally:
        if connection:
            connection.close()


@app.route('/professional_experience', methods=['GET', 'POST'])
def professional_experience():
    if request.method == 'GET':
        return render_template('teaching_experiance.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        data = request.get_json()
        username = session.get("working_email")
        employment_history = data.get('employmentHistory')
        total_years_experience = data.get('totalYearsExperience')
        key_achievements = data.get('keyAchievements')
        relevant_projects = data.get('relevantProjects')
        employment_history_json = json.dumps(employment_history)

        if not username:
            return jsonify({"error": "Session expired or invalid. Please submit personal information first."}), 401

        if not employment_history or not isinstance(employment_history, list) or not all(isinstance(job, dict) for job in employment_history):
            return jsonify({"error": "Employment history must be a non-empty list of objects"}), 400

        required_job_fields = ['employer', 'jobTitle', 'startDate', 'endDate', 'responsibilities']
        for job in employment_history:
            if not all(job.get(field) for field in required_job_fields):
                return jsonify({"error": "All employment history fields are required"}), 400

        required_fields = [total_years_experience, key_achievements, relevant_projects]
        if not all(required_fields):
            return jsonify({"error": "Total years of experience, key achievements, and relevant projects are required"}), 400

        if not isinstance(total_years_experience, str) or not total_years_experience.isdigit() or int(total_years_experience) <= 0:
            return jsonify({"error": "Total years of experience must be a positive number"}), 400

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM professional_experience WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return jsonify({"error": "Professional experience already exists for this username", "redirect": "/sample_teaching_materials"}), 409

        insert_query = """
            INSERT INTO professional_experience (
                username, employment_history, total_years_experience, key_achievements, relevant_projects
            ) VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            username,
            employment_history_json,
            total_years_experience,
            key_achievements,
            relevant_projects
        ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Professional experience submitted successfully!", "redirect": "/sample_teaching_materials"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit professional experience: {str(e)}"}), 500

    finally:
        if connection:
            connection.close()


UPLOAD_FOLDER = 'static/uploads'
UPLOAD_FOLDER_NEW = 'static/references'
ALLOWED_EXTENSIONS = {
    'Document': {'pdf', 'docx'},
    'Presentation': {'pptx'},
    'Video': {'mp4', 'webm'},
    'Other': set()
}
ALLOWED_EXTENSION_FOR_REFERENCES = {
    'Document': {'jpg', 'jpeg', 'png', 'pdf', 'docx'}
}
def allowed_file(filename, material_type):
    if material_type == 'Other':
        return True
    extension = os.path.splitext(filename)[1].lower().lstrip('.')
    return extension in ALLOWED_EXTENSIONS.get(material_type, set())

@app.route('/sample_teaching_materials', methods=['GET', 'POST'])
def sample_teaching_materials():
    if request.method == 'GET':
        return render_template('teaching_materials.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        if 'multipart/form-data' not in request.content_type.lower():
            return jsonify({"error": "Request must be multipart/form-data"}), 400

        metadata = request.form.get('metadata')
        if not metadata:
            return jsonify({"error": "Metadata is required"}), 400
        data = json.loads(metadata)

        username = session.get("working_email")
        teaching_materials = data.get('teachingMaterials')
        additional_notes = data.get('additionalNotes', '')

        if not username:
            return jsonify({"error": "Session expired or invalid. Please submit personal information first."}), 401

        if not teaching_materials or not isinstance(teaching_materials, list) or not all(isinstance(material, dict) for material in teaching_materials):
            return jsonify({"error": "Teaching materials must be a non-empty list of objects"}), 400

        required_material_fields = ['materialType', 'title', 'description', 'fileName']
        for material in teaching_materials:
            if not all(material.get(field) for field in required_material_fields):
                return jsonify({"error": "All teaching material fields are required"}), 400
            if material['materialType'] not in ALLOWED_EXTENSIONS:
                return jsonify({"error": f"Invalid material type: {material['materialType']}"}), 400

        if 'teachingVideo' not in request.files or not request.files['teachingVideo']:
            return jsonify({"error": "Teaching video file is required"}), 400
        teaching_video = request.files['teachingVideo']
        if teaching_video.filename == '':
            return jsonify({"error": "No teaching video selected"}), 400
        if teaching_video.mimetype not in ['video/mp4', 'video/webm']:
            return jsonify({"error": "Teaching video must be MP4 or WebM"}), 400


        material_files = []
        for i, material in enumerate(teaching_materials):
            file_key = f'file_{i}'
            if file_key not in request.files or not request.files[file_key]:
                return jsonify({"error": f"File for material {i+1} is required"}), 400
            file = request.files[file_key]
            if file.filename == '':
                return jsonify({"error": f"No file selected for material {i+1}"}), 400
            if not allowed_file(file.filename, material['materialType']):
                allowed = ALLOWED_EXTENSIONS[material['materialType']] if material['materialType'] != 'Other' else 'any'
                return jsonify({"error": f"Invalid file type for material {i+1}. Allowed: {allowed or 'any'}"}), 400
            material_files.append(file)


        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM sample_teaching_materials WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            return jsonify({"error": "Sample teaching materials already exist for this username", "redirect": "/certification"}), 409


        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
            print(f"Created directory: {UPLOAD_FOLDER}")
        else:
            print(f"Using existing directory: {UPLOAD_FOLDER}")


        video_filename = secure_filename(f"{uuid.uuid4()}{os.path.splitext(teaching_video.filename)[1]}")
        video_path = os.path.join(UPLOAD_FOLDER, video_filename)
        teaching_video.save(video_path)


        teaching_materials_with_paths = []
        for i, (material, file) in enumerate(zip(teaching_materials, material_files)):
            file_filename = secure_filename(f"{uuid.uuid4()}{os.path.splitext(file.filename)[1]}")
            file_path = os.path.join(UPLOAD_FOLDER, file_filename)
            file.save(file_path)
            teaching_materials_with_paths.append({
                'materialType': material['materialType'],
                'title': material['title'],
                'description': material['description'],
                'filePath': file_filename
            })

        teaching_materials_json = json.dumps(teaching_materials_with_paths)


        insert_query = """
            INSERT INTO sample_teaching_materials (
                username, teaching_materials, teaching_video, additional_notes
            ) VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            username,
            teaching_materials_json,
            video_filename,
            additional_notes or ''
        ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Sample teaching materials submitted successfully!", "redirect": "/certification"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit sample teaching materials: {str(e)}"}), 500

    except Exception as e:
        traceback.print_exc()  # ⬅️ This will print the full error to the console
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    finally:
        if connection:
            connection.close()


@app.route('/get_engagement_type')
def get_engagement_type():
    username = session.get('working_email')
    if not username:
        return jsonify({'engagement_type': 'Unknown'})

    connection = get_database_connection()
    if connection is None:
        return jsonify({'engagement_type': 'Unknown'})

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT engagement_type FROM personal_information WHERE username = %s", (username,))
        result = cursor.fetchone()
        engagement_type = result['engagement_type'] if result else 'Unknown'
        return jsonify({'engagement_type': engagement_type})

    except Error as e:
        print(f"Error fetching engagement type from personal_information: {e}")
        return jsonify({'engagement_type': 'Unknown'})
    finally:
        cursor.close()
        connection.close()

@app.route('/availability', methods=['GET', 'POST'])
def availability():
    if request.method == 'GET':
        return render_template('Availability.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        if 'multipart/form-data' not in request.content_type.lower():
            return jsonify({"error": "Request must be multipart/form-data"}), 400

        metadata = request.form.get('metadata')
        if not metadata:
            return jsonify({"error": "No data provided"}), 400

        data = json.loads(metadata)
        username = session.get('working_email')


        availability_data = data.get('availability', {})
        days = availability_data.get('days', [])
        start_date = availability_data.get('startDate', '')
        contract_length = availability_data.get('contractLength', '')
        notice_period = availability_data.get('noticePeriod', '')
        willingness_to_travel = availability_data.get('willingnessToTravel', '')
        commitments = availability_data.get('commitments', '')
        preferred_hours = availability_data.get('preferredHours', [])
        engagement_type = availability_data.get('engagementType', 'Unknown')

        additional_notes = data.get('additionalNotes', '')


        if not start_date:
            return jsonify({'error': 'Preferred start date is required'}), 400
        if not contract_length:
            return jsonify({'error': 'Contract length is required'}), 400
        if not notice_period:
            return jsonify({'error': 'Notice period is required'}), 400
        if not willingness_to_travel:
            return jsonify({'error': 'Willingness to travel is required'}), 400
        if not commitments:
            return jsonify({'error': 'Other commitments are required'}), 400


        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT engagement_type FROM personal_information WHERE username = %s", (username,))
        db_engagement_type = cursor.fetchone()
        if db_engagement_type and db_engagement_type['engagement_type'] != engagement_type:
            return jsonify({'error': 'Engagement type mismatch with personal information'}), 400

        if engagement_type in ['Part Time', 'Both']:
            if not days:
                return jsonify({'error': 'At least one day must be selected for Part Time or Both'}), 400
            if not preferred_hours:
                return jsonify({'error': 'Preferred hours are required for Part Time or Both'}), 400


        availability_json = json.dumps({
            'days': days,
            'startDate': start_date,
            'contractLength': contract_length,
            'noticePeriod': notice_period,
            'willingnessToTravel': willingness_to_travel,
            'commitments': commitments,
            'preferredHours': preferred_hours,
            'engagementType': engagement_type
        })
        print(username)

        cursor.execute("SELECT username FROM availability WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({'error': 'Information already exists with this username', 'redirect': '/rates'}), 409


        insert_query = """
            INSERT INTO availability (
                username, availability_data, additional_notes, created_at
            ) VALUES (%s, %s, %s, %s)
        """
        created_at = get_current_time()
        cursor.execute(insert_query, (username, availability_json, additional_notes or '', created_at))
        connection.commit()
        cursor.close()

        return jsonify({"message": "Availability submitted successfully!", "redirect": "/rates"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit availability: {str(e)}"}), 500
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON data: {str(e)}"}), 400
    finally:
        if connection:
            connection.close()

@app.route('/rates', methods=['GET', 'POST'])
def section7():
    if request.method == 'GET':
        return render_template('Rates.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        if 'multipart/form-data' not in request.content_type.lower():
            return jsonify({"error": "Request must be multipart/form-data"}), 400


        username = session.get('working_email')
        payment_currency = request.form.get('paymentCurrency', '')
        hourly_rate = request.form.get('hourlyRate', '')
        monthly_rate = request.form.get('monthlyRate', '') or None
        payment_method = request.form.get('paymentMethod', '')
        negotiable = request.form.get('negotiable', '')
        invoicing_cycle = request.form.get('invoicingCycle', '')

        if not payment_currency:
            return jsonify({'error': 'Preferred payment currency is required'}), 400
        if not hourly_rate:
            return jsonify({'error': 'Hourly per course rate is required'}), 400
        if not payment_method:
            return jsonify({'error': 'Payment method is required'}), 400
        if not negotiable:
            return jsonify({'error': 'Negotiability is required'}), 400
        if not invoicing_cycle:
            return jsonify({'error': 'Preferred invoicing cycle is required'}), 400



        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM payment_information WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({'error': 'Payment information already exists with this username', 'redirect': '/references'}), 409


        insert_query = """
            INSERT INTO payment_information (
                username, payment_currency, hourly_rate, monthly_rate, payment_method, negotiable, invoicing_cycle
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        cursor.execute(insert_query, (username, payment_currency, hourly_rate, monthly_rate, payment_method, negotiable, invoicing_cycle))
        connection.commit()
        cursor.close()

        return jsonify({"message": "Payment information submitted successfully!", "redirect": "/reference"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit payment information: {str(e)}"}), 500
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON data: {str(e)}"}), 400
    finally:
        if connection:
            connection.close()


def allowed_file_new(filename, material_type):
    extension = os.path.splitext(filename)[1].lower().lstrip('.')
    return extension in ALLOWED_EXTENSION_FOR_REFERENCES.get(material_type, set())

app.config['UPLOAD_FOLDER_NEW'] = UPLOAD_FOLDER_NEW
if not os.path.exists(UPLOAD_FOLDER_NEW):
    os.makedirs(UPLOAD_FOLDER_NEW)

@app.route('/references', methods=['GET', 'POST'])
def reference():
    if request.method == 'GET':
        return render_template('References.html')

    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        if 'multipart/form-data' not in request.content_type.lower():
            return jsonify({"error": "Request must be multipart/form-data"}), 400

        username = session.get('working_email')
        teaching_philosophy = request.form.get('teachingPhilosophy', '')
        constraints = request.form.get('constraints', '')
        interests_hobbies = request.form.get('interestsHobbies', '') or ''
        tools = [request.form.get(f'tool_{i}', '') for i in range(10)]
        tools = [t for t in tools if t]


        if not teaching_philosophy:
            return jsonify({'error': 'Teaching philosophy is required'}), 400
        if not constraints:
            return jsonify({'error': 'Constraints are required'}), 400
        if not tools:
            return jsonify({'error': 'At least one technology tool is required'}), 400


        certificates = []
        for i in range(10):
            desc = request.form.get(f'certificateDesc_{i}', '')
            file = request.files.get(f'certificateFile_{i}')
            if desc:
                file_path = None
                if file and file.filename and allowed_file_new(file.filename, 'Document'):
                    filename = secure_filename(f"{username}_cert_{i}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER_NEW'], filename)
                    try:
                        file.save(file_path)
                        print(f"[DEBUG] Saved certificate to {os.path.abspath(file_path)}")
                    except Exception as e:
                        print(f"[ERROR] Failed to save certificate: {str(e)}")
                        file_path = None
                certificates.append({'description': desc, 'file_path': file_path})

        publications = []
        for i in range(10):
            desc = request.form.get(f'publicationDesc_{i}', '')
            file = request.files.get(f'publicationFile_{i}')
            if desc:
                file_path = None
                if file and file.filename and allowed_file_new(file.filename, 'Document'):
                    filename = secure_filename(f"{username}_pub_{i}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER_NEW'], filename)
                    try:
                        file.save(file_path)
                        print(f"[DEBUG] Saved publication to {os.path.abspath(file_path)}")
                    except Exception as e:
                        print(f"[ERROR] Failed to save publication: {str(e)}")
                        file_path = None
                publications.append({'description': desc, 'file_path': file_path})


        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username FROM additional_notes WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            return jsonify({'error': 'Additional notes already exist with this username', 'redirect': '/final_submission'}), 409


        insert_query = """
            INSERT INTO additional_notes (
                username, teaching_philosophy, constraints, interests_hobbies, technology_tools, certificates, publications
            ) VALUES (%s, %s, %s, %s, %s, %s,%s)
        """
        cursor.execute(insert_query, (username, teaching_philosophy, constraints, interests_hobbies, ','.join(tools), json.dumps(certificates), json.dumps(publications)))
        connection.commit()
        cursor.close()

        return jsonify({"message": "Additional notes submitted successfully!", "redirect": "/final_submission"}), 200

    except Error as e:
        return jsonify({"error": f"Failed to submit additional notes: {str(e)}"}), 500
    finally:
        if connection:
            connection.close()



@app.route('/view_application', methods=['GET'])
def view_application_page():
    return render_template('View_my_application.html')

@app.route('/api/view_application', methods=['GET'])
def view_application_api():
    connection = None
    cursor = None
    try:
        connection = get_database_connection()
        if connection is None:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = connection.cursor(dictionary=True)

        username = session.get('working_email')

        if not username:
            return jsonify({"error": "Session expired or invalid"}), 401

        data = {}

        # Fetch personal_information
        cursor.execute("SELECT * FROM personal_information WHERE username = %s", (username,))
        data['personal_information'] = cursor.fetchone() or {}

        cursor.execute("SELECT picture_path,nic_passport_image_path FROM identification WHERE username = %s", (username,))
        identification = cursor.fetchone() or {}
        data['identification'] = identification

        # Fetch academic_qualifications
        cursor.execute("SELECT * FROM academic_qualifications WHERE username = %s", (username,))
        academic = cursor.fetchone() or {}
        if academic.get('degree') and academic['degree'].strip():
            try:
                academic['degrees'] = json.loads(academic['degree'])
            except json.JSONDecodeError:
                academic['degrees'] = []
                print(f"Warning: Invalid JSON in academic_qualifications.degree for user {username}")
        else:
            academic['degrees'] = []
        data['academic_qualifications'] = academic

        # Fetch teaching_areas
        cursor.execute("SELECT * FROM teaching_areas WHERE username = %s", (username,))
        teaching = cursor.fetchone() or {}
        if teaching.get('preferred_student_level') and teaching['preferred_student_level'].strip():
            try:
                teaching['preferred_student_level'] = json.loads(teaching['preferred_student_level'])
            except json.JSONDecodeError:
                teaching['preferred_student_level'] = []
                print(f"Warning: Invalid JSON in teaching_areas.preferred_student_level for user {username}")
        else:
            teaching['preferred_student_level'] = []
        data['teaching_areas'] = teaching

        # Fetch professional_experience
        cursor.execute("SELECT * FROM professional_experience WHERE username = %s", (username,))
        prof_exp = cursor.fetchone() or {}
        if prof_exp.get('employment_history') and prof_exp['employment_history'].strip():
            try:
                prof_exp['employment_history'] = json.loads(prof_exp['employment_history'])
            except json.JSONDecodeError:
                prof_exp['employment_history'] = []
                print(f"Warning: Invalid JSON in professional_experience.employment_history for user {username}")
        else:
            prof_exp['employment_history'] = []
        data['professional_experience'] = prof_exp


        cursor.execute("SELECT * FROM sample_teaching_materials WHERE username = %s", (username,))
        teaching_mats = cursor.fetchone() or {}
        if teaching_mats.get('teaching_materials') and teaching_mats['teaching_materials'].strip():
            try:
                teaching_mats['teaching_materials'] = json.loads(teaching_mats['teaching_materials'])
            except json.JSONDecodeError:
                teaching_mats['teaching_materials'] = []
                print(f"Warning: Invalid JSON in sample_teaching_materials.teaching_materials for user {username}")
        else:
            teaching_mats['teaching_materials'] = []
        data['sample_teaching_materials'] = teaching_mats


        cursor.execute("SELECT * FROM availability WHERE username = %s", (username,))
        avail = cursor.fetchone() or {}
        if avail.get('availability_data') and avail['availability_data'].strip():
            try:
                avail['availability_data'] = json.loads(avail['availability_data'])
            except json.JSONDecodeError:
                avail['availability_data'] = {}
                print(f"Warning: Invalid JSON in availability.availability_data for user {username}")
        else:
            avail['availability_data'] = {}
        data['availability'] = avail


        cursor.execute("SELECT * FROM payment_information WHERE username = %s", (username,))
        data['payment_information'] = cursor.fetchone() or {}


        cursor.execute("SELECT * FROM additional_notes WHERE username = %s", (username,))
        notes = cursor.fetchone() or {}
        if notes.get('certificates') and notes['certificates'].strip():
            try:
                notes['certificates'] = json.loads(notes['certificates'])
            except json.JSONDecodeError:
                notes['certificates'] = []
                print(f"Warning: Invalid JSON in additional_notes.certificates for user {username}")
        else:
            notes['certificates'] = []
        if notes.get('publications') and notes['publications'].strip():
            try:
                notes['publications'] = json.loads(notes['publications'])
            except json.JSONDecodeError:
                notes['publications'] = []
                print(f"Warning: Invalid JSON in additional_notes.publications for user {username}")
        else:
            notes['publications'] = []
        data['additional_notes'] = notes

        return jsonify(data)

    except Error as e:
        return jsonify({"error": f"Failed to fetch application data: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            logger.debug("Database connection closed")





def fetch_application_data_for_user(cursor, username):
    data = {}

    cursor.execute("SELECT * FROM personal_information WHERE username = %s", (username,))
    data['personal_information'] = cursor.fetchone() or {}

    cursor.execute("SELECT picture_path, nic_passport_image_path FROM identification WHERE username = %s", (username,))
    data['identification'] = cursor.fetchone() or {}

    cursor.execute("SELECT * FROM academic_qualifications WHERE username = %s", (username,))
    academic = cursor.fetchone() or {}
    try:
        academic['degrees'] = json.loads(academic.get('degree', '[]'))
    except json.JSONDecodeError:
        academic['degrees'] = []
    data['academic_qualifications'] = academic

    cursor.execute("SELECT * FROM teaching_areas WHERE username = %s", (username,))
    teaching = cursor.fetchone() or {}
    try:
        teaching['preferred_student_level'] = json.loads(teaching.get('preferred_student_level', '[]'))
    except json.JSONDecodeError:
        teaching['preferred_student_level'] = []
    data['teaching_areas'] = teaching

    cursor.execute("SELECT * FROM professional_experience WHERE username = %s", (username,))
    prof_exp = cursor.fetchone() or {}
    try:
        prof_exp['employment_history'] = json.loads(prof_exp.get('employment_history', '[]'))
    except json.JSONDecodeError:
        prof_exp['employment_history'] = []
    data['professional_experience'] = prof_exp

    cursor.execute("SELECT * FROM sample_teaching_materials WHERE username = %s", (username,))
    mats = cursor.fetchone() or {}
    try:
        mats['teaching_materials'] = json.loads(mats.get('teaching_materials', '[]'))
    except json.JSONDecodeError:
        mats['teaching_materials'] = []
    data['sample_teaching_materials'] = mats

    cursor.execute("SELECT * FROM availability WHERE username = %s", (username,))
    avail = cursor.fetchone() or {}
    try:
        avail['availability_data'] = json.loads(avail.get('availability_data', '{}'))
    except json.JSONDecodeError:
        avail['availability_data'] = {}
    data['availability'] = avail

    cursor.execute("SELECT * FROM payment_information WHERE username = %s", (username,))
    data['payment_information'] = cursor.fetchone() or {}

    cursor.execute("SELECT * FROM additional_notes WHERE username = %s", (username,))
    notes = cursor.fetchone() or {}
    try:
        notes['certificates'] = json.loads(notes.get('certificates', '[]'))
    except json.JSONDecodeError:
        notes['certificates'] = []
    try:
        notes['publications'] = json.loads(notes.get('publications', '[]'))
    except json.JSONDecodeError:
        notes['publications'] = []
    data['additional_notes'] = notes

    return data

class TableImage(Flowable):
    def __init__(self, path, width=1.5*inch, height=1.5*inch):
        Flowable.__init__(self)
        self.img_path = path
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self):
        if os.path.exists(self.img_path):
            self.canv.drawImage(self.img_path, 0, 0, width=self.width, height=self.height, preserveAspectRatio=True, mask='auto')
        else:
            self.canv.drawString(0, self.height/2, "Image not found")

@app.route('/api/generate_pdf', methods=['GET'])
def generate_pdf():
    connection = get_database_connection()
    if connection is None:
        return "DB Error", 500

    cursor = connection.cursor(dictionary=True)
    username = session.get('working_email')
    if not username:
        return "Unauthorized", 401

    application_data = fetch_application_data_for_user(cursor, username)
    if not application_data:
        return "No application data found", 404

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=0.5*inch, leftMargin=0.5*inch,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=12,
        alignment=1,
        textColor=colors.darkblue
    )
    section_style = ParagraphStyle(
        name='SectionStyle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=8,
        textColor=colors.black
    )
    normal_style = ParagraphStyle(
        name='NormalStyle',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )

    story = []

    identification = application_data['identification']
    picture_path = identification.get('picture_path', '')
    nic_passport_image_path = identification.get('nic_passport_image_path', '')


    def draw_profile_pic(canvas, doc):
        if picture_path and os.path.exists(picture_path):
            iw, ih = 1.5*inch, 1.5*inch
            x = doc.pagesize[0] - iw - doc.rightMargin
            y = doc.pagesize[1] - ih - doc.topMargin + 10
            canvas.drawImage(picture_path, x, y, width=iw, height=ih, preserveAspectRatio=True, mask='auto')


    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
    page_template = PageTemplate(id='template', frames=[frame], onPage=draw_profile_pic)
    doc.addPageTemplates([page_template])

    # Title
    story.append(Paragraph("Application Profile", title_style))
    story.append(Spacer(1, 0.2*inch))


    personal = application_data['personal_information']

    personal_data = [
        ["Professional Title", personal.get('title', 'N/A')],
        ["Full Name", personal.get('full_name', 'N/A')],
        ["Email Address", personal.get('username', 'N/A')],
        ["Phone Number", personal.get('phone_number', 'N/A')],
        ["Date of Birth", personal.get('dob', 'N/A')],
        ["Nationality", personal.get('Nationality', 'N/A')],
        ["Current Country of Residence", personal.get('country', 'N/A')],
        ["Languages Spoken", personal.get('Language', 'N/A')],
        ["LinkedIn / Professional Profile", personal.get('profile_link', 'N/A')],
        ["Skype / Zoom ID", personal.get('conference_id', 'N/A')],
        ["Work Permit", personal.get('work_permit', 'N/A')],
        ["Engagement Type", personal.get('engagement_type', 'N/A')],
        ["Preferred Teaching Mode", personal.get('preferred_teaching', 'N/A')],
    ]

    story.append(Paragraph("Personal Information", section_style))

    personal_table = Table(personal_data, colWidths=[2.5*inch, 4.5*inch])
    personal_table.setStyle(TableStyle([
        ('FONT', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -2), colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
    ]))
    story.append(personal_table)
    story.append(Spacer(1, 0.2*inch))
    nic_passport_image_path = application_data['identification'].get('nic_passport_image_path', '')

    def draw_nic_image(canvas, doc):
        if nic_passport_image_path and os.path.exists(nic_passport_image_path):
            try:
                iw, ih = 1.5*inch, 1.5*inch
                x = doc.pagesize[0] - iw - doc.rightMargin
                y = doc.pagesize[1] - ih - doc.topMargin + 10  # slight adjustment inside margin
                canvas.drawImage(nic_passport_image_path, x, y, width=iw, height=ih, preserveAspectRatio=True, mask='auto')
            except:
                pass
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')

    page_template = PageTemplate(id='nic_img', frames=[frame], onPage=draw_nic_image)
    doc.addPageTemplates([page_template])



    def add_section_table(title, data_dict):
        story.append(Paragraph(title, section_style))
        if not data_dict:
            story.append(Paragraph("No data provided.", normal_style))
            story.append(Spacer(1, 0.2*inch))
            return
        data = []
        for key, value in data_dict.items():
            if isinstance(value, list):
                val_text = ', '.join(value) if value else 'N/A'
            else:
                val_text = str(value) if value else 'N/A'
            data.append([key.replace('_', ' ').title(), val_text])
        table = Table(data, colWidths=[2.5*inch, 4.5*inch])
        table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(table)
        story.append(Spacer(1, 0.2*inch))

    academic = application_data['academic_qualifications']
    degrees = academic.get('degrees', [])
    story.append(Paragraph("Academic Qualifications", section_style))
    if degrees:
        for degree in degrees:
            deg_text = f"{degree.get('degree', 'N/A')} in {degree.get('field', 'N/A')} - {degree.get('institution', 'N/A')} (Grade: {degree.get('grade', 'N/A')}, Year: {degree.get('year', 'N/A')})"
            story.append(Paragraph(deg_text, normal_style))
    else:
        story.append(Paragraph("No academic qualifications provided.", normal_style))

    add_section_table("", {
        "Thesis / Research Topic": academic.get('thesis', 'N/A'),
        "Professional Certifications": academic.get('certifications', 'N/A'),
        "Online Courses / MOOCs": academic.get('online_courses', 'N/A'),
    })

    teaching = application_data['teaching_areas']
    teaching_data = {
        "Teaching Areas": teaching.get('teaching_areas', 'N/A'),
        "Subjects / Topics": teaching.get('subjects_topics', 'N/A'),
        "Level Of Expertise": teaching.get('level_of_expertise', 'N/A'),
        "Years Of Teaching Experience": teaching.get('years_of_experience', 'N/A'),
        "Preferred Student Level": ', '.join(teaching.get('preferred_student_level', [])) if teaching.get('preferred_student_level') else 'N/A',
        "Sample Topics For Workshops": teaching.get('sample_topics', 'N/A'),
        "Teaching Methodology": teaching.get('teaching_methodology', 'N/A'),
        "Availability": teaching.get('availability', 'N/A'),
    }
    add_section_table("Teaching Areas", teaching_data)

    prof_exp = application_data['professional_experience']
    experiences = prof_exp.get('employment_history', [])
    story.append(Paragraph("Professional Experience", section_style))
    if experiences:
        for exp in experiences:
            exp_text = f"{exp.get('jobTitle', 'N/A')} at {exp.get('employer', 'N/A')} ({exp.get('startDate', 'N/A')} - {exp.get('endDate', 'N/A')}) - Responsibilities: {exp.get('responsibilities', 'N/A')}"
            story.append(Paragraph(exp_text, normal_style))
    else:
        story.append(Paragraph("No professional experience provided.", normal_style))

    add_section_table("", {
        "Total Years Of Professional Experience": prof_exp.get('total_years_experience', 'N/A'),
        "Key Achievements": prof_exp.get('key_achievements', 'N/A'),
        "Relevant Projects": prof_exp.get('relevant_projects', 'N/A'),
    })

    materials = application_data['sample_teaching_materials']
    story.append(Paragraph("Sample Teaching Materials", section_style))
    teaching_materials = materials.get('teaching_materials', [])
    if teaching_materials:
        for material in teaching_materials:
            material_text = f"{material.get('title', 'N/A')} ({material.get('materialType', 'N/A')}): {material.get('description', 'N/A')}"
            story.append(Paragraph(material_text, normal_style))
    else:
        story.append(Paragraph("No teaching materials provided.", normal_style))

    add_section_table("", {
        "Teaching Video": materials.get('teaching_video', 'N/A'),
        "Additional Notes": materials.get('additional_notes', 'N/A'),
    })

    availability = application_data['availability']
    avail_data = availability.get('availability_data', {})
    availability_data = {
        "Engagement Type": avail_data.get('engagementType', 'N/A'),
        "Preferred Days": avail_data.get('days', 'N/A'),
        "Preferred Start Date": avail_data.get('startDate', 'N/A'),
        "Desired Contract Length": avail_data.get('contractLength', 'N/A'),
        "Notice Period": avail_data.get('noticePeriod', 'N/A'),
        "Willingness To Travel": avail_data.get('willingnessToTravel', 'N/A'),
        "Other Ongoing Commitments": avail_data.get('commitments', 'N/A'),
        "Weekly Hours Available": avail_data.get('preferredHours', 'N/A'),
        "Additional Notes": availability.get('additional_notes', 'N/A'),
    }
    add_section_table("Availability", availability_data)

    payment = application_data['payment_information']
    payment_data = {
        "Preferred Payment Currency": payment.get('payment_currency', 'N/A'),
        "Hourly Per Course Rate": payment.get('hourly_rate', 'N/A'),
        "Expected Monthly Rate": payment.get('monthly_rate', 'N/A'),
        "Payment Method": payment.get('payment_method', 'N/A'),
        "Negotiability": payment.get('negotiable', 'N/A'),
        "Preferred Invoicing Cycle": payment.get('invoicing_cycle', 'N/A'),
    }
    add_section_table("Payment Information", payment_data)

    notes = application_data['additional_notes']
    story.append(Paragraph("Additional Notes", section_style))
    certificates = notes.get('certificates', [])
    if certificates:
        story.append(Paragraph("Certificates:", normal_style))
        for cert in certificates:
            cert_text = f"{cert.get('description', 'N/A')} ({cert.get('file_path', 'N/A')})"
            story.append(Paragraph(cert_text, normal_style))

    publications = notes.get('publications', [])
    if publications:
        story.append(Paragraph("Publications:", normal_style))
        for pub in publications:
            pub_text = f"{pub.get('description', 'N/A')} ({pub.get('file_path', 'N/A')})"
            story.append(Paragraph(pub_text, normal_style))

    story.append(Paragraph(f"Teaching Philosophy: {notes.get('teaching_philosophy', 'N/A')}", normal_style))
    story.append(Paragraph(f"Technology Tools: {notes.get('technology_tools', 'N/A')}", normal_style))
    story.append(Paragraph(f"Constraints: {notes.get('constraints', 'N/A')}", normal_style))
    story.append(Paragraph(f"Additional Interests and Hobbies: {notes.get('interests_hobbies', 'N/A')}", normal_style))

    if not certificates and not publications:
        story.append(Paragraph("No additional notes provided.", normal_style))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='my_application.pdf', mimetype='application/pdf')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('working_email')
    # username="sehanyasaru@gmail.com"

    connection = get_database_connection()
    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)


        cursor.execute("SELECT picture_path FROM identification WHERE username = %s", (username,))
        id_row = cursor.fetchone()
        profile_image_url = id_row['picture_path'] if id_row else '/static/default_profile.jpg'

        cursor.execute("SELECT full_name FROM personal_information WHERE username = %s", (username,))
        pi_row = cursor.fetchone()
        full_name = pi_row['full_name'] if pi_row else 'Unknown User'

        return render_template('dashboard.html',
                               username=username,
                               full_name=full_name,
                               profile_photo_url=profile_image_url)

    except Error as e:
        return f"Database error: {str(e)}", 500

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

def get_user_profile(username):

    return {
        'full_name': 'Alex Carter',
        'username': username,
        'profile_photo_url': '/static/images/profile_photo.jpg'
    }

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.route('/api/update_application', methods=['POST'])
def update_personal_information():
    connection = get_database_connection()
    if connection is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = None
    try:
        username = session.get('working_email')  # Hardcoded for testing; replace with
        if not username:
            return jsonify({"error": "Session expired or invalid. Please log in."}), 401

        form_data = request.form.to_dict(flat=False)
        files = request.files

        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM personal_information WHERE username = %s", (username,))
        existing_personal = cursor.fetchone()
        cursor.execute("SELECT * FROM identification WHERE username = %s", (username,))
        existing_identification = cursor.fetchone()
        cursor.execute("SELECT * FROM academic_qualifications WHERE username = %s", (username,))
        existing_academic = cursor.fetchone()
        cursor.execute("SELECT * FROM teaching_areas WHERE username = %s", (username,))
        existing_teaching = cursor.fetchone() or {}
        cursor.execute("SELECT * FROM professional_experience WHERE username = %s", (username,))
        existing_professional = cursor.fetchone() or {}
        cursor.execute("SELECT * FROM sample_teaching_materials WHERE username = %s", (username,))
        existing_teaching_materials = cursor.fetchone() or {}

        if not existing_personal or not existing_identification:
            cursor.close()
            return jsonify({"error": "No existing user found with this username"}), 404

        upload_folder = 'static/uploads'
        os.makedirs(upload_folder, exist_ok=True)

        # Handle file uploads
        picture = files.get('identification.picture_path')
        nic_passport_image = files.get('identification.nic_passport_image_path')
        picture_path = existing_identification.get('picture_path')
        if picture and picture.filename:
            if not picture.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({"error": "Profile picture must be PNG, JPG, or JPEG"}), 400
            picture_filename = f"{uuid.uuid4()}_{secure_filename(picture.filename)}"
            picture_path = os.path.join(upload_folder, picture_filename)
            picture.save(picture_path)

        nic_passport_image_path = existing_identification.get('nic_passport_image_path')
        if nic_passport_image and nic_passport_image.filename:
            if not nic_passport_image.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                return jsonify({"error": "NIC/Passport image must be PNG, JPG, or JPEG"}), 400
            nic_passport_image_filename = f"{uuid.uuid4()}_{secure_filename(nic_passport_image.filename)}"
            nic_passport_image_path = os.path.join(upload_folder, nic_passport_image_filename)
            nic_passport_image.save(nic_passport_image_path)


        personal_keys = [
            'title', 'full_name', 'phone_number', 'dob', 'Nationality',
            'country', 'Language', 'profile_link', 'conference_id',
            'work_permit', 'engagement_type', 'preffered_teaching'
        ]
        personal_updates = {}
        for key in personal_keys:
            form_key = f'personal_information.{key}'
            if form_key in form_data and form_data[form_key][0] is not None:
                personal_updates[key] = form_data[form_key][0]

        if personal_updates:
            set_clause = ', '.join([f"{key} = %s" for key in personal_updates])
            personal_update_query = f"UPDATE personal_information SET {set_clause} WHERE username = %s"
            cursor.execute(personal_update_query, list(personal_updates.values()) + [username])

        # Update identification
        identification_updates = {}
        if picture and picture.filename:
            identification_updates['picture_path'] = picture_path
        if nic_passport_image and nic_passport_image.filename:
            identification_updates['nic_passport_image_path'] = nic_passport_image_path
        if identification_updates:
            set_clause = ', '.join([f"{key} = %s" for key in identification_updates])
            identification_update_query = f"UPDATE identification SET {set_clause} WHERE username = %s"
            cursor.execute(identification_update_query, list(identification_updates.values()) + [username])

        # Update academic qualifications
        academic_updates = {}
        for key in ['thesis', 'certifications', 'online_courses']:
            form_key = f'academic_qualifications.{key}'
            if form_key in form_data and form_data[form_key][0] is not None:
                academic_updates[key] = form_data[form_key][0]

        existing_degrees = json.loads(existing_academic.get('degree', '[]')) if existing_academic and existing_academic.get('degree') else []
        updated_degrees = []
        degree_fields = ['degree', 'field', 'grade', 'institution', 'year']

        for i in range(max(len(existing_degrees), 100)):
            degree_data = {}
            has_data = False
            if i < len(existing_degrees):
                degree_data = existing_degrees[i].copy()

            for field in degree_fields:
                form_key = f'academic_qualifications.degrees[{i}].{field}'
                if form_key in form_data and form_data[form_key][0].strip() != '':
                    degree_data[field] = form_data[form_key][0]
                    has_data = True

            if has_data or i < len(existing_degrees):
                updated_degrees.append(degree_data)

        if updated_degrees or academic_updates:
            if existing_academic:
                academic_updates['degree'] = json.dumps(updated_degrees)
                academic_updates.setdefault('thesis', existing_academic.get('thesis', ''))
                academic_updates.setdefault('certifications', existing_academic.get('certifications', ''))
                academic_updates.setdefault('online_courses', existing_academic.get('online_courses', ''))

                set_clause = ', '.join([f"{key} = %s" for key in academic_updates])
                academic_update_query = f"UPDATE academic_qualifications SET {set_clause} WHERE username = %s"
                cursor.execute(academic_update_query, list(academic_updates.values()) + [username])
            else:
                academic_updates.setdefault('degree', json.dumps(updated_degrees))
                academic_updates.setdefault('thesis', '')
                academic_updates.setdefault('certifications', '')
                academic_updates.setdefault('online_courses', '')
                academic_insert_query = """
                    INSERT INTO academic_qualifications (username, degree, thesis, certifications, online_courses)
                    VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(academic_insert_query, (
                    username,
                    academic_updates['degree'],
                    academic_updates['thesis'],
                    academic_updates['certifications'],
                    academic_updates['online_courses']
                ))

        teaching_updates = {}
        teaching_keys = [
            'teaching_areas', 'subjects_topics', 'level_of_expertise', 'years_of_experience',
            'preferred_student_level', 'sample_topics', 'teaching_methodology', 'availability'
        ]
        for key in teaching_keys:
            form_key = f'teaching_areas.{key}'
            if form_key in form_data and form_data[form_key][0] is not None and form_data[form_key][0].strip() != '':
                if key == 'preferred_student_level':
                    # Convert comma-separated string to JSON array, handle empty or invalid input
                    value = form_data[form_key][0]
                    if value:
                        teaching_updates[key] = json.dumps([v.strip() for v in value.split(',') if v.strip()])
                    else:
                        teaching_updates[key] = json.dumps([])
                else:
                    teaching_updates[key] = form_data[form_key][0]

        if teaching_updates:
            if existing_teaching:
                # Update existing teaching areas record
                teaching_updates.setdefault('teaching_areas', existing_teaching.get('teaching_areas', ''))
                teaching_updates.setdefault('subjects_topics', existing_teaching.get('subjects_topics', ''))
                teaching_updates.setdefault('level_of_expertise', existing_teaching.get('level_of_expertise', ''))
                teaching_updates.setdefault('years_of_experience', existing_teaching.get('years_of_experience', ''))
                teaching_updates.setdefault('preferred_student_level', existing_teaching.get('preferred_student_level', '[]'))
                teaching_updates.setdefault('sample_topics', existing_teaching.get('sample_topics', ''))
                teaching_updates.setdefault('teaching_methodology', existing_teaching.get('teaching_methodology', ''))
                teaching_updates.setdefault('availability', existing_teaching.get('availability', ''))

                set_clause = ', '.join([f"{key} = %s" for key in teaching_updates])
                teaching_update_query = f"UPDATE teaching_areas SET {set_clause} WHERE username = %s"
                cursor.execute(teaching_update_query, list(teaching_updates.values()) + [username])
            else:
                # Insert new teaching areas record
                teaching_updates.setdefault('teaching_areas', '')
                teaching_updates.setdefault('subjects_topics', '')
                teaching_updates.setdefault('level_of_expertise', '')
                teaching_updates.setdefault('years_of_experience', '')
                teaching_updates.setdefault('preferred_student_level', json.dumps([]))
                teaching_updates.setdefault('sample_topics', '')
                teaching_updates.setdefault('teaching_methodology', '')
                teaching_updates.setdefault('availability', '')
                teaching_insert_query = """
                    INSERT INTO teaching_areas (
                        username, teaching_areas, subjects_topics, level_of_expertise, years_of_experience,
                        preferred_student_level, sample_topics, teaching_methodology, availability
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(teaching_insert_query, (
                    username,
                    teaching_updates['teaching_areas'],
                    teaching_updates['subjects_topics'],
                    teaching_updates['level_of_experience'],
                    teaching_updates['years_of_experience'],
                    teaching_updates['preferred_student_level'],
                    teaching_updates['sample_topics'],
                    teaching_updates['teaching_methodology'],
                    teaching_updates['availability']
                ))

        professional_updates = {}
        professional_keys = ['total_years_experience', 'key_achievements', 'relevant_projects']
        for key in professional_keys:
            form_key = f'professional_experience.{key}'
            if form_key in form_data and form_data[form_key][0] is not None and form_data[form_key][0].strip() != '':
                professional_updates[key] = form_data[form_key][0]

        existing_employment_history = json.loads(existing_professional.get('employment_history', '[]')) if existing_professional and existing_professional.get('employment_history') else []
        updated_employment_history = []
        employment_fields = ['employer', 'jobTitle', 'startDate', 'endDate', 'responsibilities']

        for i in range(max(len(existing_employment_history), 100)):
            employment_data = {}
            has_data = False
            if i < len(existing_employment_history):
                employment_data = existing_employment_history[i].copy()

            for field in employment_fields:
                form_key = f'professional_experience.employment_history[{i}].{field}'
                if form_key in form_data and form_data[form_key][0].strip() != '':
                    employment_data[field] = form_data[form_key][0]
                    has_data = True

            if has_data or i < len(existing_employment_history):
                updated_employment_history.append(employment_data)

        if updated_employment_history or professional_updates:
            if existing_professional:
                professional_updates['employment_history'] = json.dumps(updated_employment_history)
                professional_updates.setdefault('total_years_experience', existing_professional.get('total_years_experience', ''))
                professional_updates.setdefault('key_achievements', existing_professional.get('key_achievements', ''))
                professional_updates.setdefault('relevant_projects', existing_professional.get('relevant_projects', ''))

                set_clause = ', '.join([f"{key} = %s" for key in professional_updates])
                professional_update_query = f"UPDATE professional_experience SET {set_clause} WHERE username = %s"
                cursor.execute(professional_update_query, list(professional_updates.values()) + [username])
            else:
                professional_updates.setdefault('employment_history', json.dumps(updated_employment_history))
                professional_updates.setdefault('total_years_experience', '')
                professional_updates.setdefault('key_achievements', '')
                professional_updates.setdefault('relevant_projects', '')
                professional_insert_query = """
                    INSERT INTO professional_experience (
                        username, employment_history, total_years_experience, key_achievements, relevant_projects
                    ) VALUES (%s, %s, %s, %s, %s)
                """
                cursor.execute(professional_insert_query, (
                    username,
                    professional_updates['employment_history'],
                    professional_updates['total_years_experience'],
                    professional_updates['key_achievements'],
                    professional_updates['relevant_projects']
                ))

        teaching_materials_updates = {}
        teaching_materials_keys = ['additional_notes']
        for key in teaching_materials_keys:
            form_key = f'sample_teaching_materials.{key}'
            if form_key in form_data and form_data[form_key][0] is not None and form_data[form_key][0].strip() != '':
                teaching_materials_updates[key] = form_data[form_key][0]

        existing_teaching_materials_data = json.loads(existing_teaching_materials.get('teaching_materials', '[]')) if existing_teaching_materials and existing_teaching_materials.get('teaching_materials') else []
        updated_teaching_materials = []
        teaching_materials_fields = ['materialType', 'title', 'description', 'filePath']

        for i in range(max(len(existing_teaching_materials_data), 100)):
            material_data = {}
            has_data = False
            if i < len(existing_teaching_materials_data):
                material_data = existing_teaching_materials_data[i].copy()

            for field in teaching_materials_fields:
                form_key = f'sample_teaching_materials.teaching_materials[{i}].{field}'
                if form_key in form_data and form_data[form_key][0].strip() != '':
                    material_data[field] = form_data[form_key][0]
                    has_data = True

            file_key = f'sample_teaching_materials.teaching_materials[{i}].filePath'
            if file_key in files and files[file_key].filename:
                file = files[file_key]
                material_type = material_data.get('materialType', 'Other')
                if not allowed_file(file.filename, material_type):
                    allowed = ALLOWED_EXTENSIONS.get(material_type, {'pdf'})
                    return jsonify({"error": f"Invalid file type for material {i+1}. Allowed: {', '.join(allowed)}"}), 400
                file_filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                file_path = os.path.join(upload_folder, file_filename)
                file.save(file_path)
                material_data['filePath'] = file_filename
                has_data = True

            if has_data or i < len(existing_teaching_materials_data):
                updated_teaching_materials.append(material_data)

        teaching_video_path = existing_teaching_materials.get('teaching_video', '')
        if 'sample_teaching_materials.teaching_video' in files and files['sample_teaching_materials.teaching_video'].filename:
            teaching_video = files['sample_teaching_materials.teaching_video']
            if teaching_video.mimetype not in ['video/mp4', 'video/webm'] or not allowed_file(teaching_video.filename, 'Video'):
                return jsonify({"error": "Teaching video must be MP4 or WebM"}), 400
            video_filename = f"{uuid.uuid4()}_{secure_filename(teaching_video.filename)}"
            teaching_video_path = os.path.join(upload_folder, video_filename)
            teaching_video.save(teaching_video_path)
            teaching_materials_updates['teaching_video'] = video_filename

        if updated_teaching_materials or teaching_materials_updates or teaching_video_path:
            if existing_teaching_materials:
                teaching_materials_updates['teaching_materials'] = json.dumps(updated_teaching_materials)
                teaching_materials_updates.setdefault('additional_notes', existing_teaching_materials.get('additional_notes', ''))
                teaching_materials_updates.setdefault('teaching_video', existing_teaching_materials.get('teaching_video', ''))

                set_clause = ', '.join([f"{key} = %s" for key in teaching_materials_updates])
                teaching_materials_update_query = f"UPDATE sample_teaching_materials SET {set_clause} WHERE username = %s"
                cursor.execute(teaching_materials_update_query, list(teaching_materials_updates.values()) + [username])
            else:
                teaching_materials_updates.setdefault('teaching_materials', json.dumps(updated_teaching_materials))
                teaching_materials_updates.setdefault('additional_notes', '')
                teaching_materials_updates.setdefault('teaching_video', teaching_video_path)
                teaching_materials_insert_query = """
                    INSERT INTO sample_teaching_materials (
                        username, teaching_materials, teaching_video, additional_notes
                    ) VALUES (%s, %s, %s, %s)
                """
                cursor.execute(teaching_materials_insert_query, (
                    username,
                    teaching_materials_updates['teaching_materials'],
                    teaching_materials_updates['teaching_video'],
                    teaching_materials_updates['additional_notes']
                ))

        payment_updates = {}
        payment_fields = ['payment_currency', 'hourly_rate', 'monthly_rate', 'payment_method', 'negotiable', 'invoicing_cycle']
        for field in payment_fields:
            form_key = f'payment_information.{field}'
            if form_key in form_data and form_data[form_key][0] is not None:
                payment_updates[field] = form_data[form_key][0] if field != 'monthly_rate' else (form_data[form_key][0] or None)

        cursor.execute("SELECT * FROM payment_information WHERE username = %s", (username,))
        existing_payment = cursor.fetchone()

        if payment_updates:
            if existing_payment:
                payment_updates.setdefault('payment_currency', existing_payment.get('payment_currency', ''))
                payment_updates.setdefault('hourly_rate', existing_payment.get('hourly_rate', ''))
                payment_updates.setdefault('monthly_rate', existing_payment.get('monthly_rate', None))
                payment_updates.setdefault('payment_method', existing_payment.get('payment_method', ''))
                payment_updates.setdefault('negotiable', existing_payment.get('negotiable', ''))
                payment_updates.setdefault('invoicing_cycle', existing_payment.get('invoicing_cycle', ''))
                set_clause = ', '.join([f"{key} = %s" for key in payment_updates])
                payment_update_query = f"UPDATE payment_information SET {set_clause} WHERE username = %s"
                cursor.execute(payment_update_query, list(payment_updates.values()) + [username])
            else:
                payment_updates.setdefault('payment_currency', '')
                payment_updates.setdefault('hourly_rate', '')
                payment_updates.setdefault('monthly_rate', None)
                payment_updates.setdefault('payment_method', '')
                payment_updates.setdefault('negotiable', '')
                payment_updates.setdefault('invoicing_cycle', '')
                payment_insert_query = """
                    INSERT INTO payment_information (
                        username, payment_currency, hourly_rate, monthly_rate, payment_method, negotiable, invoicing_cycle
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(payment_insert_query, (
                    username,
                    payment_updates['payment_currency'],
                    payment_updates['hourly_rate'],
                    payment_updates['monthly_rate'],
                    payment_updates['payment_method'],
                    payment_updates['negotiable'],
                    payment_updates['invoicing_cycle']
                ))

        additional_notes_updates = {}
        additional_notes_fields = ['teaching_philosophy', 'constraints', 'interests_hobbies']
        for field in additional_notes_fields:
            form_key = f'additional_notes.{field}'
            if form_key in form_data and form_data[form_key][0] is not None:
                additional_notes_updates[field] = form_data[form_key][0]

        # Handle technology_tools
        tools = []
        for i in range(10):
            form_key = f'additional_notes.technology_tools_{i}'
            if form_key in form_data and form_data[form_key][0]:
                tools.append(form_data[form_key][0])
        if tools:
            additional_notes_updates['technology_tools'] = ','.join(tools)

        # Handle certificates
        certificates = []
        for i in range(10):
            desc_key = f'additional_notes.certificates[{i}].description'
            file_key = f'additional_notes.certificates[{i}].file_path'
            desc = form_data.get(desc_key, [''])[0] if desc_key in form_data else ''
            file = request.files.get(file_key)
            if desc:
                file_path = None
                if file and file.filename and allowed_file_new(file.filename, 'Document'):
                    filename = secure_filename(f"{username}_cert_{i}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER_NEW'], filename)
                    try:
                        file.save(file_path)
                        print(f"[DEBUG] Saved certificate to {os.path.abspath(file_path)}")
                    except Exception as e:
                        print(f"[ERROR] Failed to save certificate: {str(e)}")
                        file_path = None
                certificates.append({'description': desc, 'file_path': file_path})
        if certificates:
            additional_notes_updates['certificates'] = json.dumps(certificates)

        # Handle publications
        publications = []
        for i in range(10):
            desc_key = f'additional_notes.publications[{i}].description'
            file_key = f'additional_notes.publications[{i}].file_path'
            desc = form_data.get(desc_key, [''])[0] if desc_key in form_data else ''
            file = request.files.get(file_key)
            if desc:
                file_path = None
                if file and file.filename and allowed_file_new(file.filename, 'Document'):
                    filename = secure_filename(f"{username}_pub_{i}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER_NEW'], filename)
                    try:
                        file.save(file_path)
                        print(f"[DEBUG] Saved publication to {os.path.abspath(file_path)}")
                    except Exception as e:
                        print(f"[ERROR] Failed to save publication: {str(e)}")
                        file_path = None
                publications.append({'description': desc, 'file_path': file_path})
        if publications:
            additional_notes_updates['publications'] = json.dumps(publications)

        # Validate required fields
        cursor.execute("SELECT * FROM additional_notes WHERE username = %s", (username,))
        existing_notes = cursor.fetchone()
        required_fields = ['teaching_philosophy', 'constraints', 'technology_tools']
        for field in required_fields:
            if field not in additional_notes_updates and not existing_notes:
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        if additional_notes_updates:
            if existing_notes:
                additional_notes_updates.setdefault('teaching_philosophy', existing_notes.get('teaching_philosophy', ''))
                additional_notes_updates.setdefault('constraints', existing_notes.get('constraints', ''))
                additional_notes_updates.setdefault('interests_hobbies', existing_notes.get('interests_hobbies', ''))
                additional_notes_updates.setdefault('technology_tools', existing_notes.get('technology_tools', ''))
                additional_notes_updates.setdefault('certificates', existing_notes.get('certificates', '[]'))
                additional_notes_updates.setdefault('publications', existing_notes.get('publications', '[]'))
                set_clause = ', '.join([f"{key} = %s" for key in additional_notes_updates])
                notes_update_query = f"UPDATE additional_notes SET {set_clause} WHERE username = %s"
                cursor.execute(notes_update_query, list(additional_notes_updates.values()) + [username])
            else:
                additional_notes_updates.setdefault('teaching_philosophy', '')
                additional_notes_updates.setdefault('constraints', '')
                additional_notes_updates.setdefault('interests_hobbies', '')
                additional_notes_updates.setdefault('technology_tools', '')
                additional_notes_updates.setdefault('certificates', '[]')
                additional_notes_updates.setdefault('publications', '[]')
                notes_insert_query = """
                    INSERT INTO additional_notes (
                        username, teaching_philosophy, constraints, interests_hobbies, technology_tools, certificates, publications
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(notes_insert_query, (
                    username,
                    additional_notes_updates['teaching_philosophy'],
                    additional_notes_updates['constraints'],
                    additional_notes_updates['interests_hobbies'],
                    additional_notes_updates['technology_tools'],
                    additional_notes_updates['certificates'],
                    additional_notes_updates['publications']
                ))

        connection.commit()
        cursor.close()
        return jsonify({"message": "Application updated successfully!"}), 200

    except Error as e:
        if connection and not connection.autocommit:
            connection.rollback()
        return jsonify({"error": f"Failed to update application: {str(e)}"}), 500
    except Exception as e:
        if connection and not connection.autocommit:
            connection.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

if __name__ == '__main__':
    app.run(debug=True)