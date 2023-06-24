from flask import Blueprint, Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
import pymysql
import os
import paho.mqtt.client as mqtt
import json
app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'lock'
app.secret_key = 'your_secret_key'


mail = Mail(app)
def get_db():
    if not hasattr(pymysql, '_connection'):
        pymysql._connection = pymysql.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            db=app.config['MYSQL_DB'],
            cursorclass=pymysql.cursors.DictCursor
        )
    return pymysql._connection



import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
import json

def on_message(client, userdata, message):
    topic = message.topic
    payload = message.payload.decode('utf-8')
    print(f"Received message '{payload}' on topic '{topic}'")

def send_message(topic, message):
    # create a client instance
    client = mqtt.Client()

    # connect to the broker
    client.connect("localhost", 1883, 60)

    # publish the message to the specified topic
    client.publish(topic, message)

    # disconnect from the broker
    client.disconnect()



# Définir la fonction qui sera appelée lorsque des données sont reçues sur le topic


# Définir la route Flask pour récupérer l'état de la laverie
def get_available_slots():
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT time FROM reservations4")
    reservations = cursor.fetchall()
    cursor.close()

    slots = {time_str: "available" for time_str in [f"{hour:02d}:00" for hour in range(0, 24)]}

    for reservation in reservations:
        try:
            time_str = reservation['time']  # Assuming the time is retrieved as 'HH:MM' in a dictionary
            hour = int(time_str.split(":")[0])
            slots[time_str] = "reserved"
        except (KeyError, IndexError):
            # Handle the case where the reservation object does not contain the expected time value
            # You can log an error message or take appropriate action based on your application's needs
            pass

    return slots




@app.route('/etat_laverie', methods=['GET'])
def etat_laverie():
    available_slots = get_available_slots()
    return jsonify(available_slots)

from werkzeug.utils import secure_filename


# from flask_uploads import UploadSet, IMAGES
# photos = UploadSet('photos', IMAGES) 

# Configurez l'ensemble de téléchargement pour accepter uniquement les images


@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if 'profile_image' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('profile'))
    
    # Enregistrez le fichier téléchargé
    filename = photos.save(request.files['profile_image'])
    
    # Mettez à jour le nom du fichier d'image du profil dans la base de données
    cur = get_db().cursor()
    cur.execute("UPDATE `lock4` SET profile_image = %s WHERE username = %s", (filename, session['username']))
    get_db().commit()
    cur.close()
    
    flash('Profile image uploaded successfully', 'success')
    return redirect(url_for('profile'))


import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish

@app.route('/reserver_machine', methods=['POST'])
def reserver_machine():
    # Récupérer les données du formulaire
    id_utilisateur = request.form['id_utilisateur']
    nom = request.form['nom']
    nom1 = request.form['nom1']
    time = request.form['time']
    mode_utilisation =request.form['mode_utilisation']
    print(mode_utilisation)

    # Stocker les données dans la base de données
    cur = get_db().cursor()
    cur.execute("INSERT INTO reservations4 (nom, prenom, mode_lavage,time) VALUES(%s,%s, %s,%s)", (nom,nom1, mode_utilisation ,time))
    get_db().commit()
    cur.close()
    
    # Envoyer un message à votre Raspberry Pi pour indiquer la réservation
    message = id_utilisateur  + '|' + nom + '|' + nom1 +'|' + mode_utilisation + '|' + time 
    username = "myuser"
    password = "ZAKARIA1234"
    port = 1883
        # Publish the message to the MQTT broker
    publish.single("reservations/machine_laver", message, hostname="169.254.160.100",port=port,auth={'username': username, 'password': password})
    response = {'status': 'success', 'message': 'La machine a été réservée avec succès.'}
   
    
    # Retourner une réponse JSON indiquant que la réservation a été effectuée avec succès
    return jsonify(response)




@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        msg = Message('New message from your Flask app', sender='your-email@gmail.com', recipients= email)
        msg.body = f'Name: {name}\nEmail: {email}\nMessage: {message}'
        mail.send(msg)

        return 'Thank you for your message!'

    return render_template('reset_password.html')

# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

# Page de connexion<

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Vérification des identifiants
        username = request.form['username']
        password = request.form['password'] 
        # Recherchez les informations d'identification dans la base de données
        cur = get_db().cursor()
        cur.execute("SELECT * FROM `lock3` WHERE username = %s AND password = %s", (username, password))
        user = cur.fetchone()
        cur.close()
        if user is not None:
            # Stockez l'identifiant de l'utilisateur dans la session Flask
            session['username'] = user['username']
            # Set a cookie with the username
            response = redirect(url_for('dashboard'))
            response.set_cookie('username', user['username'])
            return response
        else:
            return render_template('login.html', error='Identifiants incorrects')
    else:
        return render_template('login.html')



# Route pour la page du tableau de bord
@app.route('/changepassword', methods=['GET', 'POST'])
def changepassword():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Récupération des informations du formulaire
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        # Vérification de la validité des informations
        if new_password != confirm_password:
            return render_template('changepassword.html', error='Le nouveau mot de passe et la confirmation ne correspondent pas')
        # Vérification des anciennes informations d'identification
        cur = get_db().cursor()
        cur.execute("SELECT * FROM `lock3` WHERE username = %s AND password = %s", (session['username'], old_password))
        user = cur.fetchone()
        if user is None:
            cur.close()
            return render_template('changepassword.html', error='Mot de passe actuel incorrect')
        # Mise à jour du mot de passe dans la base de données
        cur.execute("UPDATE `lock3` SET password = %s WHERE username = %s", (new_password, session['username']))
        get_db().commit()
        cur.close()
        # Redirection vers la page de tableau de bord après la mise à jour du mot de passe
        return redirect(url_for('dashboard'))
    else:
        return render_template('changepassword.html')

# Route pour la page du tableau de bord
@app.route('/dashboard')
def dashboard():
    # Vérifiez si l'utilisateur est connecté
    if 'username' in session:
        # Récupérez le nom d'utilisateur stocké dans la session
        username = session['username']
        # Si oui, affichez la page du tableau de bord avec le nom d'utilisateur
        return render_template('dashboard.html', username=username)
    else:
        # Sinon, redirigez l'utilisateur vers la page de connexion
        return redirect(url_for('login'))

def est_connecte():
    return 'user_id' in session

app.config['MAIL_SERVER'] = 'smtp-relay.sendinblue.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'midine.zakaria00@gmail.com'
app.config['MAIL_PASSWORD'] = 'Yy7qsaIJ1TAFjnm6'
app.config['MAIL_DEFAULT_SENDER'] = 'midine.zakaria00@gmail.com'

mail = Mail(app)

@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    if request.method == 'POST':
        # Récupérez les données du formulaire
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Générez un token unique pour l'utilisateur
        token = secrets.token_hex(16)
        
        # Ajoutez l'utilisateur à la base de données avec le token
        cur = get_db().cursor()
        cur.execute("INSERT INTO `lock3`(username, password, email, token) VALUES(%s, %s, %s, %s)", (username, password, email, token))
        get_db().commit()
        cur.close()
        
         
        # Redirigez vers la page de connexion
        return redirect(url_for('login'))
    else:
        return render_template('inscription.html')

@app.route('/confirm-account/<token>')
def confirm_account(token):
    # Vérifiez si le token est valide
    cur = get_db().cursor()
    cur.execute("SELECT * FROM `lock3` WHERE token = %s", (token,))
    user = cur.fetchone()
    if user is None:
        return 'Token invalide ou expiré'
    
    # Marquez le compte de l'utilisateur comme confirmé
    cur.execute("UPDATE `lock` SET confirmed = 1 WHERE id = %s", (user['id'],))
    get_db().commit()
    cur.close()


        #result = cur.fetchone()
        #if result[0] > 0:
       

from werkzeug.utils import secure_filename



user_bp = Blueprint('user', __name__, url_prefix='/user')

@app.route('/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Récupérer les informations de l'utilisateur connecté depuis la base de données
    cur = get_db().cursor()
    cur.execute("SELECT username, MatriculeEtudiant FROM `lock4` WHERE username = %s", (session['username'],))
    user = cur.fetchone()
    cur.close()
    
    return render_template('profile.html', user=user)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.photo = filename
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('user.profile'))
    return render_template('edit_profile.html', user=user)

import secrets

def generate_reset_token(email):
    token = secrets.token_urlsafe()
    # Store the token and associated email in your database for later use
    return token
@app.route('/reset_password_confirm/<token>')
def reset_password_confirm(token):
    # Vérifier si le jeton de réinitialisation est valide et afficher un formulaire de réinitialisation de mot de passe
    return render_template('reset_confirmation.html')

# Page d'�tat de la laverie
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        # Vérifier si l'adresse e-mail existe dans la base de données
        # Si oui, générer un jeton de réinitialisation unique et l'envoyer à l'utilisateur par e-mail
        token = generate_reset_token(email)
        reset_url = url_for('reset_password_confirm', token=token, _external=True)

        msg = Message('Réinitialisation de mot de passe', sender='votre_adresse_email@gmail.com', recipients=[email])
        msg.body = f'Cliquez sur ce lien pour réinitialiser votre mot de passe : {reset_url}'

        mail.send(msg)
        # Stocker le jeton de réinitialisation dans la base de données pour une utilisation ultérieure
        # Rediriger l'utilisateur vers une page de confirmation
    return render_template('reset.html')
@app.route('/logout')
def logout():
    # Supprimer l'ID de l'utilisateur de la session Flask
    session.pop('username', None)
    # Rediriger l'utilisateur vers la page d'accueil
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    email = request.args.get('email')
    
    if request.method == 'POST':
        # Get the new password entered by the user
        new_password = request.form['new_password']
        
        # Perform any necessary password change actions, such as updating the database, etc.
        # For this example, we will simply display a success message
        
        # Display a success message to the user
        return render_template('forgot_passwordd.html', email=email)
    
    # If the request method is GET, display the password change form
    return render_template('forgot_passwordd.html', email=email)


@app.route('/laverie')
def laverie():
    # Logique pour r�cup�rer l'�tat de la laverie
    etat_laverie = {'machine_1': 'en fonctionnement', 'machine_2': 'hors service'}
    return render_template('laverie.html', etat_laverie=etat_laverie)
@app.route('/About')
def About():
         return render_template('AboutUs.html')
@app.route('/reserver', methods=['GET', 'POST'])
def reserver():
    if request.method == 'POST':
        # Logique pour enregistrer la réservation dans la base de données
     
        return redirect(url_for('laverie'))
    else:
        # Logique pour récupérer la liste des machines disponibles
        machines_disponibles = ['Machine 3', 'Machine 5']
        return render_template('reserver.html', machines=machines_disponibles)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')













   



