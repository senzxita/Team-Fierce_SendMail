from flask import render_template, request, make_response, jsonify, redirect
from markupsafe import Markup, escape
import config
from mail.flask_mail import flask_plain_email, flask_template_email, mail
from flask_mail import Message
from config import mail, db, app
from auth import token_required, check_password_hash, generate_password_hash, datetime, jwt, uuid, Users 

# Get the application instance
connex_app = config.connex_app

# Read the swagger.yml file to configure the endpoints
connex_app.add_api("swagger.yml")

@connex_app.route('/')
def documentation():
    return redirect('/v1/ui')

@connex_app.route('/v1/documentation')
def json_documentation():
    return redirect('/v1/swagger.json')


@connex_app.route('/v1/configure')
def key_value_json():
    return redirect('/v1/ui')

@connex_app.route('/v1/sendmail/interface')
def home():
    return render_template('home.html')

@connex_app.route('/v1/sendmail/demo')
def send_email():
    return render_template('create.html')


@connex_app.route('/sendmail/html', methods=['POST'])
def sendmail_html():
    if request.method == 'POST':
        subject = Markup.escape(request.form['subject'])
        message = '<strong>'+ request.form['message'] +'</strong>'
        recipients = request.form['recipients']
        mail_list = recipients.split(',')
        len_list = len(mail_list) - 1
        if recipients != '' or message != '' or subject != '':
            with mail.connect() as conn:
                while len_list > -1:
                    msg = Message(recipients=[mail_list[len_list]], html=message, subject=subject)
                    
                    try:
                        conn.send(msg)
                        response = {
                            'status': 'success',
                            'data':{
                                'message': 'Mail sent successfully'
                            }
                        }
                        status = 200
                    except Exception:
                        response = {
                            'status': 'error',
                            'data':{
                                'message': 'Error: Mail was not sent.'
                            }
                        }
                        status = 500
                    len_list -= 1
                return make_response(jsonify(response), status)


@connex_app.route('/sendmail/text', methods=['POST'])
def sendmail_text():
    if request.method == 'POST':
        subject = Markup.escape(request.form['subject'])
        message = Markup.escape(request.form['message'])
        recipients = request.form['recipients']
        mail_list = recipients.split(',')
        len_list = len(mail_list) - 1
        if recipients != '' or message != '' or subject != '':
            with mail.connect() as conn:
                while len_list > -1:
                    msg = Message(recipients=[mail_list[len_list]], body=message, subject=subject)
       
                    try:
                        conn.send(msg)
                        response = {
                            'status': 'success',
                            'data':{
                                'message': 'Mail sent successfully'
                            }
                        }
                        status = 200
                    except Exception:
                        response = {
                            'status': 'error',
                            'data':{
                                'message': 'Error: Mail was not sent.'
                            }
                        }
                        status = 500
                    len_list -= 1
                return make_response(jsonify(response), status)
                    


#Register for token access
@connex_app.route('/v1/auth/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    username = data['username']
    new_user = Users(public_id=str(uuid.uuid4()), username=username, password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'registered successfully'})
 

#Login 
@connex_app.route('/v1/auth/login', methods=['GET', 'POST'])
def login_user():

  auth = request.authorization

  if not auth or not auth.username or not auth.password:
     return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

  user = Users.query.filter_by(username=auth.username).first()

  if check_password_hash(user.password, auth.password):
     token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=1080)}, app.config['SECRET_KEY'])
     return jsonify({'token' : token.decode('UTF-8')})

  return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})



#Retrieve all registered users
@connex_app.route('/v1/auth/users', methods=['GET'])
def get_all_users():

   users = Users.query.all()

   result = []

   for user in users:
       user_data = {}
       user_data['public_id'] = user.public_id
       user_data['username'] = user.username
       user_data['password'] = user.password
       user_data['admin'] = user.admin

       result.append(user_data)

   return jsonify({'users': result})



if __name__ == '__main__':
    connex_app.run(host='127.0.0.1', port=5000, debug=True)