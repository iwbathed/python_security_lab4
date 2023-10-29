import pyotp
import qrcode


from datetime import datetime, timedelta

import requests

from flask import Flask, render_template, request, flash, redirect, url_for, make_response, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
import sqlalchemy as sa
from flask_sqlalchemy import SQLAlchemy
from pyotp import TOTP

from config import SECRET_KEY, DEBUG_STATE, MAX_LOGIN_ATTEMPTS, BLOCK_TIME_SECONDS

from hash import encrypt_password, check_hash
from model import db, User
from password_validation import validate_password
from recaptcha_settings import RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY, VERIFY_URL
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.secret_key = SECRET_KEY
db.init_app(app)
engine = sa.create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
inspector = sa.inspect(engine)

if not inspector.has_table("user"):
    with app.app_context():
        db.drop_all()
        db.create_all()
        app.logger.info('Initialized the database!')

        print('Initialized the database!')
else:
    app.logger.info('Database already contains the users table.')


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':

        secret_response = request.form['g-recaptcha-response']
        verify_response = \
            requests.post(url=f'{VERIFY_URL}?secret={RECAPTCHA_SECRET_KEY}&response={secret_response}').json()
        if not verify_response['success'] or verify_response['score'] < 0.5:
            abort(403)
        username = request.form.get('username')
        password = request.form.get('password')
        block_time = session.get('block_time')
        if block_time and datetime.now() < block_time.replace(tzinfo=None):
            return f"Доступ заборонено до {block_time.replace(tzinfo=None)}"

        user = User.query.filter_by(username=username).first()
        if user:
            if check_hash(password, user.password_hash):
                otp_secret = user.otp_secret
                otp_verif_code = request.form.get('user_otp_verif_code')

                otp = pyotp.TOTP(otp_secret)
                res = otp.verify(otp_verif_code)

                if not res:
                    return "Неправильно введений код!"

                session.pop('login_attempts', None)
                session.pop('block_time', None)
                return redirect(url_for('user', username=username))
            else:
                message = 'Неправильно введений пароль!'
                login_attempts = session.get('login_attempts', 0)
                login_attempts += 1
                session['login_attempts'] = login_attempts
                if login_attempts >= MAX_LOGIN_ATTEMPTS:
                    session['block_time'] = datetime.now() + timedelta(seconds=BLOCK_TIME_SECONDS)
                    return f"Доступ заборонено до {session['block_time']}."
        else:
            message = 'Користувача з таким логіном не існує!'
    return render_template('login.html', message=message, site_key=RECAPTCHA_SITE_KEY)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        secret_response = request.form['g-recaptcha-response']
        verify_response = \
            requests.post(url=f'{VERIFY_URL}?secret={RECAPTCHA_SECRET_KEY}&response={secret_response}').json()
        if not verify_response['success'] or verify_response['score'] < 0.5:
            abort(403)

        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')


        # Перевірка, чи користувач із таким логіном вже існує
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Користувач із таким логіном вже існує', 'error')
            return render_template('register.html')
        else:
            # Перевірка, чи пароль відповідає вимогам
            password_error = validate_password(password)

            if password_error:

                flash(password_error, 'error')
            else:
                hashed_password = encrypt_password(password)


                # otp_secret = request.form.get('otp_secret')
                # print(otp_secret)
                # print(otp_secret.replace('amp;', ''))
                # otp_verif_code = request.form.get('otp_verif_code')
                #
                # res = pyotp.parse_uri(otp_secret.replace('amp;', '')).verify(otp_verif_code)
                # print(res)

                otp_secret = request.form.get('otp_secret')
                otp_verif_code = request.form.get('otp_verif_code')
                # Розділити otp_secret на параметри
                otp_parameters = otp_secret.split('?')[1]  # Отримуємо частину параметрів після знаку питання
                # Парсимо параметри і отримуємо значення 'secret'
                secret = otp_parameters.split('secret=')[1].split('&')[0]
                # Створюємо об'єкт OTP
                otp = pyotp.TOTP(secret)

                one_time_password = otp.now()
                print(one_time_password)
                print(otp_verif_code)


                res = otp.verify(otp_verif_code)

                if not res:
                    return "Неправильно введений код!"
                new_user = User(username=username,
                                password_hash=hashed_password,
                                otp_secret=otp_secret
                                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('user',
                                        username=username))
    otp_secret = pyotp.totp.TOTP(pyotp.random_base32()).provisioning_uri(name="temp", issuer_name='Lab4')
    return render_template('register.html', site_key=RECAPTCHA_SITE_KEY, otp_secret=otp_secret)


@login_required
@app.route('/user/<username>')
def user(username):
    current_user = User.query.filter_by(username=username).first()
    if current_user:
        if current_user.is_authenticated and current_user.username == username:
            if current_user.otp_secret:
                # User has 2FA enabled; ask for the 2FA code
                return render_template('login_2fa.html')
            else:
                # User does not have 2FA; proceed with the existing user page
                return render_template('user.html', username=username)

        else:
            return "Доступ заборонено."
    else:
        return "Користувача з іменем {{ username }} не знайдено."

if __name__ == '__main__':
    app.run(debug=DEBUG_STATE)
