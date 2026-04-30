from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import timedelta, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_simple_captcha import CAPTCHA
import credits as cr
from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, SASL, GSSAPI
from ldap3.core.exceptions import LDAPBindError, LDAPException
import win32security
import win32api
import winkerberos

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pymssql://{cr.login}:{cr.password}@{cr.server}:1433/{cr.firstDB}"
app.config['SQLALCHEMY_BINDS'] = {
    'use_db': f"mssql+pymssql://{cr.login}:{cr.password}@{cr.server}:1433/{cr.secondDB}"
}
db = SQLAlchemy(app)
app.secret_key = f'{cr.secret_key}'
app.permanent_session_lifetime = timedelta(minutes=3)
SIMPLE_CAPTCHA = CAPTCHA(config=cr.YOUR_CONFIG)
app = SIMPLE_CAPTCHA.init_app(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(200), nullable=False)

class Role(db.Model):
    __bind_key__ = 'use_db'
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(20))

class UserInfo(db.Model):
    __bind_key__ = 'use_db'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    surname = db.Column(db.String(20))
    login = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(32))
    role = db.Column(db.Integer, db.ForeignKey('role.id'))
    datebirth = db.Column(db.Date)

with app.app_context():
    db.create_all()

@app.route('/', methods=['POST', 'GET'])
@app.route('/reg', methods=['POST', 'GET'])
def reg():
    generatedCaptcha = SIMPLE_CAPTCHA.create()
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']
        repeatPassword = request.form['repeatpassword']
        if password != repeatPassword:
            return render_template('reg.html', error="Пароли не совпадают", captcha=generatedCaptcha)
        else:
            c_hash = request.form.get('captcha-hash')
            c_text = request.form.get('captcha-text')
            if not SIMPLE_CAPTCHA.verify(c_text, c_hash):
                return render_template('reg.html', error="Неверная капча", captcha=generatedCaptcha)
            else:
                password = generate_password_hash(password)
                user = Users(login=login, password=password)

        try:
            sql = text(f"INSERT INTO {cr.firstDB}.dbo.users VALUES('{login}', '{password}')")
            db.session.execute(sql)
            db.session.commit()
            
            session.permanent = True
            session['login'] = login
            return redirect('/main')
        except:
            return render_template('reg.html', error="Данный пользователь уже существует", captcha=generatedCaptcha)
    else:
        return render_template('reg.html', captcha=generatedCaptcha)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        ad = request.form.get('AD')
    
        login = request.form['login']
        password = request.form['password']

        if not ad:
            user = Users.query.filter_by(login=login).first()
            
            if not user:
                return render_template('login.html', error="Пользователя не существует")

            if not check_password_hash(user.password, password):
                return render_template('login.html', error="Неверный пароль")
            else:
                session.permanent = True
                session['login'] = login
                return redirect('/main')
        else:
            LDAP_SERVER = 'ldap://internet.loc'
            LDAP_USER_DN_TEMPLATE = '{login}@internet.loc'
            user_dn = LDAP_USER_DN_TEMPLATE.format(login=login)
            try:
                server = Server(LDAP_SERVER, get_info=ALL)
                conn = Connection(server, user=user_dn, password=password, auto_bind=False)
                
                if conn.bind():
                    conn.unbind()
                    session['login'] = login
                    if not UserInfo.query.filter_by(login=login).first():
                        user = UserInfo(login=username)
                        db.session.add(user)
                        db.session.commit()
                    return redirect('/main')
                else:
                    return render_template('login.html', error="Неверный логин или пароль")

            except LDAPBindError:
                return render_template('login.html', error="Неверный логин или пароль")
            except Exception as e:
                return render_template('login.html', error=f"Ошибка подключения к LDAP: {str(e)}")

    else:
        if 'login' in session:
            return redirect('/main')

        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_QUERY
            )
            user_info = win32security.GetTokenInformation(token, win32security.TokenUser)
            sid = user_info[0]
            username, domain, _ = win32security.LookupAccountSid(None, sid)

            spn = "ldap/DC.internet.loc"

            result, context = winkerberos.authGSSClientInit(
                spn,
                gssflags=winkerberos.GSS_C_MUTUAL_FLAG | winkerberos.GSS_C_SEQUENCE_FLAG
            )

            winkerberos.authGSSClientStep(context, "")
            kerberos_token = winkerberos.authGSSClientResponse(context)

            server = Server("ldap://DC.internet.loc", get_info=ALL)
            conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=True
            )
 
            try:
                session['login'] = username
                if not UserInfo.query.filter_by(login=username).first():
                    user = UserInfo(login=username)
                    db.session.add(user)
                    db.session.commit()
                return redirect('/main')
            except:
                return render_template('login.html', error="Ошибка добавление в БД")

        except Exception as e:
            return render_template('login.html', error=f'Ошибка SSO: {str(e)}')

@app.route('/main')
def main():
    if 'login' not in session:
        return redirect('/login')

    return render_template('main.html', login=session['login'])

@app.route('/logout')
def logout():
    session.pop('login', None)
    return redirect('/login')

@app.route('/changepassword', methods=['POST', 'GET'])
def changepassword():
    if 'login' not in session:
        return redirect('/login')
    
    if request.method == "POST":
        oldpassword = request.form['oldpassword']
        newpassword = request.form['newpassword']

        user = Users.query.filter_by(login=session['login']).first()
        if not check_password_hash(user.password, oldpassword):
            return render_template('changepassword.html', error="Старый пароль не верный")
        else:
            user.password = generate_password_hash(newpassword)
            db.session.commit()
            return redirect('/main')
    else:  
        return render_template('changepassword.html')
    
@app.route('/account', methods=['POST', 'GET'])
def account():
    roleList = Role.query.all()
    if 'login' not in session:
        return redirect('/login')
    
    if request.method == "POST":
        name = request.form['name']
        surname = request.form['surname']
        email = request.form['email']
        role = request.form['role']
        try:
            dateBirth = datetime.strptime(request.form['datebirth'], '%Y-%m-%d')
        except:
            return render_template('account.html', login=session['login'], roleList=roleList, error='Неверный формат даты')
        try:
            info = UserInfo.query.filter_by(login=session['login']).first()

            info.name = name
            info.surname = surname
            info.email = email
            info.role = role
            info.datebirth = dateBirth
 
            db.session.commit()

            return redirect('/account')
        except:
            return render_template('account.html', login=session['login'], roleList=roleList, error='Ошибка при отправке данных')
    else:
        return render_template('account.html', login=session['login'], roleList=roleList)


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
    db.create_all()