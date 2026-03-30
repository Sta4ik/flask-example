from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///first.db'
db = SQLAlchemy(app)
app.secret_key = 'sqfdfsdg'
app.permanent_session_lifetime = timedelta(minutes=3)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/', methods=['POST', 'GET'])
@app.route('/reg', methods=['POST', 'GET'])
def reg():
    if request.method == "POST":
        login = request.form['login']
        password = generate_password_hash(request.form['password'])

        user = Users(login=login, password=password)

        try:
            db.session.add(user)
            db.session.commit()
            
            return redirect('/login')
        except:
            return render_template('reg.html', error="Данный пользователь уже существует")
    else:
        return render_template('reg.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']

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
        if 'login' in session:
            return redirect('/main')
        
        return render_template('login.html')

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

if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()