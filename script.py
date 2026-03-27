from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///first.db'
db = SQLAlchemy(app)

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
        password = request.form['password']

        user = Users(login=login, password=password)

        try:
            db.session.add(user)
            db.session.commit()
            
            return redirect('/login')
        except:
            return "Ошибка"
    else:
        return render_template('reg.html')
    
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']

        user = Users.query.filter_by(login=login).first()
        
        if not user:
            return "Пользователя не существует"

        if user.password != password:
            return "Ошибка"
        else:
            return redirect('/main')
    else:
        return render_template('login.html')
    
@app.route('/main')
def main(login):
    return render_template('main.html', login=login)
    
if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()