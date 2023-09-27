from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SECRET_KEY'] = 'd989deb1b8668615fecfe6d748f7fa757fd2350a784d818cf75ffa947ce992d7'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(60), nullable=False)

@app.route('/', methods=['GET', 'POST'])
def login_or_register():
    error_message = None

    if request.method == 'POST':
        if 'login' in request.form:
            email = request.form['email']
            password = request.form['password']

            user = User.query.filter_by(email=email).first()

            if user and bcrypt.check_password_hash(user.password, password):
                session['username'] = user.username  # Set the username in the session
                return redirect(url_for('welcome'))
            else:
                flash('Invalid login credentials', 'error')
                return redirect(url_for('login_or_register'))
        elif 'register' in request.form:
            email = request.form['email']
            username = request.form['username']
            password = request.form['password']

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                error_message = 'Email address is already in use. Please choose another one.'
                session['error_message'] = error_message
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(email=email, username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                session.pop('error_message', None)
                return render_template('registration_success.html')

    return render_template('login.html', error_message=error_message)

@app.route('/welcome')
def welcome():
    if 'username' in session:
        username = session['username']
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('login_or_register'))

@app.route('/download_disclaimer_pdf', methods=['GET'])
def download_disclaimer_pdf():
    # Provide the path to the existing PDF file
    pdf_path = 'files/disclaimer.pdf'

    # Serve the existing PDF file as a response
    return send_file(pdf_path, as_attachment=True, download_name='disclaimer.pdf')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
