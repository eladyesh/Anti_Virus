from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
db = SQLAlchemy(app)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)


@app.route('/')
def index():
    passwords = Password.query.all()
    return render_template('index.html', passwords=passwords)


@app.route('/add', methods=['POST'])
def add_password():
    website = request.form['website']
    username = request.form['username']
    password = request.form['password']
    new_password = Password(website=website, username=username, password=password)
    db.session.add(new_password)
    db.session.commit()
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
