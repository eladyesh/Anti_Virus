from flask import Flask, render_template_string

app = Flask(__name__)


@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
        </head>
        <body>
            <h1>Welcome to my Flask app!</h1>
            <p>This is the home page.</p>
        </body>
        </html>
    ''', title='Home')


@app.route('/about')
def about():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
        </head>
        <body>
            <h1>About Us</h1>
            <p>We are a small company based in Flaskville.</p>
        </body>
        </html>
    ''', title='About')


if __name__ == '__main__':
    app.run(debug=True)
