from flask import Flask, request, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Genera una chiave segreta casuale

login_manager = LoginManager(app)
fake_db = {"username": "root", 'password': generate_password_hash('admin')}

class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(username):
    return User(username)

class InvalidCredentialsException(Exception):
    pass

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    name = data.get('username')
    password = data.get('password')
    user = load_user(name)

    if not user:
        raise InvalidCredentialsException

    if name != fake_db["username"]:
        raise InvalidCredentialsException

    if not check_password_hash(fake_db['password'], password):
        raise InvalidCredentialsException

    user = User(name)
    login_user(user)

    response = make_response("Accesso eseguito. Ora cerca nell'endpoint dati, ma attento. Devi rimanere loggato!")
    return response

@app.route('/dati')
@login_required
def dati():
    html_content = """
    <html>
        <head>
            <title>Titolo</title>
        </head>
        <body>
            <h1>Codice tra poco!</h1>
            <p>
            Paragrafo inutile
            </p>
            <p>1234683435098403532850938423982938</p>
        </body>
    </html>    """
    return html_content, 200

@app.route('/info', methods=['OPTIONS'])
def info():
    res = {
        "endpoint": "/login",
        "username": "root",
        "password": "admin",
        "hint": "chiama l'endpoint e passa nel parametro json un dizionario con le chiavi e i valori per fare l'accesso."
    }
    return jsonify(res)

@app.route('/parametri', methods=['GET'])
@login_required
def endpoint_con_parametri():
    param1 = request.args.get('param1')
    param2 = request.args.get('param2')

    result = {"param1": param1, "param2": param2, "username": current_user.id}
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
