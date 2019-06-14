from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2 import Error



try:
    cursor = connection.cursor()
    # Print PostgreSQL Connection properties
    print(connection.get_dsn_parameters(), "\n")
    # Print PostgreSQL version
    cursor.execute("SELECT * FROM pg_catalog.pg_tables;")
    record = cursor.fetchone()
    print(record, "\n")
except (Exception, psycopg2.Error) as error :
    print("Error while connecting to PostgreSQL", error)

finally:
    # closing database connection.
    if connection:
        cursor.close()
        connection.close()
        print("PostgreSQL connection is closed")

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'miroir-producer'
jwt = JWTManager(app)


@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    return jsonify(username=username, hashedpw=pw_hash), 200


@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != 'test' or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200


@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access identity of current user
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route("/")
def hello():
    return "Hello World"


if __name__ == '__main__':
    app.run()
