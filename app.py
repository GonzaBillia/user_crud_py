import mysql.connector
import bcrypt
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bcrypt import hashpw, gensalt
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

jwt = JWTManager(app)

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )

# Ruta de registro de usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing fields"}), 400

    hashed_password = hashpw(data['password'].encode('utf-8'), gensalt()).decode('utf-8')

    # Conexión a la base de datos
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO Users (name, email, password, createdAt, updatedAt) "
            "VALUES (%s, %s, %s, NOW(), NOW())",
            (data['name'], data['email'], hashed_password)
        )
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except mysql.connector.Error as e:
        conn.rollback()
        return jsonify({"message": "Error creating user", "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Ruta de login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing email or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM Users WHERE email = %s", (data['email'],))
    user = cursor.fetchone()

    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user['id']))
    cursor.close()
    conn.close()

    return jsonify({"message": "Login successful", "access_token": access_token})

# Ruta protegida por JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM Users WHERE id = %s", (current_user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    return jsonify({"message": f"Hello {user['name']}, you are logged in!"})


@app.route('/', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Users")
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify({"users": users})

if __name__ == '__main__':
    app.run(debug=True)

