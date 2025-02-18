from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
import bcrypt
import jwt
import datetime
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)

# Configuración de CORS
CORS(app)  # Esto habilita CORS para todas las rutas

SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yaml'  # Ruta al archivo swagger.yaml
swaggerui_blueprint = get_swaggerui_blueprint(SWAGGER_URL, API_URL, config={'app_name': "Gestión de Usuarios"})
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Configuración de la base de datos
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'api_rest1'
app.config['SECRET_KEY'] = 'your_secret_key'  # Clave secreta para JWT

mysql = MySQL(app)

# Decorador para verificar el token en las rutas protegidas
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None

        # Verificar si el token está en el encabezado de autorización
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # "Bearer <token>"

        if not token:
            return jsonify({'message': 'Token de acceso es requerido'}), 403

        try:
            # Decodificar el token usando la clave secreta
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token ha expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401

        return f(current_user, *args, **kwargs)

    return decorated_function

# 1. Registro de usuario
@app.route('/usuarios/', methods=['POST'])
def register_user():
    data = request.get_json()
    usuario = data.get('usuario')
    email = data.get('email')
    clave = data.get('clave')

    if not usuario or not email or not clave:
        return jsonify({'message': 'Datos incompletos'}), 400

    # Encriptar la clave
    hashed_clave = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cur = mysql.connection.cursor()
    # Verificar si el email ya está registrado
    cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    existing_user = cur.fetchone()

    if existing_user:
        return jsonify({'message': 'Email ya registrado'}), 409

    cur.execute("INSERT INTO usuarios (usuario, email, clave) VALUES (%s, %s, %s)",
                (usuario, email, hashed_clave))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

# 2. Obtener lista de usuarios
@app.route('/usuarios', methods=['GET'])
@token_required
def get_users(current_user):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, usuario, email FROM usuarios")
    users = cur.fetchall()
    cur.close()

    if not users:
        return jsonify({'message': 'No hay usuarios registrados'}), 404

    return jsonify(users), 200

# 3. Obtener un usuario por ID
@app.route('/usuarios/<int:id>', methods=['GET'])
@token_required
def get_user_by_id(current_user, id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, usuario, email FROM usuarios WHERE id = %s", (id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    return jsonify(user), 200

# 4. Actualizar usuario
@app.route('/usuarios/<int:id>', methods=['PUT'])
@token_required
def update_user(current_user, id):
    data = request.get_json()
    usuario = data.get('usuario')
    email = data.get('email')
    clave = data.get('clave')

    cur = mysql.connection.cursor()

    # Verificar si el usuario existe
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    user = cur.fetchone()

    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    if email:
        cur.execute("SELECT * FROM usuarios WHERE email = %s AND id != %s", (email, id))
        existing_user = cur.fetchone()
        if existing_user:
            return jsonify({'message': 'Email ya registrado'}), 409

    update_data = {
        'usuario': usuario or user[1],
        'email': email or user[2],
        'clave': bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt()) if clave else user[3]
    }

    cur.execute(""" 
        UPDATE usuarios
        SET usuario = %s, email = %s, clave = %s
        WHERE id = %s
    """, (update_data['usuario'], update_data['email'], update_data['clave'], id))

    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Usuario actualizado exitosamente'}), 200

# 5. actualizar usuario parcial
@app.route('/usuarios/<int:id>', methods=['PATCH'])
@token_required
def partial_update_user(current_user, id):
    data = request.get_json()

    cur = mysql.connection.cursor()
    # Verificar si el usuario existe
    cur.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    user = cur.fetchone()

    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    # Verificar si el usuario tiene permisos para modificar (puedes validar por 'current_user' si es necesario)
    if user[0] != current_user:
        return jsonify({'message': 'No tienes permiso para modificar este usuario'}), 403

    # Actualizar parcialmente los datos
    update_data = {
        'usuario': data.get('usuario', user[1]),  # Si no se pasa el dato, mantener el actual
        'email': data.get('email', user[2]),
        'clave': bcrypt.hashpw(data.get('clave', user[3]).encode('utf-8'), bcrypt.gensalt()) if data.get('clave') else user[3]
    }

    # Solo actualizar los campos que han cambiado
    cur.execute(""" 
        UPDATE usuarios
        SET usuario = %s, email = %s, clave = %s
        WHERE id = %s
    """, (update_data['usuario'], update_data['email'], update_data['clave'], id))

    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Usuario actualizado parcialmente exitosamente'}), 200


# 6. Eliminar usuario
@app.route('/usuarios/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    user = cur.fetchone()

    if not user:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    if user[0] != current_user:
        return jsonify({'message': 'No tienes permiso para eliminar este usuario'}), 403

    cur.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Usuario eliminado exitosamente'}), 204

# 7. Login de usuario
@app.route('/usuarios/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    clave = data.get('clave')

    if not email or not clave:
        return jsonify({'message': 'Datos incompletos'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user or not bcrypt.checkpw(clave.encode('utf-8'), user[3].encode('utf-8')):
        return jsonify({'message': 'Credenciales incorrectas'}), 401

    token = jwt.encode({
        'id': user[0],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token}), 200

# 8. Recuperación de clave
@app.route('/usuarios/recover-password', methods=['POST'])
def recover_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email es obligatorio'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'Email no registrado'}), 404

    # Aquí enviarías un correo al usuario con instrucciones para recuperar la clave
    # Este es un ejemplo simple, en la realidad usarías un servicio de correo electrónico
    return jsonify({'message': f'Instrucciones para recuperar la clave enviadas a {email}'}), 200

if __name__ == '__main__':
    app.run(debug=True)
