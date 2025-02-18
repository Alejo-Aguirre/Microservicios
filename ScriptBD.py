from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Configuración de la aplicación Flask
app = Flask(__name__)

# Configuración de la base de datos (MySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/api_rest1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de SQLAlchemy
db = SQLAlchemy(app)

# Modelo de la tabla `usuarios`
class Usuarios(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    clave = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Usuario {self.usuario}>'

# Modelo de la tabla `tokens` (para JWT)
class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Token {self.token}>'

# Modelo de la tabla `password_reset_requests`
class PasswordResetRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<PasswordResetRequest {self.token}>'

# Crear la base de datos y las tablas
def crear_base_de_datos():
    with app.app_context():
        # Crear la base de datos (si no existe)
        db.create_all()
        print("Base de datos y tablas creadas exitosamente.")

# Ejecutar la función para crear la base de datos y las tablas
if __name__ == '__main__':
    crear_base_de_datos()
