import os

class Config:
    SECRET_KEY = 'secret_key'  # Clave secreta para la sesión (JWT)
    
    # Configuración de MySQL con mysql.connector
    DB_HOST = 'localhost'
    DB_USER = 'root'
    DB_PASSWORD = '40772342'
    DB_NAME = 'user_crud'
