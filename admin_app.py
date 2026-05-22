from flask import Flask, request, jsonify
from pymongo import MongoClient
import re

admin_app = Flask(__name__)

# Подключение к MongoDB (предполагается, что MongoDB запущена локально)
client = MongoClient('localhost', 27017)
db = client.vulnerable_db
users_collection = db.users

# Создаём тестовых пользователей
users_collection.delete_many({})
users_collection.insert_many([
    {"username": "admin", "password": "secret123", "role": "admin"},
    {"username": "user1", "password": "mypass", "role": "user"},
    {"username": "test", "password": "qwerty", "role": "user"}
])

@admin_app.route('/login', methods=['POST'])
def login():
    # УЯЗВИМЫЙ КОД: прямая подстановка пользовательского ввода в запрос
    username = request.json.get('username', '')
    password = request.json.get('password', '')

    query = {
        "username": username,
        "password": password
    }

    user = users_collection.find_one(query)

    if user:
        return jsonify({"success": True, "message": "Login successful", "user": user}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

if __name__ == '__main__':
    admin_app.run(debug=True)
