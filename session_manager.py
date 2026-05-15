import sqlite3
import os
import json
import secrets

from datetime import datetime, timedelta
from flask import session as flask_session

DB_FILE = 'data/database.db'
SESSION_LIFETIME_HOURS = 24

def init_session_db():
    # Создание подключения к базе данных
    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    # Создаем таблицу users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    data TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    # Сохраняем изменения
    connection.commit()

    # Закрываем соединение
    connection.close()

def create_session(user_id, username):
    """Создаёт новую сессию в БД и устанавливает куки"""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=SESSION_LIFETIME_HOURS)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO sessions (session_id, user_id, expires_at, data) VALUES (?, ?, ?, ?)',
        (session_id, user_id, expires_at, json.dumps({'username': username}))
    )
    conn.commit()
    conn.close()

    # Устанавливаем куки с ID сессии (не с логином!)
    flask_session['session_id'] = session_id
    return session_id

def get_session_data(session_id):
    """Получает данные сессии из БД по ID"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT user_id, data FROM sessions WHERE session_id = ? AND expires_at > ?',
        (session_id, datetime.now())
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        user_id, data_json = result
        data = json.loads(data_json)
        return {'user_id': user_id, 'data': data}
    return None

def delete_session(session_id):
    """Удаляет сессию из БД"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    """Очищает просроченные сессии"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM sessions WHERE expires_at <= ?', (datetime.now(),))
    conn.commit()
    conn.close()
    
init_session_db()