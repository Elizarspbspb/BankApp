import sqlite3
import re
import os
import unicodedata                  # нормализует Unicode 
from urllib.parse import unquote    # декодирует URL
import bleach                       # Санитизация

DB_FILE = 'data/database.db'

def init_db():
    # Создание подключения к базе данных
    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    # Создаем таблицу users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(30) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL CHECK(length(password_hash) <= 255),
    role VARCHAR(20) DEFAULT 'user'  -- 'user' или 'admin'
    )
    ''')
    
    # Создаем таблицу dialogs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dialogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,                       -- ID пользователя
        admin_id INTEGER NOT NULL,                      -- ID администратора
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,                 -- активен ли диалог
        last_message_at TIMESTAMP,                      -- время последнего сообщения
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    # Создаем таблицу messages
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dialog_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL CHECK(length(content) > 0),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (dialog_id) REFERENCES dialogs(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')

    # Сохраняем изменения
    connection.commit()

    # Закрываем соединение
    connection.close()

def get_user_by_username(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_password_by_password_hash(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    pass_hash = cursor.fetchone()
    conn.close()
    if pass_hash is None:
        return None  # Пользователь не найден

    return pass_hash[0]  # Возвращаем первый элемент кортежа (строку хеша)
    
def create_user(username, email, password_hash):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',(username, email, password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Пользователь с таким именем уже существует

# Поиск/создание диалога
def get_or_create_dialog(user_id, admin_id=None):
    """
    Получает активный диалог пользователя с администратором.
    Если нет активного — создаёт новый.
    Если admin_id не указан, назначает первого доступного администратора.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Если администратор не указан, берём первого из списка администраторов
    if admin_id is None:
        cursor.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_result = cursor.fetchone()
        if not admin_result:
            raise Exception("Нет доступных администраторов")
        admin_id = admin_result[0]

    # Ищем активный диалог
    cursor.execute(
        'SELECT id FROM dialogs WHERE user_id = ? AND admin_id = ? AND is_active = TRUE', (user_id, admin_id)
    )
    result = cursor.fetchone()
    if result:
        dialog_id = result[0]
    else:
        # Создаём новый диалог... правда нет остальных параметров таблицы
        cursor.execute(
            'INSERT INTO dialogs (user_id, admin_id) VALUES (?, ?)',
            (user_id, admin_id)
        )
        dialog_id = cursor.lastrowid
        # полезная нагрузка для выполнения уязвимости
        #content = "<script>alert(1)</script>"
        content = "Welcome to the chat-online !!!"
        decoded = unquote(content)                                  # AppSec - декодирует URL
        normalized = unicodedata.normalize('NFC', decoded)          # AppSec - нормализует Unicode
        clean_content = bleach.clean(normalized)                    # AppSec - Санитизация
        cursor.execute("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")
        admin_start = cursor.fetchone()
        cursor.execute('INSERT INTO messages (dialog_id, user_id, content) VALUES (?, ?, ?)', (dialog_id, admin_start[0], clean_content))

    conn.commit()
    conn.close()
    return dialog_id

# Добавление сообщения в диалог    
def add_message_to_dialog(dialog_id, user_id, content):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO messages (dialog_id, user_id, content) VALUES (?, ?, ?)',
        (dialog_id, user_id, content)
    )

    # Обновляем время последнего сообщения в диалоге
    cursor.execute(
        'UPDATE dialogs SET last_message_at = CURRENT_TIMESTAMP WHERE id = ?',
        (dialog_id,)
    )
    conn.commit()
    conn.close()

# Получение сообщений диалога  
def get_dialog_messages(dialog_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT m.id, m.content, m.created_at,
               u.username, u.role
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.dialog_id = ?
        ORDER BY m.created_at
    ''', (dialog_id,))
    rows = cursor.fetchall()
    conn.close()

    # Преобразуем в список словарей
    messages = []
    for msg_id, content, created_at, username, role in rows:
        messages.append({
            'text': f'<strong>{username}:</strong> {content}',
            'type': role,  # 'user' или 'admin'
            'timestamp': created_at
        })
    return messages  

# Получение активных диалогов администратора
"""
def get_admin_dialogs(admin_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.id, u.username, d.last_message_at
        FROM dialogs d
        JOIN users u ON d.user_id = u.id
        WHERE d.admin_id = ? AND d.is_active = TRUE
        ORDER BY d.last_message_at DESC
    ''', (admin_id,))
    dialogs = cursor.fetchall()
    conn.close()
    return dialogs
"""
    
# Закрытие диалога
"""
def close_dialog(dialog_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE dialogs SET is_active = FALSE WHERE id = ?',
        (dialog_id,)
    )
    conn.commit()
    conn.close()
"""
# Получение информации о диалоге
"""def get_dialog_info(dialog_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.id, d.created_at, d.is_active,
               u.username as user_username,
               a.username as admin_username
        FROM dialogs d
        JOIN users u ON d.user_id = u.id
        JOIN users a ON d.admin_id = a.id
        WHERE d.id = ?
    ''', (dialog_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return {
            'id': result[0],
            'created_at': result[1],
            'is_active': result[2],
            'user_username': result[3],
            'admin_username': result[4]
        }
    return None"""
    
init_db()