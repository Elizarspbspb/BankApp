from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
#from database import get_user_by_username, create_user, get_password_by_password_hash, get_or_create_dialog, add_message_to_dialog, get_dialog_messages, get_admin_dialogs, close_dialog, get_dialog_info
from database import get_user_by_username, create_user, get_password_by_password_hash, get_or_create_dialog, add_message_to_dialog, get_dialog_messages
#from session_manager import create_session, get_session_data

#import secrets      # CSRF-token
#import time         # CSRF-token + time

import unicodedata                  # нормализует Unicode 
from urllib.parse import unquote    # декодирует URL
import bleach                       # Санитизация
#import re                           # Валидация
from markupsafe import escape, Markup   # Энкодинг - новая версия

app = Flask(__name__)
app.secret_key = '6G6A906SBHP7@J0KX0'  #  — заменить 
    
# python sqlmap.py -u http://127.0.0.1:5000/login --batch --banner --data="username=123&password=12345678" --cookie="session=eyJ1c2VybmFtZSI6IjEyMyJ9.agrbmQ.Kb_CWePMO6r7YolX80hr_mZPGIc" --tables

@app.route('/')
def index():
    #if 'username' in session: !!! Риск подмены сессии, зная имя пользователя
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

# Не протестировано
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not username or not password or not email:
            flash('Заполните все поля', 'error')
            return render_template('register.html')
        exist_user = get_user_by_username(username)
        if exist_user:
            flash('Пользователь уже существует', 'error')
            return render_template('register.html')
        # Хешируем пароль
        pw_hash = generate_password_hash(password)
        
        # Регистрируем пользователя        
        if create_user(username, email, pw_hash):
            flash('Регистрация прошла успешно. Войдите.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Ошибка при регистрации', 'error')
            return render_template('register.html')
        
    return render_template('register.html')

# Не протестировано
@app.route('/login', methods=['GET', 'POST'])
#@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Заполните все поля', 'error')
            return render_template('login.html')
        exist_user = get_user_by_username(username)
        if exist_user and check_password_hash(get_password_by_password_hash(username), password):
            # session['username'] = username          # Риск подмены сессии, зная имя пользователя
            session['username'] = username          
            flash('Вы успешно вошли', 'success')
            return redirect(url_for('chat'))
        flash('Неверный логин или пароль', 'error')
        return render_template('login.html')
    return render_template('login.html')

# sqlmap.py -u http://127.0.0.1:5000/chat --batch --banner --data="username=123" --cookie="session=eyJ1c2VybmFtZSI6IjEyMyJ9.agrbmQ.Kb_CWePMO6r7YolX80hr_mZPGIc" --level=3 --method=GET --tables
@app.route('/chat', methods=['GET'])
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']      # ???
    user = get_user_by_username(username)
    user_id = user[0]

    # CSRF-token на сессию
    '''
    if "csrf" not in session:
        session["csrf"] = {
            #"token": generate_random(), 
            "token": secrets.randbelow(100),
            "ts": time.time()s
        }
    #csrf = session["csrf"]
    csrf = session.get("csrf", {})
    '''
    
    # Получаем диалог пользователя (создаётся, если нет)
    dialog_id = get_or_create_dialog(user_id)
    
    messages = get_dialog_messages(dialog_id)
    #return render_template('chat.html', username=username, messages=messages, dialog_id=dialog_id, csrf=csrf)
    return render_template('chat.html', username=username, messages=messages, dialog_id=dialog_id)

#python sqlmap.py -u http://127.0.0.1:5000/send --batch --banner --data="username=123&password=12345678" --level=3 --method=POST --tables              
# python sqlmap.py -u http://127.0.0.1:5000/send --batch --banner --data="username=123&password=12345678" --level=3 --method=POST --tables --data="message=sqlmap"
# рабочая нагрузка, но защита работает - python sqlmap.py -u http://127.0.0.1:5000/send --batch --banner --data="username=123&password=12345678&message=sqlmap2" --level=1 --method=POST --tables
@app.route('/send', methods=['POST'])
def send():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    # Проверка CSRF-token
    '''
    #if session.get("csrf") != request.form.get("csrf_token"):
    #    return "CSRF blocked", 403
    # Проверка CSRF-token + time
    csrf = session.get("csrf", {})
    if csrf.get("token") != request.form.get("csrf_token"):
        return "CSRF blocked", 403
    if time.time() - csrf.get("ts", 0) > 3600:
        return "CSRF expired", 403
    '''
    
    #message = request.form.get('message', '').strip()
    message = request.form.get('message', '')
    print("Message 1 :", message)
    clean_message = message

    # Декодирование, нормализация, санитизация от атак XSS <script>alert(1)</script>
    decoded = unquote(message)      # декодирует URL
    normalized = unicodedata.normalize('NFC', decoded)  # нормализует unicode
    clean_message = bleach.clean(normalized)  # санитизация
    print("Message 3 :", clean_message)

    username = session['username']
    user = get_user_by_username(username)
    user_id = user[0]
    dialog_id = get_or_create_dialog(user_id)
    
    add_message_to_dialog(dialog_id, user_id, clean_message)
    return redirect(url_for('chat'))
    
# Для демонстрации сохраненной XSS - <script>alert(1)</script>
'''@app.route('/send', methods=['POST'])
def send():
    if 'username' not in session:
        return redirect(url_for('login'))
    message = request.form.get('message', '')
    print("Message:", message)
    # сохранить сообщение в сессии (не для продакшна). В учебном стенде можно хранить сообщения в памяти или в файле
    msgs = session.get('messages', [])
    username = session['username']
    #msgs.append({"user": session['username'], "text": message})
    msgs.append({'text': f'<strong>{username}:</strong> {message}', 'type': 'user'})
    session['messages'] = msgs
    return redirect(url_for('chat'))
'''
# Для демонстрации отраженной XSS - <script>alert(1)</script>
'''@app.route('/send', methods=['GET'])
def send():
    if 'username' not in session:
        return redirect(url_for('login'))
    message = request.args.get('message', '')
    print("Message:", message)
    msgs = session.get('messages', [])
    username = session['username']
    #msgs.append({"user": session['username'], "text": message})
    msgs.append({'text': f'<strong>{username}:</strong> {message}', 'type': 'user'})
    session['messages'] = msgs
    return redirect(url_for('chat'))
'''

# Панель администратора
'''
@app.route('/admin/dialogs')
#@login_required
def admin_dialogs():
    # Проверяем, что пользователь — администратор
    if g.current_user.role != 'admin':
        abort(403)

    admin_id = g.current_user.id
    dialogs = get_admin_dialogs(admin_id)
    return render_template('admin_dialogs.html', dialogs=dialogs)

# Просмотр диалога администратором
@app.route('/admin/dialog/<int:dialog_id>')
#@login_required
def admin_view_dialog(dialog_id):
    # Проверяем, что текущий пользователь — администратор
    if g.current_user_role != 'admin':
        abort(403)  # Запрет доступа

    # Получаем информацию о диалоге
    dialog = get_dialog_info(dialog_id)
    if not dialog:
        abort(404)  # Диалог не найден

    # Получаем все сообщения диалога
    messages = get_dialog_messages(dialog_id)

    return render_template('admin_dialog.html', dialog=dialog, messages=messages)
'''
'''
@app.route('/logout', methods=['POST'])
def logout():
    #if request.form.get('csrf_token') != session.get('csrf_token'):
    #    abort(403)  # Запретить доступ при неверном токене
    #session.pop('username', None)
    session.clear()
    flash('Вы вышли', 'info')
    return redirect(url_for('login'))
'''
if __name__ == '__main__':
    app.run(debug=True)