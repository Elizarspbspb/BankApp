from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
#from database import get_user_by_username, create_user, get_password_by_password_hash, get_or_create_dialog, add_message_to_dialog, get_dialog_messages, get_admin_dialogs, close_dialog, get_dialog_info
from database import get_user_by_username, create_user, get_password_by_password_hash, get_or_create_dialog, add_message_to_dialog, get_dialog_messages
#from session_manager import create_session, get_session_data
import os
import subprocess   # OS-command injection
from werkzeug.utils import secure_filename      # XXE
import xml.etree.ElementTree as ET              # XML
from defusedxml.ElementTree import parse as safe_parse  # XXE
from io import BytesIO

#import secrets      # CSRF-token
#import time         # CSRF-token + time

import unicodedata                  # нормализует Unicode 
from urllib.parse import unquote    # декодирует URL
import bleach                       # Санитизация XSS
#import re                           # Валидация
from markupsafe import escape, Markup   # Энкодинг - новая версия

app = Flask(__name__)
app.secret_key = '6G6A906SBHP7@J0KX0'  #  — заменить 
    
# Полезные нагрузки тестирования безопасности
# 1. SQL: python sqlmap.py -u http://127.0.0.1:5000/login --batch --banner --data="username=123&password=12345678" --cookie="session=eyJ1c2VybmFtZSI6IjEyMyJ9.agrbmQ.Kb_CWePMO6r7YolX80hr_mZPGIc" --tables

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

    # УЯЗВИМЫЙ УЧАСТОК OS-Command injection
    # Злоумышленник может внедрить системную команду через message
    # Тест сообщения - '; rm -rf /important_data; #
    # Тест сообщения - echo Test & del E:\workspace\BankApp\logs\1.txt /s /q &
    # Тест сообщения - echo Test & del E:\workspace\BankApp\logs\1.txt /s /q & echo Done >> E:\workspace\BankApp\logs\messages_123.log
    '''
    # Linux
    # command = f"echo '{clean_message}' >> /var/logs/messages_{username}.log"
    # Windows
    command = f"echo '{clean_message}' >> E:\workspace\BankApp\logs\messages_{username}.log"
    print("command :", command)
    os.system(command)  # ПРЯМАЯ УЯЗВИМОСТЬ К OS-ИНЪЕКЦИИ
    '''
    # 1. Безопасный файловый ввод‑вывод
    with open(f"E:\workspace\BankApp\logs\messages_{username}.log", "a") as f:
        f.write(clean_message + "\n")
    '''
    # 2. Безопасный вызов: аргументы передаются списком, shell=False. pip install subprocess.run
    subprocess.run(["echo", clean_message],
        stdout=open(f"E:\workspace\BankApp\logs\messages_{username}.log", "a"),
        shell=False)
    # 3. Валидация по белому списку
    allowed_messages = ['start', 'stop', 'status']
    #if clean_message not in allowed_messages:
    #    raise ValueError("Недопустимое сообщение")
    '''
    return redirect(url_for('chat'))

# http://127.0.0.1:5000/xml_upload
@app.route('/xml_upload', methods=['GET'])
def upload_xml_form():
    """Отображает форму для загрузки XML-файла"""
    return render_template('xml_upload.html')

# Уязвимая функция парсинга XML
def parse_xml_unsafe(xml_data):
    """Уязвимый парсер XML — разрешает внешние сущности"""
    try:
        # Отключаем защиту от XXE — это создаёт уязвимость
        parser = ET.XMLParser()
        #parser.parser.StartDocumentHandler = None
        tree = ET.fromstring(xml_data, parser=parser)
        return tree
    except Exception as e:
        return str(e)

# Защищённая функция парсинга XML
'''
def parse_xml_safe(xml_data):
    """ Безопасный парсер XML — блокирует внешние сущности и DTD. 
    Использует defusedxml для защиты от XXE и других атак. """
    try:
        # Используем defusedxml — безопасную замену стандартного ET
        tree = safe_parse(BytesIO(xml_data.encode('utf-8')))
        return tree
    except Exception as e:
        return f"Ошибка парсинга XML: {str(e)}"
'''
# Не защищённый endpoint для обработки XML
@app.route('/send_xml', methods=['POST'])
#@app.route('/send_xml', methods=['GET'])
def send_xml():
    if 'username' not in session:
        return redirect(url_for('login'))
    # УЯЗВИМОСТЬ: Нет проверки на наличие файла
    file = request.files['xmlFile']
    # УЯЗВИМОСТЬ: Небезопасное имя файла
    filename = file.filename
    target_directory = r'E:\workspace\BankApp\data'
    target_path = os.path.join(target_directory, filename)
    print("target_path = ", target_path)
    try:
        # Читаем содержимое файла как строку
        xml_content = file.read().decode('utf-8')
        # УЯЗВИМОСТЬ: Используем уязвимый парсер — это позволяет XXE‑атаки
        result = parse_xml_unsafe(xml_content)
        # Проверяем, что парсинг прошёл успешно
        if isinstance(result, str):  # Если вернулось сообщение об ошибке
            flash(f'Ошибка парсинга XML: {result}', 'error')
            print("error parsing !!! - ", result)
            return render_template('xml_upload.html')
        # Сохраняем файл только после парсинга
        file.stream.seek(0)  # Возвращаем указатель в начало
        file.save(target_path)
        flash('XML‑файл успешно загружен и проверен', 'success')
        return redirect(url_for('chat'))
    except Exception as e:
        flash(f'Ошибка: {str(e)}', 'error')
        return render_template('xml_upload.html')

# Защищённый endpoint для обработки XML
'''
@app.route('/process-xml', methods=['POST'])
def process_xml():
    """Безопасный endpoint для обработки XML с валидацией и ограничениями"""
    # 1. Проверяем, что файл загружен
    if 'xmlFile' not in request.files:
        return "Файл не предоставлен", 400
    file = request.files['xmlFile']
    # 2. Проверяем имя файла
    if file.filename == '':
        return "Имя файла отсутствует", 400
    # 3. Проверяем расширение файла
    if not file.filename.lower().endswith('.xml'):
        return "Недопустимый формат файла. Требуется .xml", 400
    # 4. Ограничиваем размер файла (1 MB)
    max_size = 1024 * 1024          # 1 MB
    file.stream.seek(0, 2)          # Перемещаем указатель в конец
    file_size = file.stream.tell()
    file.stream.seek(0)             # Возвращаем указатель в начало
    if file_size > max_size:
        return "Файл слишком большой. Максимальный размер — 1 MB", 413
    # 5. Читаем содержимое файла
    xml_content = file.read().decode('utf-8')
    # 6. Безопасный парсинг XML
    result = parse_xml_safe(xml_content)
    if isinstance(result, str) and "Ошибка" in result:
        return result, 400
    return "XML успешно обработан и проверен", 200
'''
'''
# Защищённый endpoint для обработки XML
@app.route('/process-xml', methods=['POST'])
def process_xml():
    """Безопасный endpoint для обработки XML с валидацией и ограничениями"""
    # 1. Проверяем Content-Type
    if request.content_type != 'text/xml':
        return "Неподдерживаемый тип контента", 400
    # 2. Ограничиваем размер XML (1 MB максимум)
    content_length = request.content_length
    if content_length and content_length > 1024 * 1024:  # 1 MB
        return "XML слишком большой", 413
    xml_data = request.data.decode('utf-8')
    # 3. Валидируем базовую структуру XML
    if not xml_data.strip().startswith('<?xml') and not xml_data.strip().startswith('<'):
        return "Недопустимый формат XML", 400
    # 4. Используем безопасный парсер
    result = parse_xml_safe(xml_data)
    if isinstance(result, str) and "Ошибка" in result:
        return result, 400
    return "XML успешно обработан", 200
'''
# Не защищённая загрузка файлов
@app.route('/upload-file', methods=['POST'])
def upload_file():
    """Уязвимая загрузка файлов — демонстрирует атаки через SVG и DOCX"""
    file = request.files.get('file')
    if file and file.filename.endswith('.svg'):
        # Уязвимо: парсим SVG как XML без защиты
        try:
            tree = ET.fromstring(file.read())
            return "Файл успешно обработан"
        except Exception as e:
            return f"Ошибка обработки: {str(e)}"
    return "Неверный формат файла"

'''
# Защищённая загрузка файлов
@app.route('/upload-file', methods=['POST'])
def upload_file():
    """Безопасная загрузка файлов с проверкой формата и содержимого"""
    file = request.files.get('file')
    if not file:
        return "Файл не предоставлен", 400
    filename = file.filename
    # 1. Проверяем расширение файла
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return "Недопустимый формат файла", 400
    # 2. Безопасное имя файла
    safe_filename = secure_filename(filename)
    # 3. Сохраняем файл без обработки как XML
    upload_path = os.path.join('uploads', safe_filename)
    file.save(upload_path)
    # 4. Если нужно проверить SVG — используем специализированные инструменты
    if filename.lower().endswith('.svg'):
        if not is_safe_svg(file.read()):
            os.remove(upload_path)  # Удаляем небезопасный файл
            return "SVG содержит потенциально опасный контент", 400
        file.seek(0)  # Возвращаем указатель файла в начало
    return "Файл успешно загружен", 200

def is_safe_svg(svg_content):
    """ Проверяет SVG на наличие потенциально опасных конструкций.
    В реальной реализации используйте специализированные библиотеки. """
    dangerous_patterns = [
        b'<!DOCTYPE',
        b'<!ENTITY',
        b'xlink:href',
        b'javascript:',
        b'data:'
    ]
    for pattern in dangerous_patterns:
        if pattern in svg_content:
            return False
    return True
'''

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