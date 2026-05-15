from flask import Flask, request, render_template_string
from html import escape

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('name', '')
    # ИСПРАВЛЕНО: экранирование пользовательского ввода
    # http://127.0.0.1:5000/?name=<script>alert(1)%</script>
    safe_input = escape(user_input)
    template = f"<h1>Добро пожаловать {safe_input}!</h1>"
    template = f"<h1>Добро пожаловать {user_input}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False)    # Отключаем debug в продакшене