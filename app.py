from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('name', '')
    # УЯЗВИМОСТЬ: прямой рендеринг пользовательского ввода (XSS)
    # http://127.0.0.1:5000/?name=<script>alert(1)%</script>
    template = f"<h1>Добро пожаловать {user_input}!</h1>"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)