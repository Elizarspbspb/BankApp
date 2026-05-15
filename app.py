from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    user_input = request.args.get('name', '')
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)