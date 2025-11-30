from flask import Flask
app = Flask(__name__)

@app.route('/<path:path>', methods=['GET','POST'])
def dummy(path):
    return f"Received request at /{path}", 200

app.run(port=5001)
    # Inspects the request for attacks and forwards it if safe and blocks it otherwise.