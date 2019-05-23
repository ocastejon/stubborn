from builder import build
from flask import Flask, flash, redirect, render_template, request, send_file, Session
from flask_bootstrap import Bootstrap

import secrets

app = Flask(__name__)
Bootstrap(app)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
sess = Session()


@app.route('/', methods=['GET', 'POST'])
def build_crypter():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        path = build(file.read())
        if not path:
            flash('Something failed')
            return redirect(request.url)
        return send_file(path, as_attachment=True, attachment_filename="packed-{}".format(file.filename))
    return render_template("base.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0')
