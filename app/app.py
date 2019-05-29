from builder import build_stub
from flask import Flask, flash, redirect, render_template, request, send_file, Session
from flask_bootstrap import Bootstrap
from form import StubbornForm

import secrets

app = Flask(__name__)
Bootstrap(app)
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
sess = Session()


@app.route('/', methods=['GET', 'POST'])
def handle_form():
    form = StubbornForm()
    if form.validate_on_submit():
        file = form.file.data
        if file.filename == '':
            flash('No selected file', 'file')
            return redirect(request.url)
        try:
            path = build_stub(file.read(), target_exe=form.targetExe.data, build_type=form.buildType.data,
                              key_type=form.keyType.data, key_length=form.keyLength.data, custom_key=form.customKey.data)
        except:
            path = None
        if not path:
            flash('Something failed', 'global')
            return redirect(request.url)
        return send_file(path, as_attachment=True, attachment_filename="packed-{}".format(file.filename))
    return render_template("home.html", form=form)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
