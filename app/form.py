from flask_wtf import FlaskForm
from wtforms import RadioField, SelectField, StringField, SubmitField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import InputRequired, NumberRange
from wtforms_components import IntegerField


def validate_key_length(form, field):
    if form.keyType.data == 'randomKey':
        NumberRange(message="Minimum length of the key is 1", min=1).__call__(form, field)


def validate_custom_key(form, field):
    if form.keyType.data == 'userKey':
        InputRequired(message="A custom key is required").__call__(form, field)


class StubbornForm(FlaskForm):
    file = FileField("Choose a file...", validators=[FileRequired(message="A payload file is required")])
    targetExe = SelectField("Select the executable to inject your payload",
                            choices=[("same", "Same executable file"), ("calc", "calc.exe"), ("notepad", "notepad.exe"),
                                     ("svchost", "svchost.exe")], default="same",
                            validators=[InputRequired(message="A target executable is required")])
    buildType = RadioField("Select the desired build type", choices=[("release", "Release"), ("debug", "Debug")],
                           default="release", validators=[InputRequired(message="A build type is required")])
    keyType = RadioField("Select the encryption key you want to use",
                         choices=[("randomKey", "Randomly Generated Key"), ("userKey", "Custom Key")],
                         default="randomKey", validators=[InputRequired(message="A key type is required")])
    keyLength = IntegerField("Key Length", default=32,
                             validators=[validate_key_length])
    customKey = StringField("Enter the key you want to use", validators=[validate_custom_key])
    submit = SubmitField("Pack your file!")

    @staticmethod
    def get_target(value):
        return "#{}Options".format(value)
