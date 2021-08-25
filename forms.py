from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTF Post Form
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# WTF Register Form
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=150)])
    name = StringField("Name", validators=[DataRequired(), Length(min=1, max=250)])
    submit = SubmitField("Sign Me Up!")


# WTF Login Form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=150)])
    submit = SubmitField("Let Me In!")


# WTF Comment Form
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


# WTF Email Form
class EmailForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=1, max=250)])
    email = StringField("Email Address", validators=[DataRequired(), Email(), Length(max=150)])
    phone = StringField("Phone Number", validators=[DataRequired(), Length(min=6, max=150)])
    message = TextAreaField("Message", render_kw={"rows": 10},
                            validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField("Send")
