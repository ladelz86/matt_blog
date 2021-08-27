import os
from flask import Flask, render_template, redirect, url_for, flash, abort, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, EmailForm
from flask_gravatar import Gravatar
from functools import wraps
from flask_mail import Mail, Message
from dotenv import load_dotenv
from datetime import datetime as dt

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Mail Settings
app.config["MAIL_SERVER"] = "smtp.mail.yahoo.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("GMAIL_ADDR")
app.config["MAIL_PASSWORD"] = os.environ.get("PASS_GMAIL")
mail = Mail(app)

# CONNECT TO DB
db_url = os.environ.get("DATABASE_URL")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    # Blog posts one to many
    blog_posts = relationship("BlogPost", back_populates="author", cascade="all, delete", passive_deletes=True)
    # Comments one to many
    comments = relationship("Comment", back_populates="author", cascade="all, delete", passive_deletes=True)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Many blog posts to one user
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    author = relationship("User", back_populates="blog_posts")
    # One Blog post many comments
    comments = relationship("Comment", back_populates="parent_post", cascade="all, delete", passive_deletes=True)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Many comments one author
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    author = relationship("User", back_populates="comments")
    # Many comments one post
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id", ondelete="CASCADE"), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            # return redirect(url_for('login', next=request.url))
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    session["year"] = dt.utcnow().year
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    session["year"] = dt.utcnow().year
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        if not User.query.filter_by(email=email).first():
            new_user = User(email=email,
                            password=generate_password_hash(register_form.password.data,
                                                            method='pbkdf2:sha256',
                                                            salt_length=8),
                            name=register_form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    session["year"] = dt.utcnow().year
    login_form = LoginForm()
    email = login_form.email.data
    password = login_form.password.data
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("That email does not exist, please try again.")
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    session["year"] = dt.utcnow().year
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to loin or register to comment.")
            return redirect(url_for('login'))
        text = comment_form.comment.data
        comment = Comment(text=text, author_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        comment_form.comment.data = ""

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    session["year"] = dt.utcnow().year
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    session["year"] = dt.utcnow().year
    flash_color = None
    email_form = EmailForm()
    if email_form.validate_on_submit():
        name = email_form.name.data
        email = email_form.email.data
        phone = email_form.phone.data
        message = email_form.message.data
        msg = Message("BLOG MESSAGE", sender=app.config["MAIL_USERNAME"], recipients=[app.config["MAIL_USERNAME"]])
        msg.body = f"Name: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        try:
            mail.send(msg)
        except Exception:
            flash("Error: Sorry, but there was an error and your email did not send. Please try again!")
            flash_color = "flashes-error"
        else:
            flash("Success: Your message has been sent successfully!")
            flash_color = "flashes-success"
            email_form.name.data = ""
            email_form.email.data = ""
            email_form.phone.data = ""
            email_form.message.data = ""
    return render_template("contact.html", form=email_form, flash_color=flash_color)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run()
