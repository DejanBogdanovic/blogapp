from flask import Flask, render_template, request, redirect, session, url_for, abort, flash, g
from peewee import *
from functools import wraps
from hashlib import md5
from flask_wtf import Form
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'asdwedfbgasdfasdfasdfasdfasdfasd'
database = SqliteDatabase('blog_database.db')
#logging.basicConfig(filename='blogapp.log',level=logging.INFO)

"""
    A few methods I copied from the Github repository of Flask. I will mark those methods with 2 stars(**)
"""


"""
    MODELS
"""
class BaseModel(Model):
    class Meta:
        database = database

class User(Model):
    first_name = CharField()
    last_name = CharField()
    password = CharField()
    email = CharField(unique=True)
    join_date = DateField()

    class Meta:
        database = database # This model uses the "blog.db" database.

class Blog(Model):
    title = CharField(max_length=50)
    creator = ForeignKeyField(User)
    text = TextField()
    creation_date = DateField()
    likes = IntegerField(default=0)

    class Meta:
        database = database # This model uses the "blog.db" database.
        order_by = ('-creation_date',)

"""
    FORMS
"""
class LoginForm(Form):
    email = StringField('E-Mail', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegistrationForm(Form):
    first_name = StringField('First name', [validators.Length(min=4, max=25)])
    last_name = StringField('Last name', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Email])
    password = PasswordField('New Password', [validators.DataRequired()])

"""
    APP
"""
# simple utility function to create tables **
def create_tables():
    database.connect()
    database.create_tables([Blog])

# simple utility function to drop tables **
def drop_tables():
    database.connect()
    database.drop_tables([Blog])

# Request handlers -- these two hooks are provided by flask and we will use them
# to create and tear down a database connection on each request. **
@app.before_request
def before_request():
    g.db = database
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

# view decorator which indicates that the requesting user must be authenticated
# before they can access the view.  it checks the session to see if they're
# logged in, and if not redirects them to the login view. **
def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

# retrieve a single object matching the specified query or 404 -- this uses the
# shortcut "get" method on model, which retrieves a single object or raises a
# DoesNotExist exception if no matching object exists
# http://charlesleifer.com/docs/peewee/peewee/models.html#Model.get) **
def get_object_or_404(model, *expressions):
    try:
        return model.get(*expressions)
    except model.DoesNotExist:
        logging.error('Could not get model because it does not exist: %s', model )
        abort(404)

# method for the start page. it returns all blog, that will be displayed on the start page.
@app.route('/')
@app.route('/index')
def index():
    blogs = Blog.select()
    return render_template('index.html', blog_list=blogs)

# return the page with the "Arbeitsjournal"
@app.route('/journal')
def journal():
    return render_template('journal.html')

# unsecure method for a login, for SQL-Injection demonstration purpose
@app.route('/unsafelogin', methods=['GET', 'POST'])
def unsafe_login():
    conn = sqlite3.connect('blog_database.db')
    c = conn.cursor()
    if request.method == 'POST' and request.form['email']:
        user = c.execute("SELECT * FROM User WHERE email = '{0}' AND password = '{1}'".format(request.form['email'], request.form['password'])).fetchone()
        if user:
            print 'User found'
            session['logged_in'] = True
            session['user_id'] = user[0]
            session['name'] = user[1] + ' ' + user[2]
            session['user_email'] = user[4]
            return redirect(url_for('index'))
        else:
            print 'Nothing found'

    return render_template('unsafelogin.html')

# login method for the user. gets a user with his provided email in the form.
# if a entry could be found in the database, his hashed password will be checked
# and if this is also correct he will be loged in and redirected to the start page.
# othwerise he will get a message, that his provided login data aren't correct.
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form['email']:
        try:
            user = User.get(
                email=request.form['email'])

            if check_password_hash(user.password, request.form['password']):
                auth_user(user)
                logging.info('User logged in with email: %s', request.form['email'] )
                return redirect(url_for('index'))
            else:
                flash('Login not correct')
                logging.info('Login not correct for email: %s', request.form['email'] )
        except User.DoesNotExist:
            logging.info('User does not exist with email: %s', request.form['email'] )
            flash('Login not correct')

    return render_template('login.html')

# method for the user registration. checks if email is already used, if that's the case
# the user will get a message, otherwise a new account will be created for him
# and he will automatically be logged in
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and request.form['email']:
        try:
            with database.transaction():
                # Attempt to create the user. If the username is taken, due to the
                # unique constraint, the database will raise an IntegrityError.
                user = User.create(
                    first_name=request.form['first_name'],
                    last_name=request.form['last_name'],
                    password=generate_password_hash(request.form['password']),
                    email=request.form['email'],
                    join_date=datetime.datetime.now())

            # mark the user as being 'authenticated' by setting the session vars
            auth_user(user)
            logging.info('New user registered with email: %s', request.form['email'] )
            return redirect(url_for('index'))

        except IntegrityError:
            logging.error('Could not register user with email because it already exists: %s', request.form['email'] )
            flash('That email is already in use')

    return render_template('register.html')

# the user can create a blog only if he is logged in. if this is the case and he filled
# every field, the new blog will be created and he will be redirected to the start page
@app.route('/createBlog', methods=['GET', 'POST'])
@login_required
def createBlog():
    if request.method == 'POST' and request.form['blog_text'] and request.form['blog_title']:
        with database.transaction():
            user = get_current_user()
            blog = Blog.create(title=request.form['blog_title'],
                               creator=user,
                               text=request.form['blog_text'],
                               creation_date=datetime.datetime.now())

        logging.info('User created new blog with title %s', request.form['blog_title'] )
        return redirect(url_for('index'))

    return render_template('createBlog.html')

# returns detail view of a blog entry. later it will cover also comments for the blog
@app.route('/blog/<blogId>/')
def blog(blogId):
    blog = get_object_or_404(Blog, Blog.id == blogId)
    return render_template('blog.html', blog=blog)

# for demonstration purpose for Cross-Site-Scripting
@app.route('/unsafeblog/<blogId>/')
def unsafeblog(blogId):
    blog = get_object_or_404(Blog, Blog.id == blogId)
    return render_template('unsafeblog.html', blog=blog)

# deletes the session variable logged_in and all flash messages
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('_flashes', None)
    return redirect(url_for('index'))

# flask provides a "session" object, which allows us to store information across
# requests (stored by default in a secure cookie).  this function allows us to
# mark a user as being logged-in by setting some values in the session data: **
def auth_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['name'] = user.first_name + ' ' + user.last_name
    session['user_email'] = user.email

# get the user from the session **
def get_current_user():
    if session.get('logged_in'):
        return User.get(User.id == session['user_id'])

# allow running from the command line
if __name__ == '__main__':
    #drop_tables()
    #create_tables()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
