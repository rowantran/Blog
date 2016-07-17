#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import hashlib
import hmac
import jinja2
import logging
import os
import random
import string
import webapp2

from google.appengine.ext import db

secret = '@HK=&qt3_^crF3mFXwL2?@bPS?@LghhC'

# Jinja setup
template_path = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_path),
                               autoescape = True)

# Define models
class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)


class Post(db.Model):
    title = db.StringProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)
    body = db.TextProperty(required = True)


# Hash functions
def hash_username(username):
    return hmac.new(secret, username, hashlib.sha256).hexdigest()

def hash_password(password, salt):
    return hmac.new(salt, password, hashlib.sha256).hexdigest()

# Cookie functions
def write_cookie(response, name, value):
    cookie = "{}={}".format(name, value)
    response.headers.add_header('Set-Cookie', cookie)

def delete_cookie(response, name):
    cookie = "{}=; expires=Thu, 01 Jan 1970 00:00:00 GMT".format(name)
    response.headers.add_header('Set-Cookie', cookie)

def generate_cookie(username):
    return "{}|{}".format(username, hash_username(username))

def verify_cookie(cookie):
    username = cookie.split("|")[0]
    return cookie == generate_cookie(username)

# Authentication functions
def authenticate_user(user, password):
    user_hash = hash_password(str(password), str(user.salt))
    return user_hash == user.password

# Other functions
def username_exists(username):
    return User.gql("WHERE username=:username", username=username).get()

# Define handlers
class Handler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))


class MainHandler(Handler):
    def render_main(self, username='', auth=False):
        posts = Post.all()
        posts.order('-date')

        self.render('main.html', username=username, posts=posts, auth=auth)

    def get(self):
        user = self.request.cookies.get('User')
        if not user:
            self.render_main()
        else:
            if not verify_cookie(user):
                self.render_main()
            else:
                username = user.split("|")[0]
                self.render_main(username, True)


class RegisterHandler(Handler):
    def render_register(self, username='', email='', errors=''):
        self.render('register.html', username=username, email=email, errors=errors)
    
    def get(self):
        self.render_register() 

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        confirm_password = self.request.get('confirm-password')
        email = self.request.get('email', '')

        errors = []
        if not username:
            errors.append("Username is required.")
        if not password == confirm_password:
            errors.append("Passwords must match.")
        if not password:
            errors.append("Password is required.")
        if username_exists(username):
            errors.append("Username already exists.")
    
        if errors:
            self.render_register(username, email, '<br>'.join(errors))
        else:
            salt = "".join(random.choice(string.letters) for i in xrange(16))
            password_hash = hash_password(password, salt)

            new_user = User(username = username, email = email,
                            password = password_hash, salt = salt)
            new_user.put()

            write_cookie(self.response, 'User', generate_cookie(username))
            self.redirect("/")


class LoginHandler(Handler):
    def render_login(self, username='', error=False):
        if error:
            error_message = "Username or password is incorrect."
        else:
            error_message = ""
        self.render('login.html', username=username, error=error_message)

    def get(self):
        self.render_login()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.gql('WHERE username=:username', username=username).get() 
        if user:
            if authenticate_user(user, password):
                write_cookie(self.response, 'User', generate_cookie(username))
                self.redirect("/")
            else:
                self.render_login(username, True)
        else:
            self.render_login(username, True)


class LogoutHandler(Handler):
    def get(self):
        delete_cookie(self.response, 'User')
        self.redirect("/")


class NewPostHandler(Handler):
    def render_newpost(self, title='', body='', error=''):
        self.render('newpost.html', title=title, body=body, error=error)

    def get(self):
        self.render_newpost()
    
    def post(self):
        title = self.request.get('title')
        body = self.request.get('body')

        if title and body:
            new_post = Post(title = title, body = body)
            new_post.put()
            self.redirect('/post/{post_id}'.format(post_id = new_post.key().id()))
        else:
            self.render_newpost(title, body, "Title and body are required.")

class PostHandler(Handler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        self.render('post.html', post=[post])


app = webapp2.WSGIApplication([
    webapp2.Route(r'/', handler=MainHandler, name='main'),
    webapp2.Route(r'/register', handler=RegisterHandler, name='register'),
    webapp2.Route(r'/login', handler=LoginHandler, name='login'),
    webapp2.Route(r'/logout', handler=LogoutHandler, name='logout'),
    webapp2.Route(r'/newpost', handler=NewPostHandler, name='newpost'),
    webapp2.Route(r'/post/<post_id:\d+>', handler=PostHandler, name='post')
], debug=True)
