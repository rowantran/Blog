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

# Define functions
def hash_username(username):
    return hmac.new(secret, username, hashlib.sha256).hexdigest()

def hash_password(password, salt):
    return hmac.new(salt, password, hashlib.sha256).hexdigest()

def write_cookie(response, name, value):
    cookie = "{}={}".format(name, value)
    response.headers.add_header('Set-Cookie', cookie)

def generate_cookie(username):
    return "{}|{}".format(username, hash_username(username))

def verify_cookie(cookie):
    username = cookie.split("|")[0]
    return cookie == generate_cookie(username)

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
    def get(self):
        user = self.request.cookies.get('User')
        if not user:
            self.redirect('/register')
        else:
            if not verify_cookie(user):
                self.redirect('/register')
            else:
                self.write('Welcome, {}!'.format(user.split("|")[0]))


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
        
        if errors:
            self.render_register(username, email, "<br>".join(errors))
        else:
            salt = "".join(random.choice(string.letters) for i in xrange(16))
            password_hash = hash_password(password, salt)

            new_user = User(username = username, email = email,
                            password = password_hash, salt = salt)
            new_user.put()

            write_cookie(self.response, 'User', generate_cookie(username))
            self.redirect("/")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/register', RegisterHandler)
], debug=True)
