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
    likes = db.ListProperty(long)
    dislikes = db.ListProperty(long)


class Post(db.Model):
    author = db.ReferenceProperty(User, required = True)
    likes = db.IntegerProperty(default = 0, required = False)
    title = db.StringProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)
    body = db.TextProperty(required = True)

    def get_comments(self):
        return Comment.gql("WHERE post = :post", post=self)


class Comment(db.Model):
    author = db.ReferenceProperty(User, required = True)
    post = db.ReferenceProperty(Post, required = True)
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

def get_cookie_username(cookie):
    return cookie.split("|")[0]

def verify_cookie(cookie):
    username = get_cookie_username(cookie)
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
    def render_main(self, user='', username='', auth=False):
        posts = Post.all()
        posts.order('-date')

        self.render('main.html', user=user, username=username, posts=posts, auth=auth)

    def get(self):
        user = self.request.cookies.get('User')
        if not user:
            self.render_main()
        else:
            if not verify_cookie(user):
                self.render_main()
            else:
                username = user.split("|")[0]
                user = User.gql("WHERE username=:username", username=username).get()
                self.render_main(user, username, True)


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
        user = self.request.cookies.get('User')
        if user:
            self.render_newpost()
        else:
            self.redirect("/")
 
    def post(self):
        user = self.request.cookies.get('User')
        if user:
            if verify_cookie(user):
                username = get_cookie_username(user)
                author = User.gql("WHERE username=:username", username=username).get()
                title = self.request.get('title')
                body = self.request.get('body')

                if title and body:
                    new_post = Post(author = author, title = title, body = body)
                    new_post.put()
                    self.redirect('/post/{post_id}'.format(post_id = new_post.key().id()))
                else:
                    self.render_newpost(title, body, "Title and body are required.")
            else:
                self.redirect("/")
        else:
            self.redirect("/")


class PostHandler(Handler):
    def get(self, post_id):
        user = self.request.cookies.get('User')
        post = Post.get_by_id(int(post_id))

        if user:
            user_data = User.gql("WHERE username=:username", username=get_cookie_username(user)).get()
            self.render('post.html', post=[post], auth=verify_cookie(user), user=user_data, username=get_cookie_username(user))
        else:
            self.render('post.html', post=[post], auth=False, user='', username='')

class VoteHandler(Handler):
    def get(self, post_id):
        action = self.request.get('action')
        user = self.request.cookies.get('User')
        post = Post.get_by_id(int(post_id))
        if user:
            if verify_cookie(user):
                user_data = User.gql("WHERE username=:username", username=get_cookie_username(user)).get()
                if post:
                    post_id = int(post_id)
                    if action == "up":
                        if post_id in user_data.likes:
                            post.likes -= 1
                            user_data.likes.remove(post_id)
                        elif post_id in user_data.dislikes:
                            post.likes += 2
                            user_data.dislikes.remove(post_id)
                            user_data.likes.append(post_id)
                        else:
                            post.likes += 1
                            user_data.likes.append(post_id)
                    elif action == "down":
                        if post_id in user_data.dislikes:
                            post.likes += 1
                            user_data.dislikes.remove(post_id)
                        elif post_id in user_data.likes:
                            post.likes -= 2
                            user_data.likes.remove(post_id)
                            user_data.dislikes.append(post_id)
                        else:
                            post.likes -= 1
                            user_data.dislikes.append(post_id)
                    user_data.put()
                    post.put()
                    self.redirect("/")
                else:
                    self.write("Post does not exist.")
            else:
                self.redirect("/")
        else:
            self.redirect("/")


class EditHandler(Handler):
    def render_edit(self, title='', body='', error=False):
        if error:
            error_text = "Both a title and body are required."
        else:
            error_text = ""
        self.render('editpost.html', title=title, body=body, error=error_text)

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        title = post.title
        body = post.body
        self.render_edit(title, body, False)

    def post(self, post_id):
        post_data = Post.get_by_id(int(post_id))
        if post_data:
            user = self.request.cookies.get('User')
            if user:
                if verify_cookie(user):
                    if get_cookie_username(user) == post_data.author.username:
                        title = self.request.get('title')
                        body = self.request.get('body')
                        if title and body:
                            post_data.title = title
                            post_data.body = body
                            post_data.put()
                            self.redirect("/")
                        else:
                            self.render_edit(title, body, True)
                    else:
                        self.redirect("/")
                else:
                    self.redirect("/")
            else:
                self.redirect("/")
        else:
            self.write("Post not found.")


class DeleteHandler(Handler):
    def post(self, post_id):
       post_data = Post.get_by_id(int(post_id))
       if post_data:
           user = self.request.cookies.get('User')
           if user:
               if verify_cookie(user):
                    if get_cookie_username(user) == post_data.author.username:
                        post_data.delete()
                    self.redirect("/")
               else:
                   self.redirect("/")
           else:
               self.redirect("/")
       else:
           self.write("Post not found.")


class CommentHandler(Handler):
    def post(self, post_id):
        post_data = Post.get_by_id(int(post_id))
        if post_data:
            user = self.request.cookies.get('User')
            if user:
                if verify_cookie(user):
                    user_data = User.gql("WHERE username=:username", username=get_cookie_username(user)).get()
                    body = self.request.get('comment')
                    if body:
                        new_comment = Comment(author=user_data, post=post_data, body=body)
                        new_comment.put()
                    self.redirect("/")
            else:
                self.redirect("/")
        else:
            self.write("Post not found.")


class EditCommentHandler(Handler):
    def get(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            user = self.request.cookies.get('User')
            if user:
                if verify_cookie(user):
                    self.render('editcomment.html', comment=comment.body)
                else:
                    self.redirect("/")
            else:
                self.redirect("/")
        else:
            self.write("Comment not found.")

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            user = self.request.cookies.get('User')
            if user:
                if verify_cookie(user):
                    comment_text = self.request.get('comment')
                    if comment_text:
                        comment.body = comment_text
                        comment.put()
                        self.redirect("/")


class DeleteCommentHandler(Handler):
    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            user = self.request.cookies.get('User')
            if user:
                if verify_cookie(user):
                    if get_cookie_username(user) == comment.author.username:
                        comment.delete()
                        self.redirect("/")


app = webapp2.WSGIApplication([
    webapp2.Route(r'/', handler=MainHandler, name='main'),
    webapp2.Route(r'/register', handler=RegisterHandler, name='register'),
    webapp2.Route(r'/login', handler=LoginHandler, name='login'),
    webapp2.Route(r'/logout', handler=LogoutHandler, name='logout'),
    webapp2.Route(r'/newpost', handler=NewPostHandler, name='newpost'),
    webapp2.Route(r'/post/<post_id:\d+>', handler=PostHandler, name='post'),
    webapp2.Route(r'/vote/<post_id:\d+>', handler=VoteHandler, name='vote'),
    webapp2.Route(r'/edit/<post_id:\d+>', handler=EditHandler, name='edit'),
    webapp2.Route(r'/delete/<post_id:\d+>', handler=DeleteHandler, name='delete'),
    webapp2.Route(r'/comment/<post_id:\d+>', handler=CommentHandler, name='comment'),
    webapp2.Route(r'/editcomment/<comment_id:\d+>', handler=EditCommentHandler, name='editcomment'),
    webapp2.Route(r'/deletecomment/<comment_id:\d+>', handler=DeleteCommentHandler, name='deletecomment')
], debug=True)
