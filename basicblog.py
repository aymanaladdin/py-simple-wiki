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

import re
import os
import random
import time
import string
import cgi

import jinja2
import webapp2
import logging

import hmac
import hashlib

import json

from google.appengine.ext import db
from google.appengine.api import memcache

#===================================(JINJA)=======================================================

#init jinja2
template_dir = os.path.join(os.path.dirname(__file__), "templates") 
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


#=============================(GLOBAL VARIABLRS)=======================================================
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

def name_filtr(pagename):
 return cgi.escape(pagename, quote = True)


def get_wiki(pagename):
    return db.GqlQuery("SELECT * FROM Wiki WHERE path = :name",name = name_filtr(pagename)).get()

def add_wiki(pagename, content):
    return Wiki(path= pagename, content = content).put()

def update_wiki(wiki, new_content):
    wiki.content = new_content
    return wiki.put()

def get_user(username):
    return db.GqlQuery("SELECT * FROM User WHERE username = :name",name = username).get()



#=============================(USER DATA VALIDATION METHODS)=======================================================

#valid user name checking
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
 return USER_RE.match(username)

#valid user password checking
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
 return USER_RE.match(password)

#valid user email checking
MAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    if email:
     return MAIL_RE.match(email)
    return True

#verify password checking
def pass_verify(password, verify):
 return (password == verify) 

#====================================(COOKIES HASHING USING SECRET)==========================================================#

def make_hash_val(str_val):
    return hashlib.md5(str_val).hexdigest()

def make_hash_val_with_sec(str_val):
    SECRET = "hardTOguess"                 
    return hmac.new(SECRET, str_val).hexdigest()

def make_secure_val(str_val):
    return "%s|%s"%(str_val,make_hash_val_with_sec(str_val))

def check_secure_val(hash_and_val):
    if hash_and_val is not None:
        val = hash_and_val.split("|")[0]
    
        if make_secure_val(val) == hash_and_val:
            return val


#=============================(PASSWORD HASHING USING SALT)=======================================================

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = make_salt()):
    hash_val = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (hash_val, salt)

def valid_pw(name, pw, hashed_pw):
  salt = hashed_pw.split(',')[1]
  return hashed_pw == make_pw_hash(name, pw, salt)


#=============================(DB ENTITIES CLASSES)=======================================================

#create post entity
class Wiki(db.Model):
    path = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)


#create post entity
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email    = db.StringProperty()
    created  = db.DateTimeProperty(auto_now_add = True)
    
#=================================(APP HANDLERS)==============================================

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **param):
        template_str = jinja_env.get_template(template)
        return template_str.render(param)

    def render(self, template, **kw):
        return self.write(self.render_str(template, **kw))


#=============================(USER LOG_SIGN HANDLER)=======================================================


class SignUp(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        #inputs from the user
        user_name   = self.request.get("username")
        user_pass   = self.request.get("password")
        user_verify = self.request.get("verify")
        user_mail   = self.request.get("email")

       #validate user inputs
        valid_name   = valid_username(user_name)
        valid_pass   = valid_password(user_pass)
        valid_verify = (pass_verify(user_pass, user_verify) or (not valid_pass))
        valid_mail   = valid_email(user_mail)
        new_user = get_user(user_name)

        #error variables
        name_error =""
        pass_error =""
        verfy_error=""
        mail_error= ""

        #var flags
        error_flag = False 

        if not valid_name:
            error_flag = True
            name_error = "That's not a valid username."

        if not valid_pass:
            error_flag = True
            pass_error ="That wasn't a valid password."

        if not valid_verify:
               error_flag = True
               verfy_error ="Your passwords didn't match."

        if not valid_mail:
               error_flag = True
               mail_error = "That's not a valid email."

 
        if new_user is not None:
               error_flag = True
               name_error = "username already exist."               
                
        if error_flag:
            
          self.render("signup-form.html", error_username = name_error,
                                          error_password = pass_error,
                                          error_verify   = verfy_error,
                                          error_email    = mail_error,
                                          username       = user_name,
                                          email          = user_mail)

        if not error_flag:

                     user = User(username = user_name, password = make_pw_hash(user_name, user_pass), email = user_mail)
                     user_key = user.put()
                     
                     #generating id cookie
                     new_cookie_val = make_secure_val(str(user_key.id()))
                     self.response.headers.add_header("Set-Cookie", "user =%s" %new_cookie_val)
                     
                     #redirect to new welcome page  
                     self.redirect("/")
    
    

class LogIn(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        logged_name = self.request.get("username")
        logged_pass = self.request.get("password")

        user = get_user(logged_name)

        if user and valid_pw(logged_name, logged_pass, user.password):

             new_cookie_val = make_secure_val(str(user.key().id()))
             self.response.headers.add_header("Set-Cookie", "user =%s" %new_cookie_val)
             self.redirect("/")

        else:
            self.render("login.html",username = logged_name, error = "invalid login")
            
        
class LogOut(Handler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", "user=%s;bath='/'"% "")
        self.redirect("/")


#=================================(WIKI HANDLER)=======================================================


class WikiPage(Handler):
    def get(self, pagename):
        wiki_page = get_wiki(pagename)

        if pagename is "/" and wiki_page is None:
            Wiki(path = "/", content = "Welcome To Default Page").put()
            self.render("wikipage.html", pagecontent = "Welcome To Default Page")

        elif wiki_page is not None:
            self.render("wikipage.html", pagecontent = wiki_page.content)
        else:
            self.redirect("/_edit%s" %pagename)

class EditPage(Handler):
    def get(self, pagename):

        userID_cookie_str = self.request.cookies.get("user")
        userID_val = check_secure_val(userID_cookie_str)

        if userID_val:
            wiki_page = get_wiki(pagename)
            if wiki_page is not None:
                self.render("editpage.html", pagecontent = wiki_page.content)
            else:
                self.render("editpage.html", pagecontent ="")
        else:
            self.redirect("/")

    def post(self, pagename):
            wiki_page = get_wiki(pagename)
            if wiki_page is not None:
                update_wiki(wiki_page, self.request.get("content"))
            else:
                add_wiki(pagename, self.request.get("content"))
            #time.sleep(0.4)    
            self.redirect(pagename)
        
        
app = webapp2.WSGIApplication([
                               ('/signup', SignUp),
                               ('/login', LogIn),
                               ('/logout', LogOut),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               ],
                              debug=True)
