import re
import hmac

import webapp2

from google.appengine.ext import db

from user import User
from post import Post
from comment import Comment
from like import Like
import jinjahelper

# random string use as our hash secret for cookies.

secret = 'sdowla'


# Creates secure value using secret.

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Functions for taking one of those secure values and making sure it's valid.


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# BlogHandler class -- here we have all the generic stuff that all the handlers
# can use. This is a BlogHandler Class, inherits webapp2.RequestHandler,
# and provides helper methods.


class BlogHandler(webapp2.RequestHandler):
    # This methods write output to client browser.
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    # This methods renders html using template.

    def render_str(self, template, **params):
        params['user'] = self.user
        return jinjahelper.render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# sets a cookie whose name is name and value is val

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

# give it a name, and if finds that cookie in the request if
# cookie_val and pass check_secure_val then return cookie val.

    def read_secure_cookie(self, name):
        # find the cookie in the request
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        # This function sets a secure cookie, user ID, and it equals to the
        # users ID. Gets the user's id and data store.
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


# Reads the cookie and makes sure that cookie is valid and
# sets the user on the handler.
# Check if user is logged in or not.
# This methods gets executed for each page and
# verfies user login status, using oookie information.

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        # if user_id is valid it assigns self.user to that user
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')

# blog


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(BlogHandler):
    def get(self):
        # renders all posts, sorted by date
        postId_deleted = self.request.get('postId_deleted')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, postId_deleted=postId_deleted)


class PostPage(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login?error=You need to logged in " +
                          "to comment or like!! ")
            return
        # Display post page with content, comments and likes.
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("permalink.html", post=post, likeCount=likes.count(),
                    comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        c = ""
        if(self.user):
            # post-like value increases by clicking like.
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your  " +
                                  "own post!")
                    return
                elif likes.count() == 0:
                    like = Like(parent=blog_key(),
                                user_id=self.user.key().id(),
                                post_id=int(post_id))
                    like.put()
                    self.redirect("/blog/" + post_id +
                                  "?error=You can like your  " +
                                  "post once.!!!!")
                    return

            comment = self.request.get('comment')
            if comment:
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id), comment=comment)
                c.put()
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You need to type your  " +
                              "comment.!!!!")
                return
        else:
            self.redirect("/login?error=First login and then " +
                          "try to edit, comment or like.!!")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post,
                    comments=comments, likeCount=likes.count(),
                    new=c)


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment = db.get(key)
            if post:
                if comment:
                    if comment.user_id == self.user.key().id():
                        comment.delete()
                        self.redirect("/blog/"+post_id+"?commentId_deleted=" +
                                      comment_id)
                    else:
                        self.redirect("/login?error=You cannot delete this " +
                                      "comment first login and then delete!! ")
                else:
                    self.redirect("/blog/" + post_id + "?error=Type " +
                                  "your comment please!!.")
            else:
                self.redirect("/blog/" + post_id + "?error=Post " +
                              "does not exist!!.")
        else:
            self.redirect("/login?error=First login and then delete!! ")


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            comment = db.get(key)
            if post:
                if comment.user_id == self.user.key().id():
                    if comment:
                        self.render("editcomment.html",
                                    comment=comment.comment)
                    else:
                        error = "Type your comment, please!"
                        self.render("editcomment.html",
                                    comment=comment.comment, error=error)
                else:
                    self.redirect("/login?error=If you want " +
                                  "to edit this comment, login first!")

            else:
                self.redirect("/blog/" + post_id + "?error=Post " +
                              "does not exist!!.")
        else:
            self.redirect("/login?error=You need " +
                          "to login first!")

    def post(self, post_id, comment_id):
        # Updates post.
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if self.user:
            if post:
                key = db.Key.from_path('Comment',
                                       int(comment_id), parent=blog_key())
                comment = db.get(key)
                if comment:
                    if comment.user_id == self.user.key().id():
                        comment.comment = self.request.get('comment')
                        comment.put()
                        self.redirect('/blog/%s' % post_id)
                    else:
                        self.redirect("/login?error=If you want " +
                                      "to edit this comment, login first!")
                else:
                    error = "Type your comment, please!"
                    self.render("editcomment.html",
                                comment=comment.comment, error=error)
            else:
                self.redirect("/blog/" + post_id + "?error=Post " +
                              "does not exist!!.")
        else:
            self.redirect("/login?error=You need " +
                          "to login first!")


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login?error=To post, you need " +
                          "to login first!")

    def post(self):
        if not self.user:
            self.redirect("/login?error=To post, you need " +
                          "to login first!")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(
                    parent=blog_key(), user_id=self.user.key().id(),
                    subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                   "newpost.html",
                   subject=subject,
                   content=content,
                   error=error)


class UpdatePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # check if the post exist
            if post:
                if post.user_id == self.user.key().id():
                    self.render("updatepost.html", subject=post.subject,
                                content=post.content, post=post)
                else:
                    self.redirect("/blog/" + post_id + "?error=You cannot " +
                                  "edit this record.")
            else:
                self.redirect("/blog/" + post_id + "?error=Post does not " +
                              "exist.")
        else:
            self.redirect("/login?error=You need to login, " +
                          "to edit your post!!")

    def post(self, post_id):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post:
                if post.user_id == self.user.key().id():
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    self.redirect("/blog/" + post_id + "?error=You cannot " +
                                  "post this record.")
            else:
                self.redirect("/blog/" + post_id + "?error=Post does not " +
                              "exist.")
        else:
            self.redirect("/login?error=You need to login first, " +
                          "to post your updated post !!")


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post:
                if post.user_id == self.user.key().id():
                    post.delete()
                    self.redirect("/blog/?postId_deleted="+post_id)
                else:
                    self.redirect("/blog/" + post_id + "?error=You cannot " +
                                  "delete this record.")
            else:
                self.redirect("/blog/" + post_id + "?error=Post does not " +
                              "exist.")
        else:
            self.redirect("/login?error=You need to login first" +
                          " to delete your post!")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        # if we have an error we re-render the form with the error
        # messages and values.
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
    # just raises an error


def done(self, *a, **kw):
        raise NotImplementedError


# inherits from the Signup class

class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        # if user exist then send error message.
        if u:
            msg = 'That user already exists. Please login!'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            # call the login function, which set the cookies.
            self.login(u)
            self.redirect('/blog/welcome')
# This is a login page, not for creating a new user, but signing into an
# old one.


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html', error=self.request.get('error'))

    def post(self):
        # out of the request we get the username and password.
        username = self.request.get('username')
        password = self.request.get('password')

        # we call the login function on the user objects. It returns
        # the user if username and passwords are valid. It returns
        # none if it's not.
        # it will sets the cookie
        u = User.login(username, password)
        if u:
            # login function here on the blog handler.
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login, you need to signup first!!'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        # call the logout function which is in Bloghandler class
        self.logout()
        self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/updatepost/([0-9]+)', UpdatePost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/([0-9]+)/([0-9]+)/deletecomment',
                                DeleteComment),
                               ('/blog/([0-9]+)/([0-9]+)/editcomment',
                                EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ],
                              debug=True)
