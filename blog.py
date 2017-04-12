import os
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)



###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.redirect('/unit2/welcome?username=' + username)


# User sign up functionality

def users_key(group='default'):
    return db.Key.from_path('users', group)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def login(cls, username, password):
        u = User.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u


class Register(Signup):

    def done(self):
        u = User.by_name(self.username)

        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid Username or Password'
            self.render('login-form.html', error=msg)

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Delete(BlogHandler):

    def get(self, post_id, post_user_id):
        if self.user and self.user.key().id() == int(post_user_id):
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.delete()

            self.redirect('/blog')

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to delete this post")


class EditPost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.render('editpost.html', subject=post.subject,
                        content=post.content, post_id=post_id)
        elif not self.user:
            self.redirect('/login')
        else:
            self.write(
                "You cannot edit this post becuase you are not the one who wrote this post.")

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            post.subject = subject
            post.content = content

            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class LikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot like your own post")
        elif not self.user:
            self.redirect('/login')
        else:
            l = Like.all().filter('user_id =', self.user.key().id()
                                  ).filter('post_id =', post.key().id()).get()

            if l:
                self.redirect('/blog/' + str(post.key().id()))
            else:
                like = Like(parent=key, user_id=self.user.key().id(),
                            post_id=post.key().id())
                post.likes += 1

                like.put()
                post.put()

                self.redirect('/blog/' + str(post.key().id()))


class UnlikePost(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.key().id() == post.user_id:
            self.write("You cannot dislike your own post")
        elif not self.user:
            self.redirect('/login')
        else:
            l = Like.all().filter('user_id =', self.user.key().id()
                                  ).filter('post_id =', post.key().id()).get()

            if l:
                l.delete()
                post.likes -= 1
                post.put()

                self.redirect('/blog/' + str(post.key().id()))
            else:
                self.redirect('/blog/' + str(post.key().id()))


class Like(db.Model):
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)


class Comment(db.Model):
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)


class AddComment(BlogHandler):

    def get(self, post_id, user_id):
        self.render("addcomment.html")

    def post(self, post_id, user_id):
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        c = Comment(parent=key, user_id=int(user_id), content=content)
        c.put()

        self.redirect('/blog/' + post_id)


class DeleteComment(BlogHandler):

    def get(self, post_id, post_user_id, comment_id):

        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)
            comment.delete()

            self.redirect('/blog/' + post_id)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to delete this comment.")


class EditComment(BlogHandler):

    def get(self, post_id, post_user_id, comment_id):
        if self.user and self.user.key().id() == int(post_user_id):
            postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
            comment = db.get(key)

            self.render('editcomment.html', content=comment.content)

        elif not self.user:
            self.redirect('/login')

        else:
            self.write("You don't have permission to delete this comment.")

    def post(self, post_id, post_user_id, comment_id):
        content = self.request.get('content')

        postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        key = db.Key.from_path('Comment', int(comment_id), parent=postKey)
        comment = db.get(key)

        comment.content = content
        comment.put()

        self.redirect('/blog/' + post_id)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ],
                              debug=True)
