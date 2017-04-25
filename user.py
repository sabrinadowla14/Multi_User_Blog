import random
import hashlib

from string import letters
from google.appengine.ext import db


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# h is what we store in the db
# returns salt and hash version of name, pw and salt


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# takes name, password and h from the database
# and checks if h from the database matches
# users version of hasvalue.


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# users_key creates the ancestor element in the database to
# store all of our users.


def users_key(group='default'):
    return db.Key.from_path('users', group)


# users object we will be storing in the database.

class User(db.Model):
    # This is a User Class, which holds user information.
    # And helps to store/retrieve User data to/from database.
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # looks up a user by id
    # you can call this method[by_id] on this object[User]
    # user.byid give it an ID, get_by_id to load the user on to the
    # database doesn't have to be an instance of the object
    # cls refers to self, which here is Class User

    @classmethod
    def by_id(self, uid):
            # This method fetchs User object from database.
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(self, name):
        # This method fetchs List of User objects from database,
        # whose name is name.
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(self, name, pw, email=None):
        # This method creates a new User in database.
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

# going to call user class functions by_name method. We say class by name
# not user by name so that we can over write this function. by name looks
# for a user of that name. if it exist it's a valid password.

    @classmethod
    def login(self, name, pw):
        # This method creates a new User in database.
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
