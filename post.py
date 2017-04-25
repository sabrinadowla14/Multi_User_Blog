from google.appengine.ext import db

from user import User
import jinjahelper


# Post Model
class Post(db.Model):

    # This is a Post Class, which holds blog post information.
    # And helps to store/retrieve User data to/from database.
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def userName(self):
        #   Gets username of the person, who wrote the blog post.
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        # Renders the post using object data.
        self._render_text = self.content.replace('\n', '<br>')
        return jinjahelper.render_str("post.html", p=self)
