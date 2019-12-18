from cybsec import db
from cybsec.models import Pastebin


class PastebinHelper:
    def __init__(self, data, status, comp_user, username, user_id):
        self.data = data
        self.status = status
        self.comp_user = comp_user
        self.username = username
        self.user_id = user_id

    def edit_entry(self, entry_id):
        post = Pastebin.query.filter_by(id=entry_id).first()

        post.data = self.data
        post.status = self.status
        post.comp_user = self.comp_user
        post.username = self.username

        db.session.commit()
