# -*- encoding: utf-8 -*-
# begin
import json
from datetime import datetime

from cybsec import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except ValueError:
        pass


class DmcaHistory(db.Model):
    __tablename__ = "dmca_history"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    date_posted = db.Column('date_posted', db.DateTime, default=datetime.utcnow)
    offender_ip = db.Column('offender_ip', db.String)
    offender_mac = db.Column('offender_mac', db.String)
    action = db.Column('action', db.String)
    classification = db.Column('classification', db.String)
    case_id = db.Column('case_id', db.String)
    evidence = db.deferred(db.Column('evidence', db.Text))
    offender_userid = db.Column('offender_userid', db.String)
    date_closed = db.Column('date_closed', db.DateTime)
    comments = db.deferred(db.Column('comments', db.Text))

    user = db.relationship('User', foreign_keys=internal_user_id)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __str__(self):
        return f"DMCA_History({self.id}, {self.internal_user_id}, {self.date_posted}, {self.offender_ip}, {self.offender_mac}, " \
            f"{self.action}, {self.classification}, {self.case_id}, {self.evidence}, " \
            f"{self.offender_userid}, {self.date_closed}, {self.comments})"


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    username = db.Column('username', db.String)
    role = db.Column('role', db.String)
    name = db.Column('name', db.Text)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"User('{self.id}', '{self.username}', '{self.role}', '{self.name}')"


class Pastebin(db.Model):
    __tablename__ = "pastebin"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    date = db.Column('date', db.DateTime, default=datetime.utcnow)
    status = db.deferred(db.Column('status', db.Text))
    comp_user = db.deferred(db.Column('comp_user', db.Text))
    data = db.deferred(db.Column('data', db.Text))

    user = db.relationship('User', foreign_keys=internal_user_id)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"Pastebin('{self.id}', '{self.date}', '{self.internal_user_id}', '{self.comp_users}')"


# nuff said
class GeorgeQuotes(db.Model):
    __tablename__ = "george_quotes"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    quote = db.deferred(db.Column('quote', db.Text))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"Quote('{self.id}', '{self.quote}')"


# list of approved places to go out and eat
class FoodList(db.Model):
    __tablename__ = "food_list"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    restaurant = db.deferred(db.Column('restaurant', db.Text))
    food_type = db.Column('food_type', db.String)

    user = db.relationship('User', foreign_keys=internal_user_id)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"Food('{self.id}', '{self.internal_user_id}', '{self.restaurant}', '{self.food_type}')"


# taha.....
class Twss(db.Model):
    __tablename__ = "twss"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    count = db.Column('count', db.Integer)
    date_posted = db.Column('date_posted', db.DateTime, default=datetime.utcnow)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"TWSS('{self.id}', '{self.count}', '{self.date_posted}')"


'''
################################################################################################################################################################################################################
Added 8/16/2019 by Jared
################################################################################################################################################################################################################
'''


# holds the list of IPs
class edl_IPList(db.Model):
    __tablename__ = "edl_ip_list"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    ip_string = db.deferred(db.Column('ip_string', db.String))
    # when it was blocked
    date_blocked = db.Column('date_blocked', db.DateTime, default=datetime.utcnow)
    # date it was unblocked
    date_allowed = db.Column('date_allowed', db.DateTime)
    # if its being blocked or not
    status = db.deferred(db.Column('status', db.String))
    # direction_block is meaning if we are blocking it inbound to outbound or vis versa
    # will have a value of outbound, inbound, or both
    direction_block = db.deferred(db.Column('direction_block', db.String))
    comments = db.deferred(db.Column('comments', db.Text))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"edl_IPList('{self.id}', '{self.internal_user_id}', '{self.ip_string}', '{self.date_blocked}', '{self.date_allowed}', '{self.status}', '{self.direction_block}', '{self.comments}')"


class edl_URLList(db.Model):
    __tablename__ = "edl_url_list"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    url_string = db.deferred(db.Column('url_string', db.String))
    # date it was blocked
    date_blocked = db.Column('date_blocked', db.DateTime, default=datetime.utcnow)
    # date it was unblocked
    date_allowed = db.Column('date_allowed', db.DateTime)
    # if its being blocked or not
    status = db.deferred(db.Column('status', db.String))
    # direction_block is meaning if we are blocking it inbound to outbound or vis versa
    # will have a value of outbound, inbound, or both
    direction_block = db.deferred(db.Column('direction_block', db.String))
    comments = db.deferred(db.Column('comments', db.Text))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"edl_URLList('{self.id}', '{self.internal_user_id}', '{self.url_string}', '{self.date_blocked}', '{self.date_allowed}', '{self.status}', '{self.direction_block}', '{self.comments}')"


# list of links we commonly use
class linkLists(db.Model):
    __tablename__ = "link_list"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    url_link = db.deferred(db.Column('url_link', db.String))  # holds the actual url link
    display_text = db.deferred(db.Column('display_text', db.String))  # holds the text to use as the link text
    category = db.deferred(db.Column('category', db.String))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"linkList('{self.id}', '{self.url_link}', '{self.display_text}', '{self.category}')"


'''
################################################################################################################################################################################################################
Added 10/3/2019 by Jared
################################################################################################################################################################################################################
'''


# associates api keys to users
class api_table(db.Model):
    __tablename__ = "api_table"
    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    internal_user_id = db.Column('internal_user_id', db.Integer, db.ForeignKey('user.id'))
    api_key = db.Column('api_key', db.String)
    date_created = db.Column('date_created', db.DateTime, default=datetime.utcnow)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"api_table('{self.id}', '{self.internal_user_id}', '{self.api_key}', '{self.date_created}')"


'''
################################################################################################################################################################################################################
'''


# # end
