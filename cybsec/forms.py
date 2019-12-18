from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, MacAddress, Optional, IPAddress

from cybsec.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Linkblue"})
    email = StringField('Email',
                        validators=[DataRequired(), Email()], render_kw={"placeholder": "@uky.edu"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "AD password"})
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()

        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Linkblue"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "AD password"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')



# Form listing some of the types of restaurant food types and a name for the restaurant which will then  be tied to the user who submitted it
class FoodForm(FlaskForm):
    restaurant = StringField('Restaurant', validators=[DataRequired()],
                             render_kw={"placeholder": "ie. Tally Ho, Qdoba, Goodfellas, etc."})
    food_type = SelectField('Cuisine', validators=[DataRequired()],
                            choices=[('Mexican', 'Mexican'), ('Italian', 'Italian'), ('TexMex', 'TexMex'),
                                     ('Burgers', 'Burger Joint'),
                                     ('Qdoba', 'Chase'), ('Pizza', 'Pizza'), ('BBQ', 'BBQ'),
                                     ('Asian', 'Asian'), ('Cajun', 'Cajun'),
                                     ('American', 'American'), ('Other', 'Other')])
    submit = SubmitField('Submit')



# Following form submit a george quote to the db table
class QuoteSub(FlaskForm):
    quote = StringField('Quote: ', validators=[DataRequired()])
    submit = SubmitField('Submit')


class UpdateForm(FlaskForm):
    user_id = StringField('User ID', render_kw={"placeholder": "Don't do this"})
    username = StringField('Username', render_kw={"placeholder": "If user can auth"})
    role = StringField('Role')
    submit = SubmitField('Submit')


'''
#######################################################################################################################################
Added 8/16/19 by Jared
#######################################################################################################################################
'''


# Used for both the IP and URL EDL Table (using regex to parse out what we are blocking)
class EDL_Submission(FlaskForm):
    user_input = StringField('Enter IP or URL', render_kw={"placeholder": "ie. 123.45.67.89 or badbouy.cry"})
    block_direction = SelectField('Which direction should it be blocked?',
                                  choices=[("both", "Both"), ("outbound", "Outbound"), ("inbound", "Inbound")])
    comments = StringField('Comments', render_kw={"placeholder": "ie. Reason why its being blocked"})
    submit = SubmitField('Submit')



# Submission to add links to the database
class Link_Submission(FlaskForm):
    url_text = StringField('Enter URL', render_kw={
        "placeholder": "ie. https://172.24.164.164/lc-landing-page/smc.html#/dashboard or https://www.talosintelligence.com/"})
    displayText = StringField('Text Used to Display the Link',
                              render_kw={"placeholder": "ie. Stealthwatch Beta A or Talos IP Lookup"})
    category = StringField('Category', default="General")
    submit = SubmitField('Submit')


class PastebinParse(FlaskForm):
    pastebin_text = TextAreaField('Pastebin text', validators=[DataRequired()])
    submit = SubmitField('Submit')


class PastebinSubmit(FlaskForm):
    text = StringField('Additional email information')
    submit = SubmitField('Send', validators=[Optional()])


class DMCAParse(FlaskForm):
    dmca_text = TextAreaField('DMCA Email', validators=[DataRequired()], render_kw={"rows": "10"})
    submit = SubmitField('Submit')


'''
#######################################################################################################################################
Added 8/27/19 by Jared
#######################################################################################################################################
'''


# Form to lookup ips or urls
class LookupForm(FlaskForm):
    search_input = StringField('Lookup IP\\URL: ', validators=[DataRequired()])
    submit = SubmitField('Search')


'''
#######################################################################################################################################
Added 9/10/19 by Jared
#######################################################################################################################################
'''

# Form to update and/or unblock an entry
class DMCA_DetsForm(FlaskForm):
    type_input = SelectField('Edit Type: ', choices=[("Update", "Update Only"), ("Unblock", "Unblock & Update")],
                             validators=[DataRequired()])
    comments_input = TextAreaField('Comments: ')
    offender_userid = StringField('User ID: ', render_kw={"placeholder": "Optional"})
    wlc_pass_input = PasswordField('WLC Password: ', validators=[DataRequired()],
                                   render_kw={"placeholder": "Your linkblue password."})
    submit = SubmitField('Submit')


'''
#######################################################################################################################################
Added 9/27/19 by Jared
#######################################################################################################################################
'''


# Form to add svc acct to db for api access
class Api_UserForm(FlaskForm):
    user_input = StringField('Linkblue: ', validators=[DataRequired()])
    submit = SubmitField('Submit')


'''
#######################################################################################################################################
Added 10/1/19 by Jared
#######################################################################################################################################
'''


class LDAPForm(FlaskForm):
    user_input = StringField('Linkblue: ', validators=[DataRequired()])
    type_input = SelectField('Domain: ', choices=[("AD", "AD"), ("MC", "MC")], validators=[DataRequired()])
    submit = SubmitField('Submit')
