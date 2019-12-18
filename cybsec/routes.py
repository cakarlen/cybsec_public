import socket
import re
import ldap3
import os

from flask import url_for, redirect, flash, render_template, request, jsonify, send_file, send_from_directory, Response, \
    abort
from flask_login import current_user, login_user, logout_user
from flask_mail import Message

from cybsec import db, app, login_required, mail

# list of forms to import
from cybsec.forms import LoginForm, FoodForm, QuoteSub, UpdateForm, EDL_Submission, Link_Submission, PastebinParse, \
    PastebinSubmit, LookupForm, DMCA_DetsForm, Api_UserForm, LDAPForm, DMCAParse
from cybsec.models import User, DmcaHistory, GeorgeQuotes, FoodList, edl_IPList, edl_URLList, linkLists, Pastebin, \
    api_table

from scripts.dmca import DMCA
from scripts.ip_lookup import Lookup
from scripts.edl_funcs import EDL
from scripts.home_helper import HomeHelper

from cybsec.le_routes.importTest import netmgr_import, get_user
from cybsec.le_routes.jsoc_buildin import jsoc_main


from sqlalchemy import text
from datetime import datetime

import pandas as pd
import csv
import secrets

from werkzeug.utils import secure_filename

from functools import wraps
import requests
import json

import svc_config
from scripts.pastebin_helper import PastebinHelper

'''
Decorator for api requirement
'''


def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        try:
            # get the key sent from the user and search db for the key
            user_key = request.json['key']
            api_results = api_table.query.filter_by(api_key=user_key).first()
            if (api_results is not None):
                # this second if might be redundant but works for now
                if (user_key == api_results.api_key):
                    # if they match, then proceed
                    return view_function(*args, **kwargs)

            else:
                return Response("Recieved api key does not match any existing keys.\n", status=404)

        except Exception as e:
            print(e)
            return Response(
                'Missing the "key" attribute in the json data or recieved api key does not match any existing keys.\n',
                status=404)

    return decorated_function


'''
TODO:   allow images to be added in the dmca block evidence
        Try to either store the image seperately by tying it with a foreign key of the dmca or just\
'''

'''
#################################################################################################################################
# AUTHENTICATION ROUTES #
#################################################################################################################################
'''


def check_ldap(user, password):
    server = ldap3.Server('gc.ad.uky.edu')
    connection = ldap3.Connection(server, user=user, password=password)
    connection.bind()

    for key, value in connection.result.items():
        if "description" in key:
            if "invalidCredentials" in value:
                return False
            elif "success" in value:
                return True



'''
#################################################################################################################################
# User Logging-things #
#################################################################################################################################
'''


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    super_users = ["caka236", "jlri243"]

    form = LoginForm()

    if form.validate_on_submit():
        svc_account = svc_config.svc_account
        password = svc_config.svc_ps

        if check_ldap(form.username.data + "@uky.edu", form.password.data):
            username = form.username.data

            user = User.query.filter_by(username=username).first()

            os_dir = './static/ldap_roles/'
            temp_roles = []

            if (username in super_users):
                temp_roles.append("SUPERUSER")

            base_flag = False
            # check the text files in ./static/ldap_roles/
            for k in os.listdir(os_dir):
                # check if its a file or dir
                if (os.path.isfile(os.path.join(os_dir, k))):
                    # get the contents of the file
                    with open(os_dir + str(k), mode="r", encoding="utf-8-sig", errors='ignore') as f:
                        content = f.readlines()
                    # stip newline char
                    content = [x.strip() for x in content]

                    # check if username is in list
                    if (username in content):
                        # append the role based on the current text file we are reading
                        temp_roles.append(str(k[:-4]))
                        base_flag = True

            # if the flag is true then atleast one role applied
            if (base_flag):
                roles_combined = ' '.join(map(str, temp_roles))
            else:
                # assign the user just a basic role
                roles_combined = 'USER'

            # get the user display name
            username_temp = get_user('ad', svc_account, password, 'cn', form.username.data)
            temp_displayname =username_temp["displayName"].value

            # if the user exists, then just update the rows
            if user:
                user.role = roles_combined
                if (not user.name):
                    user.name = temp_displayname

            # else create and add the user
            else:
                user = User(username=form.username.data, role=roles_combined, name=temp_displayname)
                db.session.add(user)
            # commit the changes
            db.session.commit()

            login_user(user)
            next_page = request.args.get('next')
            flash(f'Welcome {user.name}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login unsuccessful! Please check your username and/or password.', 'danger')

    return render_template('auth/login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash('You have logged out!', 'danger')
    return redirect(url_for('home'))


@app.route("/account")
@login_required(role="ADMIN SUPERUSER INTERN USER")
def account():
    return render_template('auth/account.html', title='Account')


'''
#################################################################################################################################
# Pastebin ROUTES #
#################################################################################################################################
'''


@app.route("/setup/pastebin")
@login_required(role="ADMIN SUPERUSER INTERN")
def setup_pastebin():
    # the query below gets the username instead of the user.id
    sql_query = text(
        "select pastebin.id, pastebin.comp_user, pastebin.date, pastebin.status, pastebin.data, user.username "
        "from pastebin, user where (pastebin.internal_user_id = user.id) ")
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    dict_resultsEdit = []

    for i in dict_results:
        i['date'] = convert_timeFormat(i['date'])
        i.update({"remove": "remove"})
        dict_resultsEdit.append(i)

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


@app.route("/pastebin/", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def pastebin_page():
    query = Pastebin.query.all()
    now = datetime.now()

    form = PastebinParse()

    if form.validate_on_submit():
        stripped = form.pastebin_text.data.rstrip().lower()

        for item in stripped.split("\n"):
            if "uky.edu" in item:
                full_line = item
                get_line = item.split()
                for data in get_line:
                    if "uky.edu" in data:
                        try:
                            colon_delim = data.split(":")
                            comp_user = colon_delim[0]
                        except:
                            comp_user = data

                        paste = Pastebin(internal_user_id=current_user.id, comp_user=comp_user,
                                         data=f'{full_line}', status="PENDING", date=now)
                        db.session.add(paste)
                        db.session.commit()

    return render_template("pages/pastebin_page.html", title="Pastebin", output=query, form=form)


@app.route("/pastebin/update/<string:user_id>", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER")
def pastebin_update(user_id):
    user = Pastebin.query.get_or_404(user_id)
    form = PastebinSubmit()

    if form.text.data == "":
        form.text.data = "N/A"

    content = f"""
    Please reset the following user’s passwords.
    <br>
    Their credentials were leaked from an outside third party source and as a safety precaution please alert the user and reset their password.
    <br><br>
    User: {user.comp_user}
    <br>
    Additional information: {form.text.data}
    <br><br>
    Thank you,
    <br>
    UK Cybersecurity, Data Privacy, and Policy
    <br><br>
    <em>{current_user.username} initiated this automated message. Please forward this email to <strong>cybersecurity@uky.edu</strong> with any questions/concerns you may have</em>
    """

    if form.validate_on_submit():
        send_email("pastebin", "Compromised credentials", content)

        user.status = "SENT"
        db.session.commit()

        flash("Email has been set to the Helpdesk!", "success")
        return redirect(url_for("pastebin_page"))

    return render_template("pages/pastebin_submit.html", title="Send Pastebin", output=user, form=form)


@app.route("/pastebin/delete/<int:pastebin_id>", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER")
def delete_pastebin(pastebin_id):
    paste = Pastebin.query.get_or_404(pastebin_id)

    db.session.delete(paste)
    db.session.commit()
    return redirect(url_for('pastebin_page'))


@app.route("/pastebin/update/post/<int:entry_id>", methods=["POST"])
@login_required(role="ADMIN SUPERUSER")
def pastebin_update_post(entry_id):
    if request.method == 'POST':
        # get the form values
        data = request.form["data"]
        status = request.form["status"]
        comp_user = request.form["comp_user"]
        username = request.form["username"]

        # Init HomeHelper
        pastebin_helper = PastebinHelper(data, status, comp_user, username, current_user.id)
        pastebin_helper.edit_entry(entry_id)

    # redirect back to home page
    return redirect(url_for('pastebin_page'))


'''
#################################################################################################################################
# User Update ROUTES #
#################################################################################################################################
'''


@app.route("/update")
@login_required(role="SUPERUSER")
def update_page():
    # results = User.query.all()
    return render_template("pages/update_user.html")


@app.route("/update/<string:user_id>", methods=['GET', 'POST'])
@login_required(role="SUPERUSER")
def update_page_submit(user_id):
    user = User.query.get_or_404(user_id)
    form = UpdateForm()

    if form.validate_on_submit():
        if form.user_id.data:
            user.id = form.user_id.data
        if form.username.data:
            user.username = form.username.data
        if form.role.data:
            user.role = form.role.data.upper()

        db.session.commit()

        flash(f"{user.username} has been updated!", "success")
        return redirect(url_for("update_page"))

    return render_template("results/update_results.html", output=user, form=form)


@app.route("/setup/update_users")
@login_required(role="SUPERUSER")
def setup_update_users():
    # the query below gets the username instead of the user.id
    sql_query = text("select * from user")
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


'''
#################################################################################################################################
# Home Page #
#################################################################################################################################
'''


@app.route("/setup/home")
@login_required(role="USER ADMIN SUPERUSER INTERN")
def setup_home():
    # the query below gets the username instead of the user.id
    sql_query = text(
        'select dmca_history.id, dmca_history.case_id, dmca_history.date_posted, user.username, dmca_history.action, '
        'dmca_history.classification, dmca_history.offender_ip, dmca_history.offender_mac, dmca_history.evidence '
        'from dmca_history, user '
        'where (dmca_history.internal_user_id = user.id)')
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]

    for i in dict_results:
        i['date_posted'] = convert_timeFormat(i['date_posted'])

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


@app.route("/")
@app.route("/home")
def home():
    return render_template('pages/home.html')


'''
#########################################################################################################
# Fud Routes and Functions #
#########################################################################################################
'''


@app.route("/food/", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER")
def food():
    # set the form obj
    form = FoodForm()

    # check if we are submitting anything
    if form.validate_on_submit():
        food = FoodList(internal_user_id=current_user.id, restaurant=form.restaurant.data,
                        food_type=form.food_type.data)
        db.session.add(food)
        db.session.commit()

    return render_template("pages/food.html", title="Food", form=form)


@app.route("/setup/food")
@login_required(role="ADMIN SUPERUSER INTERN")
def setup_food():
    # the query below gets the username instead of the user.id
    sql_query = text("select food_list.id, food_list.food_type, food_list.restaurant, user.username "
                     "from food_list, user where (food_list.internal_user_id = user.id) ")
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    dict_resultsEdit = []

    for i in dict_results:
        i.update({"remove": "remove"})
        dict_resultsEdit.append(i)

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


@app.route("/food/delete/<int:food_id>", methods=['GET', 'POST'])
@login_required(role="SUPERUSER")
def delete_food(food_id):
    post = FoodList.query.get_or_404(food_id)

    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('food'))


'''
#########################################################################################################
# Dynamic Lookup Routes and Functions #
#########################################################################################################
'''


# display list of all lookup files in the static/lookup_files dir
@app.route("/lookup/manage", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def manage_files():
    # post method means we should expect a file to be included
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for("manage_files"))

        # assign object to variable
        file = request.files['file']

        # make sure the name isnt empty
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(url_for("manage_files"))

        # check if the file exists and that its a .csv file
        if file and (".csv" in file.filename):
            # save file to desired path
            filename = secure_filename(file.filename)
            # replace any spaces with underlines as this will cause some errors with the
            # dynamic table creation
            filename = filename.replace(" ", "_")

            file.save(os.path.join("./static/lookup_files/", filename))

            flash('File successfully uploaded', 'success')
            return redirect(url_for("manage_files"))

        # return error msg to user
        else:
            flash('Please upload file in csv format.')
            return redirect(url_for("manage_files"))

    return render_template("pages/lookup_manage.html", title="Lookup Manage")


# get the list of lookup files in the proper dir
@app.route("/setup/lookup_files", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER INTERN")
def lookup_list():
    file_list = file_finding("static/lookup_files/")
    # final pre stuff
    file_listFinal = {"data": file_list}
    return jsonify(file_listFinal)


# delete specified file
@app.route("/lookup/manage/<string:str_filename>", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def lookup_delete(str_filename):
    # get list of files to check if file exists
    file_list = file_finding("static/lookup_files/")

    for i in file_list:
        if (str_filename in i["filename"]):
            os.remove("./static/lookup_files/" + str_filename)
            flash(str_filename + " has been deleted successfully.", "success")
            return redirect(url_for('manage_files'))

    flash(str_filename + " does not exist.", "danger")
    return redirect(url_for('manage_files'))


# Renders the page for all the files in the lookup folder
@app.route("/lookup/pages", methods=['GET'])
@login_required(role="ADMIN SUPERUSER INTERN")
def lookup_pages():
    return render_template("pages/lookup_pages.html", title="Lookup Pages")


# gets the list of files and their headers
@app.route("/setup/lookup/list", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def lookup_list_setup():
    # get list of files in the desired dir
    file_list = file_finding("static/lookup_files/")

    file_listTemp = {}

    # loop through files and add the headers to the dict
    for i in file_list:
        temp = i.get('filename')
        file_listTemp.update({str(temp): lookup_helper(temp, "list")})

    # final pre stuff
    file_listFinal = {"data": file_listTemp}
    return jsonify(file_listFinal)


# gets the data for the requested data
@app.route("/setup/lookup/list/<string:str_filename>", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def lookup_list_setupHelper(str_filename):
    file_listTemp = {str(str_filename[:-4]): lookup_helper(str_filename, "data")}
    return jsonify(file_listTemp)


# helper function to reduce redundant code
def lookup_helper(str_filename, str_type):
    dict_results = {}
    # open the folder with utf8 significant encoding and ignore an errors when reading
    with open('./static/lookup_files/' + str_filename, mode="r", encoding="utf-8-sig", errors='ignore') as csv_file:
        reader = csv.DictReader(csv_file)

        # determine if we are getting just the headers or the entire dataset
        if (str_type == "list"):
            x = 0
            # get the headers to reduce data transfer(?)
            for k in reader.fieldnames:
                dict_results.update({x: str(k)})
                x = x + 1

        elif (str_type == "data"):
            # convert to dict format
            dict_results = [dict(row.items()) for row in reader]

    # return the results
    return dict_results


'''
#########################################################################################################
# Quote Routes and Functions #
#########################################################################################################
'''

'''
Quote Submission Route main
mainly hosts the form to submit or remove the quote
'''


@app.route("/quote", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def quote_sub():
    form = QuoteSub()

    # check if data is valid
    if form.validate_on_submit():
        # prep for commit
        quoteCommit = GeorgeQuotes(quote=form.quote.data)
        db.session.add(quoteCommit)
        db.session.commit()

    return render_template("pages/quote_main.html", title="Quote Submission", form=form)


'''
Quote Submission Data
Retrieves the data from the quotes table and returns them to the appropriate location
'''


@app.route("/quote_data")
@login_required(role="ADMIN SUPERUSER INTERN")
def quoteData():
    # the query below gets all rows from quotes table
    sql_query = text('select * from george_quotes')
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    dict_resultsEdit = []

    # add remove option to each row
    for i in dict_results:
        i.update({"remove": "remove"})
        dict_resultsEdit.append(i)

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_resultsEdit}
    return jsonify(dict_resultsTemp)


'''
Quote Submission remove
The following function allows a logged in admin to remove a quote based on id. 
Should only be accessed from the remove link in the quote main page
'''


@app.route("/quote/remove/<string:quote_id>", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def quote_sub_remove(quote_id):
    # query the table based on the passed in row
    quoteDel = GeorgeQuotes.query.get_or_404(quote_id)

    # delete row and commit changes
    db.session.delete(quoteDel)
    db.session.commit()

    # redirect back to quote page
    return redirect(url_for('quote_sub'))


'''
#########################################################################################################
# EDL Routes and Functions #
#########################################################################################################
'''

# testing api wrapping
'''
example curl to access stuff
curl  -d '{"key":"JPfot4-q8hsT0WoazAUo7w", "entry_string":"20.20.45.45", "comments":"api test", "direction_blocked":"inbound"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:5000/api/edl
'''


@app.route("/api/edl", methods=["POST"])
@require_appkey
def api_edl_sub():
    # check if the method is post and try to get the required data fields
    if request.method == 'POST':
        try:
            entry_string = request.json["entry_string"]
            try:
                comments = request.json["comments"]
            except:
                comments = ''
                pass
            dir_block_val = request.json["direction_blocked"]

            # get the api key and retrieve the user id associated with it
            user_key = request.json['key']
            api_results = api_table.query.filter_by(api_key=user_key).first()
            userid = api_results.internal_user_id

            # initialize the edl class obj and then exe the edl addition
            edl_stuff = EDL(entry_string, dir_block_val, comments, userid, "Blocked")
            edl_stuff.edl_sub()

            # return a standard success resp
            return Response("{'results': 'success'}\n", status=201, mimetype='application/json')
        except:
            # return an error code if some thing goes wrong
            # abort(Response("Missing key attribute data.\nAttributes: entry_string, comments (optional), status, direction_blocked\n", status=403))
            return Response(
                "Missing key attribute data.\nAttributes: entry_string, comments (optional), status, direction_blocked\n",
                status=403)


# this works but shouldnt really need to use this in an api case..... for now <.<
# still think this could be done better
@app.route("/api/edl/<string:action>/<string:edl_table>/<string:edl_entryid>", methods=["POST"])
@require_appkey
def api_edl_edit(action, edl_table, edl_entryid):
    if request.method == 'POST':
        try:
            entry_string = request.json["entry_string"]
            try:
                comments = request.json["comments"]
            except:
                comments = ''
                pass
            status_val = request.json["status"]
            dir_block_val = request.json["direction_blocked"]

            # get the api key and retrieve the user id associated with it
            user_key = request.json['key']
            api_results = api_table.query.filter_by(api_key=user_key).first()
            userid = api_results.internal_user_id

            # initialize the edl class obj and then exe the edl addition
            edl_stuff = EDL(entry_string, dir_block_val, comments, userid, status_val)
            flag_check = edl_stuff.edl_edit_update(action, edl_table, edl_entryid)

            if (flag_check):
                # return a standard success resp
                return Response("{'results': 'success'}\n", status=201, mimetype='application/json')

            else:
                # abort(400)
                return Response("Recieved EDL ID does not exist.\n", status=404)
        except:
            return Response(
                "Missing key attribute data.\nAttributes: entry_string, comments (optional), status, direction_blocked\n",
                status=404)

    # if we want to go the method route
    # elif request.method == "DELETE":
    #     try:
    #         #initialize the edl class obj and then exe the edl addition
    #         edl_stuff = EDL('', '', '', '', '')
    #         edl_stuff.edl_edit_update(action, edl_table, edl_entryid)

    #         #return a standard success resp
    #         return Response("{'results': 'success'}", status=201, mimetype='application/json')
    #     except:
    #         abort(400)


'''
EDL Submission Route main
Displays the main edl page
'''
@app.route("/edl", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER")
def edl_sub():
    form = EDL_Submission()

    if (form.validate_on_submit()):
        # set the vars
        user_input = form.user_input.data
        block_direction = form.block_direction.data
        comments = form.comments.data

        # initialize the edl class obj and then exe the edl addition
        edl_stuff = EDL(user_input, block_direction, comments, current_user.id, "Blocked")

        edl_stuff.edl_sub()

    return render_template("pages/edl_main.html", title="EDL Submission", form=form)

'''
EDL Submission Data
'''
@app.route("/edl_data")
@login_required(role="ADMIN SUPERUSER")
def edlData():
    edl_thighs = ['ip', 'url'] # I lol'd here
    Final_results = {}
    for i in edl_thighs:
        edl_grill = 'edl_' + i + '_list'
        edl_query = text(
            'select '+ edl_grill +'.id, '+ edl_grill +'.' + i + '_string, '+ edl_grill +'.date_blocked, '+ edl_grill +'.date_allowed, '+ edl_grill +'.status, '+ edl_grill +'.direction_block, '+ edl_grill +'.comments, user.username from '+ edl_grill +', user where ('+ edl_grill +'.internal_user_id = user.id)')

        # pass query to helper func to reduce redundancy
        Final_results.update({i: edl_query_helper(edl_query)})

    # return the data
    return jsonify(Final_results)


'''
Local helper function for the edl query
NOTE: could make this more generalized to work with the other functions, for another time
'''


def edl_query_helper(query_string):
    result = db.engine.execute(query_string)

    # this transforms the results var into a dict
    query_results = [dict(row.items()) for row in result]

    query_resultsTemp = []

    for i in query_results:
        i['date_allowed'] = convert_timeFormat(i['date_allowed'])
        i['date_blocked'] = convert_timeFormat(i['date_blocked'])

    # return the results
    return query_results


'''
EDL Edit update
'''
@app.route("/edl/<string:action>", methods=["POST"])
@login_required(role="ADMIN SUPERUSER")
def edl_edit_update(action):
    # get the current time
    now = datetime.now()
    if request.method == 'POST':
        # get the form values
        entry_string = request.form["entry_string"]
        edl_table = request.form["edl_table"]
        edl_entryid = request.form["edl_entryid"]
        try:
            comments = request.form["comments"]
        except:
            comments = ''
            pass
        status_val = request.form["status"]
        dir_block_val = request.form["direction_blocked"]

        # initialize the edl class obj and then exe the edl addition
        edl_stuff = EDL(entry_string, dir_block_val, comments, current_user.id, status_val)

        edl_stuff.edl_edit_update(action, edl_table, edl_entryid)

    # redirect back to edl page
    return redirect(url_for('edl_sub'))


'''
#################################################################################################################################
# Link Stuff #
#################################################################################################################################
'''
'''
Link Submission Route main
'''


@app.route("/links", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER")
def link_sub():
    form = Link_Submission()

    if (form.validate_on_submit()):
        # set the var
        url_text = form.url_text.data
        displayText = form.displayText.data
        category = form.category.data

        # takes care of a trailing / char causing the link to not fully work
        if (url_text[-1] == "/"):
            url_text = url_text[:-1]

        # prep for commit
        linkCommit = linkLists(url_link=url_text, display_text=displayText, category=category)
        db.session.add(linkCommit)
        db.session.commit()

    return render_template("pages/link_main.html", title="Link Submission", form=form)


'''
Link Submission Data
'''


@app.route("/link_data", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def linkData():
    sql_query = text('select * from link_list')
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    dict_resultsEdit = []

    # add remove option to each row
    for i in dict_results:
        i.update({"remove": "remove"})
        dict_resultsEdit.append(i)

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_resultsEdit}
    return jsonify(dict_resultsTemp)


'''
Link Submission remove
'''


@app.route("/link/remove/<string:link_id>", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def link_sub_remove(link_id):
    # query the table based on the passed in row
    linkDel = linkLists.query.get_or_404(link_id)

    # delete row and commit changes
    db.session.delete(linkDel)
    db.session.commit()

    return redirect(url_for('link_sub'))


'''
#################################################################################################################################
IP/URL Lookup 
#################################################################################################################################
'''


@app.route("/lookup/reputation", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER INTERN USER")
def lookup_main():
    form = LookupForm()
    output = []
    # only perform if the form has been submitted
    if (form.validate_on_submit()):
        # check for ip\url validation
        user_input = form.search_input.data
        original_input = user_input
        try:
            # first check if its an ip
            socket.inet_aton(user_input)
            valid_input = True
        except:
            try:
                # then check if the url is valid and can resolve to an ip
                user_input = socket.gethostbyname(user_input)
                valid_input = True
            except:
                # display an alert message stating the input is invalid
                valid_input = False
                pass

        if (valid_input == True):
            lookup = Lookup(user_input, user_input, original_input)

            talos = lookup.talos()
            abuseipdb = lookup.abuseipdb()
            virustotal = lookup.virustotal_run()

            output.extend((talos, abuseipdb, virustotal))
        else:
            flash("IP/URL is either invalid or does not exist.", "danger")

    return render_template("pages/lookup_main.html", title="IP/URL Lookup", form=form, output=output)


'''
#################################################################################################################################
Download Files..... and stuff
#################################################################################################################################
'''


@app.route("/downloads", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER USER")
def downloads():
    return render_template("pages/downloads.html", title="Downloads")


@app.route("/downloads/files", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER USER")
def downloads_files():
    file_list = file_finding("static/ipad_jamf_files/")
    # final pre stuff
    file_listFinal = {"data": file_list}
    return jsonify(file_listFinal)


# use this function to retreive the list of files approved for download
def file_finding(dir_val):
    # NOTE: when executing, the base path is /git_repo/cybsec_site/
    base_os_path = "./"
    file_list = []

    # for now this will be updated manually in the code
    dir_list = [dir_val]

    for i in dir_list:
        # loop through the files in the curr dir
        for k in os.listdir((base_os_path + i)):
            temp_path = base_os_path + i
            temp = {}
            # check if its a file or dir
            if (os.path.isfile(os.path.join(temp_path, k))):
                # below is suppose to be for linux
                # mod_time = stat.st_mtime
                mod_time = os.path.getmtime(str(i))  # for windows only
                mod_time = datetime.fromtimestamp(mod_time).strftime('%B %d, %Y %I:%M:%S %p')

                temp.update({"filename": k, "path": str(i), "modified": mod_time, "delete": str(k)})
                file_list.append(temp)

    return file_list


'''
#################################################################################################################################
Help Page
#################################################################################################################################
'''


@app.route("/help", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER INTERN")
def help_user():
    return render_template("pages/help_user.html", title="Help")


'''
#################################################################################################################################
LDAP Stuff
#################################################################################################################################
'''


@app.route("/ldap", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER USER INTERN")
def ldap_lookup():
    form = LDAPForm()
    results = {}
    resultsFinal = []
    if (form.validate_on_submit()):
        search_for = form.user_input.data
        type_input = form.type_input.data
        domain = type_input.lower()

        # set svc account creds
        svc_account = svc_config.svc_account
        password = svc_config.svc_ps

        # set attr list
        attr_list = [ "cn", "displayName", "userPrincipalName", "mail", "title", "department", "distinguishedName"]
        
        out = get_user(domain, svc_account, password, attr_list, search_for)

        # check the bool val of the flag
        if (not out):
            flash("Error: Search text does not exist", 'danger')

        else:
            # define the values we want to look for to build out the table
            attr_table = ['cn', 'displayName', 'company', 'department', 'title', 'mail', 'badPwdCount', 'pwdLastSet',
                          'lastLogonTimestamp', 'physicalDeliveryOfficeName', 'memberOf']

            # loop through results and match obj key with attr table then assign to value
            for obj in out:
                if (obj.key in attr_table):
                    results[obj.key] = out[obj.key].value

            # loop through attr table and check if the key exists
            for j in attr_table:
                if not (j in results.keys()):
                    results[j] = "null"

            # required for the ajax side of things... for some reason?
            resultsFinal = [results]

    return render_template("pages/ldap_lookup.html", title="LDAP lookup", form=form, output=resultsFinal)


'''
#################################################################################################################################
# DMCA Stuffffffffff #
#################################################################################################################################
'''

'''
DMCA Entry 
'''

@app.route("/setup/userlist", methods=['GET', 'POST'])
@login_required(role="ADMIN SUPERUSER INTERN")
def setup_userlist():
    sql_query = text('SELECT username FROM user WHERE role LIKE "%ADMIN%" OR role LIKE "%SUPERUSER%" OR role LIKE "%INTERN%"')
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


@app.route("/entry/update/<int:entry_id>", methods=["POST"])
@login_required(role="ADMIN SUPERUSER")
def post_update(entry_id):
    if request.method == 'POST':
        # get the form values
        offender_ip = request.form["off_ip"]
        offender_mac = request.form["off_mac"]
        case_id = request.form["case_id"]
        classification = request.form["classification"]
        evidence = request.form["evidence"]
        action = request.form["action"]

        # Init HomeHelper
        home_is_helped = HomeHelper(offender_ip, offender_mac, case_id, classification, evidence, current_user.id, action)
        home_is_helped.edit_entry(entry_id)

    # redirect back to home page
    return redirect(url_for('home'))


@app.route("/entry/<int:post_id>", methods=["POST", "GET"])
@login_required(role="USER ADMIN SUPERUSER INTERN")
def post(post_id):
    post = DmcaHistory.query.get(post_id)

    # check if post method was sent
    if request.method == "POST":
        # get the comment
        user_comment = request.form["user_comment"]

        # make sure something is there
        if user_comment:
            dmcaComment_update(post, user_comment)

    post = DmcaHistory.query.get(post_id)

    return render_template('pages/post.html', post=post)

def dmcaComment_update(dmca_obj, comment):
    now = datetime.now()
    now = convert_timeFormat(str(now))
    if not (dmca_obj.comments is None):
        dmca_obj.comments = dmca_obj.comments+'\n\n\n' + current_user.username+' at '+now+' commented:\n'+comment+'________________________________________________________________________________________________________________________'
    else:
        dmca_obj.comments = current_user.username+' at '+now+' commented:\n'+comment
    db.session.commit()

'''
DMCA Block Removal
'''

def dmcaUnblock_helper(dmca_obj, auto_comment):
    now = datetime.now()
    dmca_obj.date_closed = now
    dmca_obj.action = "UNBLOCKED"
    dmcaComment_update(dmca_obj, auto_comment)


@app.route("/block/remove/<int:post_id>", methods=["POST"])
@login_required(role="ADMIN SUPERUSER INTERN")
def block_submit_remove_id(post_id):
    evidence_input = request.form["evidence"]
    wlc_pass = request.form["wlc_pass"]
    auto_comment = "\nUser has been approved to be unblocked.\n"+evidence_input

    case = DmcaHistory.query.filter_by(id=post_id).first()
    in_dorm = case.offender_ip.startswith("10.31.")

    if in_dorm:
        dmcaUnblock_helper(case, auto_comment)
        email_prep("dmca_dorm_unblock", case.case_id, case.offender_ip, evidence_input)

        flash("Email has been sent to Boingo to unblock!", "success")
        return redirect(url_for("home"))
    else:
        pwned = DMCA("r", current_user.username, wlc_pass, case.offender_mac, "")
        devices = pwned.do_setup()
        pwned.reset()
        output = pwned.do_dmca(devices, case.offender_mac)

        if not output[0]["dmca"]["error"]:
            dmcaUnblock_helper(case, auto_comment)

    return render_template("results/block_results.html", title="Results", output=output)


'''
DMCA deletion 
'''


@app.route("/entry/<int:post_id>/delete", methods=['POST'])
@login_required(role="ADMIN SUPERUSER")
def delete_post(post_id):
    post = DmcaHistory.query.get_or_404(post_id)

    db.session.delete(post)
    db.session.commit()
    flash('Entry has been deleted!', 'success')
    return redirect(url_for('home'))


#parse the submitted dmca email
@app.route("/block/parse", methods=["GET", "POST"])
@login_required(role="ADMIN SUPERUSER INTERN")
def dmca_parse():
    now = datetime.now()
    form = DMCAParse()

    if form.validate_on_submit():
        actual_email = form.dmca_text.data
        email_attributes = ["ID", "TimeStamp", "IP_Address", "Port"]
        email_results = {}

        # loop through attributes and extract attributes
        for attr in email_attributes:
            matched = re.findall(rf"<{attr}>(.*)</{attr}>", actual_email)
            for match in matched:
                email_results[attr] = match

        # assign to values
        email_ip = email_results["IP_Address"]
        offender_port = email_results["Port"]
        offender_timestamp = email_results["TimeStamp"]

        # query splunk to get the possible ip associated with this event
        init_query = json.loads(query_splunk(email_ip, offender_port, offender_timestamp))

        # try/except to determine if anything was found
        try:
            offender_ip = init_query["result"]["src"]

            try:
                # these ips wont be able to be associated with the correct macs due to it being guest wireless
                if offender_ip.startswith("10.20") or offender_ip.startswith("10.21") or offender_ip.startswith("10.46"):
                    user_mac = format_mac(init_query["result"]["src_user"])

                    dmca_parse_helper(now, offender_ip, user_mac, email_results["ID"], actual_email, "PENDING")

                elif offender_ip.startswith("10.47"):
                    eduroam_query = json.loads(query_splunk(offender_ip, "na", offender_timestamp))

                    user_mac = format_mac(eduroam_query["result"]["src_mac"])

                    dmca_parse_helper(now, offender_ip, user_mac, email_results["ID"], actual_email, "PENDING")
                else:
                    dmca_parse_helper(now, offender_ip, "N/A", email_results["ID"], actual_email, "PENDING")
            except:
                dmca_parse_helper(now, offender_ip, "N/A", email_results["ID"], actual_email, "PENDING")
                pass
        except KeyError:
            flash("Disregard compliant. Results are inconclusive!", "danger")
            dmca_parse_helper(now, email_ip, "N/A", email_results["ID"], actual_email, "INCON")
            pass

        return redirect(url_for("home"))

    return render_template("pages/dmca_parse.html", form=form)


#just a helper function to help keep code clean~ish
def dmca_parse_helper(now, offender_ip, user_mac, email_results_id, actual_email, action):
    history = DmcaHistory(date_posted=now, offender_ip=offender_ip,
                        offender_mac=user_mac, action=action,
                        classification="DMCA", case_id=email_results_id,
                        evidence=actual_email, internal_user_id=current_user.id)
    db.session.add(history)
    db.session.commit()


# function to query splunk and for code cleanup
def query_splunk(offender_ip, offender_port, timestamp):
    # set up the variables and get the correct timespan 
    try:
        date_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
    except:
        date_time = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')

    epoch_time = int(date_time.timestamp())

    if date_time > datetime.now():
        epoch_time_now = date_time.now().timestamp()
    else:
        epoch_time_now = epoch_time - 10800

    if(offender_port == "na"):
        data = {
            'search': f'search index=its_syslog sourcetype="infoblox:dhcp" src_ip="{offender_ip}" earliest={epoch_time - 18000} latest={epoch_time_now} | table _time, src_ip, src_mac | rename src_ip as "Source IP", src_mac as "Source MAC" | head 1',
            'output_mode': 'json'
        }
    else:
        data = {
            'search': f'search index=its_network_sec_fw sourcetype=pan:traffic host="uk-pa7080-edge1-act-log.net.uky.edu" app="bittorrent" src_translated_ip="{offender_ip}" src_translated_port="{offender_port}" earliest={epoch_time - 18000} latest={epoch_time_now} '
                    '| where src_translated_port!=0 '
                    '| table _time, src_translated_ip, src_translated_port, src_user,  src, src_zone, src_port, dest, dest_location '
                    '| fillnull value=NULL src_user '
                    '| head 1',
            'output_mode': 'json'
        }
    # attack!
    response = requests.post('https://uky.splunkcloud.com:8089/services/search/jobs/export', data=data, verify=False,
                             auth=(svc_config.splunk_user, svc_config.splunk_ps))

    return response.text


'''
DMCA add block
'''


@app.route("/block/add")
@login_required(role="ADMIN SUPERUSER")
def block_page_add():
    return render_template("pages/block_add.html", title="Add")


'''
DMCA remove block
'''


@app.route("/block/remove")
@login_required(role="ADMIN SUPERUSER")
def block_page_remove():
    return render_template("pages/block_remove.html", title="Remove")


'''
DMCA add results
'''


@app.route("/block/<int:post_id>/result", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def block_submit_confirm(post_id):
    # get the info
    post = DmcaHistory.query.get(post_id)
    get_pass = request.form["wlc_pass"]

    in_dorm = post.offender_ip.startswith("10.31.")
    in_shawneetown = post.offender_ip.startswith("172.16.")

    # check how many times the mac addr has been blocked
    check_mac = DmcaHistory.query.filter_by(offender_mac=post.offender_mac).all()

    if not in_dorm and not in_shawneetown:
        # executes the actual dmca blocking
        pwned = DMCA("a", current_user.username, get_pass, post.offender_mac, "dmca")
        devices = pwned.do_setup()
        pwned.reset()
        output = pwned.do_dmca(devices, post.offender_mac)

        if output[0]["dmca"]["length"]:
            if "Shorten your WLC description" in output[0]["dmca"]["length"][0]:
                flash(output[0]["dmca"]["length"][0], "danger")
                return redirect(url_for("block_page_add"))

        if not output[0]["dmca"]["error"]:
            check = [{"output": len(check_mac)}]

            post.action = "BLOCKED"
            db.session.commit()

            return render_template("results/block_results.html", title="Results", output=output, check=check)

        return render_template("results/block_results.html", title="Results", output=output)
    elif in_dorm:
        email_prep("dmca_dorm", post.case_id, post.offender_ip, post.evidence)

        post.action = "BLOCKED"
        db.session.commit()

        flash("Email has been sent to Boingo to block!", "success")
        return redirect(url_for("home"))
    elif in_shawneetown:
        email_prep("dmca_shawneetown", post.case_id, post.offender_ip, post.evidence)

        post.action = "BLOCKED"
        db.session.commit()

        flash("Email has been sent to Josh to block!", "success")
        return redirect(url_for("home"))


@app.route("/block/add/result", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def block_submit_add():
    # get the info
    get_mac = request.form["mac"]
    get_mac = format_mac(get_mac)  # format the mac in the desired standard
    get_offender_ip = request.form["off_ip"]
    # get_classification = request.form["classification"]
    get_case_id = request.form["case_id"]
    evidence = request.form["evidence"]
    # get_description = request.form["desc"]
    now = datetime.now()  # get current time

    dmca_parse_helper(now, get_offender_ip, get_mac, get_case_id, evidence, "PENDING")

    return redirect(url_for("home"))


'''
DMCA remove results
'''


@app.route("/block/remove/result", methods=["POST"])
@login_required(role="ADMIN SUPERUSER")
def block_submit_remove():
    get_offender_ip = request.form["ip_address"]
    get_mac = request.form["mac"]
    get_mac = format_mac(get_mac)
    get_evidence = request.form["evidence"]
    get_pass = request.form["wlc_pass"]
    now = datetime.now()

    bad_mac = DmcaHistory.query.filter_by(offender_mac=get_mac).first()
    bad_ip = DmcaHistory.query.filter_by(offender_ip=get_offender_ip).first()

    # Dorms
    if bad_ip.offender_ip.startswith("10.31."):
        history = DmcaHistory(date_posted=now, offender_ip=bad_ip.offender_ip, action="UNBLOCKED",
                              classification=bad_ip.classification, case_id=bad_ip.case_id,
                              evidence=get_evidence, internal_user_id=current_user.id)
        db.session.add(history)
        db.session.commit()

        email_prep("dmca_dorm_unblock", bad_ip.case_id, bad_ip.offender_ip, get_evidence)

        flash("Email has been sent to Boingo to unblock!", "success")
        return redirect(url_for("home"))
    # Unblock on controllers
    else:
        pwned = DMCA("r", current_user.username, get_pass, get_mac, "")
        devices = pwned.do_setup()
        pwned.reset()
        output = pwned.do_dmca(devices, get_mac)

        if not output[0]["dmca"]["error"]:
            history = DmcaHistory(date_posted=now, offender_ip=bad_mac.offender_ip,
                                  offender_mac=get_mac, action="UNBLOCKED",
                                  classification=bad_mac.classification, case_id=bad_mac.case_id,
                                  evidence=get_evidence, internal_user_id=current_user.id)
            db.session.add(history)
            db.session.commit()

    return render_template("results/block_results.html", title="Results", output=output)


'''
#################################################################################################################################
# Other functions #
#################################################################################################################################
'''


# Mac addr Format - Formats passed in mac into preferred format of xx:xx:xx:xx:xx:xx
def format_mac(mac: str) -> str:
    mac = re.sub('[.:-]', '', mac).lower()  # remove delimiters and convert to lower case
    mac = ''.join(mac.split())  # remove whitespaces

    if not len(mac) == 12:
        return "N/A"

    if mac is None:
        mac = None
    # convert mac in canonical form (eg. 00:80:41:ae:fd:7e)
    mac = ":".join(["%s" % (mac[i:i + 2]) for i in range(0, 12, 2)])
    return mac


def send_email(reason, subject, content):
    if reason == "dmca_dorm":
        receivers = ["abuse@elauwit.com", "support@elauwitnetworks.com", "tjones@elauwit.com", "cybersecurity@uky.edu"]
        # receivers = ["chase@uky.edu"]

        msg = Message(subject,
                      recipients=receivers)
        msg.html = content
        mail.send(msg)
    elif reason == "pastebin":
        receivers = ["218help@uky.edu"]
        # receivers = ["chase@uky.edu"]

        msg = Message(subject,
                      recipients=receivers)
        msg.html = content
        mail.send(msg)
    elif reason == "dmca_shawnee":
        receivers = ["Joshua.Burke@charter.com", "matt.dillon@uky.edu", "cybersecurity@uky.edu"]
        # receivers = ["chase@uky.edu"]

        msg = Message(subject,
                      recipients=receivers)
        msg.html = content
        mail.send(msg)


# email prep purely for code cleanup
def email_prep(dest, case_id, ip_input, evidence):
    # determine which email to send
    if dest == "dmca_dorm":
        message = f"""
            Boingo Support,
            <br><br>
            This infringement tracks down to {ip_input} on the Boingo Network. Please block the user and direct them to the University of Kentucky's Customer Service Center (218-HELP) to resolve the issue.
            <br><br>
            Evidence of the DMCA is as listed: <pre>{evidence}</pre>
            <br>
            Thank you,
            <br>
            UK Cybersecurity, Data Privacy, and Policy
            <br><br>
            <em>{current_user.username} initiated this automated message. Please forward this email to <strong>cybersecurity@uky.edu</strong> with any questions/concerns you may have</em>
            """
    elif dest == "dmca_shawneetown":
        message = f"""
            Josh,
            <br><br>
            We received a DMCA complaint for the following:
            <br><br>
            IP: {ip_input}
            <br>
            Evidence: <pre>{evidence}</pre>
            <br>
            Thank you,
            <br>
            UK Cybersecurity, Data Privacy, and Policy
            <br><br>
            <em>{current_user.username} initiated this automated message. Please forward this email to <strong>cybersecurity@uky.edu</strong> with any questions/concerns you may have</em>
            """
        dest = "dmca_shawnee"
    elif dest == "dmca_dorm_unblock":
        message = f"""
            Boingo Support,
            <br><br>
            Please unblock the IP address: {ip_input}
            <br><br>
            Evidence of DMCA compliance: <pre>{evidence}</pre>
            <br>
            Thank you,
            <br>
            UK Cybersecurity, Data Privacy, and Policy
            <br><br>
            <em>{current_user.username} initiated this automated message. Please forward this email to <strong>cybersecurity@uky.edu</strong> with any questions/concerns you may have</em>
            """
        dest = "dmca_dorm"
    else:
        # return false and present an error
        return flash("Email route is not defined!", "danger")

    # otherwise call email function and return true
    send_email(dest, f"DMCA Case ID {case_id}", message)
    return True


# convert default datetime format from db to a 'pretty' version
# NOTE: known bug, when trying to sort by date, sorts in incorrect order
def convert_timeFormat(time_string):
    if (time_string):
        temp = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S.%f').strftime('%B %d, %Y %I:%M:%S %p')
        return temp


'''
#################################################################################################################################
# Import Testing #
#################################################################################################################################
'''


@app.route("/import/begin")
@login_required(role="ADMIN SUPERUSER")
def import_route():
    results = netmgr_import()
    if not results:
        flash("Search text does not exist", "danger")
            
    return redirect(url_for('home'))


'''
#################################################################################################################################
# Assign Users to API keys #
#################################################################################################################################
'''

@app.route("/api/user", methods=["POST", "GET"])
@login_required(role="ADMIN SUPERUSER")
def api_users():
    form = Api_UserForm()

    # check if data is valid
    if form.validate_on_submit():
        svc_user = form.user_input.data

        # check if svc is currently in db
        check_user = User.query.filter_by(username=svc_user).first()

        flag = True

        if (not check_user):
            # query ldap server
            try:
                svc_account = svc_config.svc_account
                password = svc_config.svc_ps
                temp = get_user("ad", svc_account, password, "cn", svc_user)

                if ('OU=ServiceAccounts' in temp['distinguishedName'].value):
                    user = User(username=svc_user, role="SVC_ACCT")

                else:
                    flash("Linkblue is not a Service Account!", "danger")
                    return render_template("pages/api_user.html", title="API Users", form=form)

                db.session.add(user)
                db.session.commit()

            except:
                flash("Linkblue does not exist!", "danger")
                flag = False

        # only create api key if flag is true
        if (flag == True):
            check_user = User.query.filter_by(username=svc_user).first()
            user_id = check_user.id
            add_apikey(user_id)

    return render_template("pages/api_user.html", title="API Users", form=form)


'''
API Data    -   gets the list of api keys currently tied to users
'''


@app.route("/setup/api")
@login_required(role="ADMIN SUPERUSER")
def setup_api():
    # the query below gets the username instead of the user.id
    sql_query = text("select api_table.*, user.username "
                     "from api_table, user where (api_table.internal_user_id = user.id) ")
    # execute
    result = db.engine.execute(sql_query)

    # this transforms the results var into a dict
    dict_results = [dict(row.items()) for row in result]
    dict_resultsEdit = []

    for i in dict_results:
        i.update({"remove": "remove"})
        dict_resultsEdit.append(i)

    # just assigning this to another dict just because I didnt want to search the solution :P
    dict_resultsTemp = {"data": dict_results}
    return jsonify(dict_resultsTemp)


def add_apikey(user_id):
    # create the api key via secrets lib
    # NOTE: we will just keep it 16 bytes
    super_secret = secrets.token_urlsafe(16)

    # add the api key to the db
    api_entry = api_table(internal_user_id=user_id, api_key=super_secret)
    db.session.add(api_entry)
    db.session.commit()


@app.route("/api/remove/<string:api_id>", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def api_remove(api_id):
    # query the table based on the passed in row
    api_results = api_table.query.get_or_404(api_id)

    # delete row and commit changes
    db.session.delete(api_results)
    db.session.commit()

    # redirect back to quote page
    return redirect(url_for('api_users'))




@app.route("/jsoc_test", methods=['GET', "POST"])
@login_required(role="ADMIN SUPERUSER")
def jsoc_test():

    jsoc_main()

@app.route("/api/splunk/test", methods=['GET', "POST"])
def splunk_test():
    if request.method == 'POST':
        wah = request
        x = 42
