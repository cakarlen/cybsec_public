import socket
import re
import os

from cybsec import db, app

from cybsec.models import User, DmcaHistory, GeorgeQuotes, FoodList, edl_IPList, edl_URLList, linkLists, Pastebin, api_table

from sqlalchemy import text
from datetime import datetime


class EDL:
    # Initialize the class with arguments
    def __init__(self, user_input, block_direction, comments, userid, status_val):
        self.user_input = user_input
        self.block_direction = block_direction
        self.comments = comments
        self.userid = userid
        self.status_val = status_val

        '''
        #stuff not to define
            date blocked/allowed
        '''

    '''
    EDL Submission Route main
    Displays the main edl page
    '''
    def edl_sub(self):
        now = datetime.now()

        # default value
        ip_update = True

        #use regex to seperate input by space or comma (this will result in empty entries but is taken care of later)
        dict_input = re.findall('[^\\s|,\\s]*', self.user_input)

        # loop through the array of ips/urls and continuously add them to the table
        for i in dict_input:
            if (len(i) > 0):
                table_id = ""
                # check if the curr input is a valid ip or not
                try:
                    socket.inet_aton(i)
                    ipcheck = edl_IPList.query.filter_by(ip_string=i).first()
                    # check if the current ip/url is currently in the list
                    if (not (ipcheck)):
                        edlCommit = edl_IPList(internal_user_id=self.userid, date_blocked=now,
                                                ip_string=str(i), status="Blocked", direction_block=self.block_direction,
                                                comments=self.comments)
                        table_id = "ip"

                except:
                    # trim possible https:// and other similar iterations
                    temp = i[:7]
                    if (f'https://' in i):
                        i = i[8:]
                    elif (f'http://' in i):
                        i = i[7:]
                    # check if the current ip/url is currently in the list
                    urlcheck = edl_URLList.query.filter_by(url_string=i).first()
                    if (not (urlcheck)):
                        edlCommit = edl_URLList(internal_user_id=self.userid, date_blocked=now,
                                                url_string=str(i), status="Blocked", direction_block=self.block_direction,
                                                comments=self.comments)
                        table_id = "url"

                # commit the act if the table_id var is not empty
                if (table_id != ""):
                    # do the deed
                    db.session.add(edlCommit)
                    db.session.commit()

                    # call a function to update the edl txt file
                    edlPage_creation("edl_"+table_id+"_list", table_id+"_string")

        return True

    '''
    EDL Edit update
    '''
    def edl_edit_update(self, action, edl_table, edl_entryid):
        #get the current time
        now = datetime.now()

        #set for later
        queryTable = "edl_"+edl_table+"_list"
        queryAttr = edl_table+"_string"

        #query the correct db
        if(edl_table == "ip"):
            edl_query = edl_IPList.query.filter_by(id=edl_entryid).first()

        else:
            edl_query = edl_URLList.query.filter_by(id=edl_entryid).first()

        #check if it exists
        if(not edl_query):
            return False

        if(action == "remove"):
            #delete row
            db.session.delete(edl_query)

        elif(action == "update"):            
            #either unpdate to blocked or unblocked
            edl_query.status = str(self.status_val)
            if(self.status_val == "Blocked"):
                #using the type None is the same as NULL for sqlite and is used to empty out the date_allowed column
                edl_query.date_allowed = None
                edl_query.date_blocked = now
            else:
                edl_query.date_allowed = now

            #update the rest of the entry
            if(edl_table == "ip"):
                edl_query.ip_string = self.user_input
            else:
                edl_query.url_string = self.user_input
            edl_query.direction_block = self.block_direction
            edl_query.comments = self.comments

        #do the deed
        db.session.commit()

        #update the edl text files
        edlPage_creation(queryTable, queryAttr)                        

        #redirect back to edl page
        return True




'''
EDL Page Creation
Purpose: to query the appropriate table and overwrite the current one in the static dir
'''

def edlPage_creation(edlTable, edlString):
    # use for loop for page creation
    direction_list = ["inbound", "outbound"]
    for i in direction_list:
        query_string = text(
            'select {0}.{1} from {0} where ({0}.status = "Blocked" AND (({0}.direction_block = "{2}") OR ({0}.direction_block = "both" )))'.format(
                edlTable, edlString, i))
        result = db.engine.execute(query_string)
        # this transforms the results var into a dict
        query_results = [dict(row.items()) for row in result]

        # cause im too lazy to fix the above
        listTemp = []
        for j in query_results:
            for key, val in j.items():
                if (key in edlString):
                    listTemp.append(val)

        #save path for latter use
        #NOTE: The cwd is: /var/www/html/flask/git_repo/cybsec_site/
        os_dir = './static/edl_plain/'
        os_path = os_dir+i+edlString+'EDL.txt' #ex: ./edl_plain/inboundip_stringEDL.txt

        # open/overwrite the file with the new data
        if (os.path.exists(os_path)):
            os.remove(os_path)

        with open(os_path, mode='w+', encoding='utf-8') as newfile:
            newfile.write('\n'.join(listTemp))

        # change permissions
        os.chmod(os_path, 0o775)

