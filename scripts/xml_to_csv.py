import xml.etree.ElementTree as ET
import requests
import pandas as pd
from datetime import datetime
import os
import svc_config

def get_jamf_xml():
    #perform a curl/wget to get the jamf data
    url = r"https://universityofkentucky.jamfcloud.com/JSSResource/advancedmobiledevicesearches/name/devices%20-%20student%20=%20yes"
    #this prob isnt the most secure way to do this buuuuuuuuuutttttt ohhhhhh well
    r = requests.get(url, auth=(svc_config.svc_jamf_acc, svc_config.svc_jamf_pwd))

    now = datetime.now()
    curr_date = now.strftime("%m-%d-%Y")
    
    os_dir = '/var/www/html/flask/git_repo/cybsec_site/static/ipad_jamf_files/'
    os_path = os_dir+"jamf_data_"+curr_date+".xml" #ex: ./edl_plain/inboundip_stringEDL.txt

    # open/overwrite the file with the new data
    if (os.path.exists(os_path)):
        os.remove(os_path)

    #encode to avoid some stupid issuessssssssssssssss
    with open(os_path, mode='w+', encoding='utf-8') as newfile:
        newfile.write(r.text)

    # change permissions
    os.chmod(os_path, 0o775)


def main():
    get_jamf_xml()
    now = datetime.now()
    curr_date = now.strftime("%m-%d-%Y")

    #creates the object(i think)
    tree = ET.parse("/var/www/html/flask/git_repo/cybsec_site/static/ipad_jamf_files/jamf_data_"+curr_date+".xml")
    #gets the tree of the root
    root = tree.getroot()

    result = []
    #def the columns we want
    df_cols = ["Display_Name", "Class_of", "Username", "Serial_Number", "Wi_Fi_MAC_Address", "Full_Name"]
    #get all mobile_device tags
    for device in root.iter("mobile_device"):
        temp = {}
        #iterate through the cols and try to find them
        #dont care if they are empty or not
        for i in df_cols:
            #put in dict format
            temp.update({i : device.find(i).text})
        #append to temp
        result.append(temp)

    #create and append data to dataframe
    df = pd.DataFrame(result, columns=df_cols)


    #overwrite/create file in csv format w/o the index
    df.to_csv("/var/www/html/flask/git_repo/cybsec_site/static/ipad_jamf_files/convert_"+curr_date+".csv", index=False)
main()