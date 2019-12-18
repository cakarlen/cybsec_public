import socket
import re
import ldap3
import os
import requests
import csv
import io

from cybsec import db, app

from cybsec.models import User

from sqlalchemy import text
from datetime import datetime

import pandas as pd
import numpy as np
import svc_config

# query splunk to get the latest results of the jsoc table and return the results
def query_splunk():
    # set up the variables
    data = {
        'search': 'search index=its_network_sec_fw | table src_ip | head 10',
        'output_mode': 'csv'
    }
    # attack!
    response = requests.post('https://uky.splunkcloud.com:8089/services/search/jobs/export', data=data, verify=False,
                             auth=(svc_config.splunk_user, svc_config.splunk_ps))

    return response


def jsoc_add(jsoc_df):
    # loop through the dataframe and commit them to the db
    for index, row in jsoc_df.iterrows():
        new_entry = jsoc_table(status="NEW", date_occured=row["_time"], source=row['Source'], src_ip=row['Source_IP'],
                               category=row['Category'], severity=row['Severity'], action=row['Action'],
                               ipam_loc=row['IPAM Location'], threat_content=row['Specific Threat/Content'],
                               reported_userid=row['User ID'], reported_mac=row['Source MAC'],
                               total=row['Category Count'])

        db.session.add(new_entry)
        db.session.commit()


def jsoc_main():
    data_stuff = query_splunk()
    data_data_data = data_stuff.content.decode('utf8')

    df = pd.read_csv(io.StringIO(data_data_data))
    print(df.head())

    # jsoc_add(df)
