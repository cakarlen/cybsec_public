import socket
import re
import ldap3
import os
import svc_config


def get_groupMembers(groups):
    users = []
    groups_dict = {}

    server = ldap3.Server('gc.ad.uky.edu')
    connection = ldap3.Connection(server, user=svc_config.svc_account, password=svc_config.svc_ps)
    connection.bind()

    # Verify search_base is correct depending on each group (aka, add elif statement)
    for group in groups:
        connection.search(
            search_base=f'CN={group},OU=Cybersecurity,OU=Groups,OU=IT,DC=ad,DC=uky,DC=edu',
            search_filter='(objectClass=group)',
            search_scope='SUBTREE',
            attributes=['member']
        )
        # Shouldn't have to change this below
        for entry in connection.entries:
            for member in entry.member.values:
                connection.search(
                    search_base='DC=ad,DC=uky,DC=edu',
                    search_filter=f'(distinguishedName={member})',
                    attributes=[
                        'sAMAccountName'
                    ]
                )

                users += connection.entries[0].sAMAccountName.values

        users = list(set(users))
        groups_dict[group] = users

    return groups_dict

def main():
    #get the ldap members by group
    admins = ["gITSecurity", "GG_Cis-SecurityTeamHigh", "GG_Cis-SecurityTeamLow", "GG_CyberSecurityGroupAdmins",
                        "GG_ITSSec", "gITSecAdmin"]
    interns = ["GG_CyberSecurityInterns", "GG_CyberSecurityStudentEmp"]

    groups_blah = {"ADMIN": admins, "INTERN": interns}

    os_dir = './static/ldap_roles/'

    #loop through the groups and query ldap based on them
    for key, val in groups_blah.items():
        #get the member list
        user_list = get_groupMembers(val)
        temp_list =[]

        for i, j in user_list.items():
            temp_list.extend(j)

        temp_list = list(set(temp_list))

        os_path = os_dir + key+ ".txt"

        # open/overwrite the file with the new data
        if (os.path.exists(os_path)):
            os.remove(os_path)
        try:
            os.makedirs(os_dir)
        except FileExistsError:
            # directory already exists
            pass

        with open(os_path, mode='w+', encoding='utf-8') as newfile:
            newfile.write('\n'.join(temp_list))

        # change permissions
        os.chmod(os_path, 0o775)
main()