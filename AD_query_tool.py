import os
import ldap
import csv
import pandas as pd
import datetime
import dateutil.relativedelta

LDAP_SERVER = 'ldap://172.20.1.216:389'
BASE_DN = 'DC=lab, DC=visiblerisk, DC=com'
LDAP_LOGIN = 'Administrator'
LDAP_PASS = 'Nhwk2iISxJuOZQa43IDch0J8z0hqB5jY'
SEARCH_OBJECT = '(&(objectClass=user)(objectCategory=person))'
SEARCH_ATTR = ['userAccountControl', 'lastLogon', 'PwdLastSet', 'memberOf']
CSV_PATH = os.path.join('.', 'AD_output.csv')  # path and file name for AD query results dataset  

def active_directory_conn(LDAP_SERVER, LDAP_LOGIN, LDAP_PASS):
    conn = ldap.initialize(LDAP_SERVER)
    conn.simple_bind_s(LDAP_LOGIN, LDAP_PASS) 
    return(conn)

def search_active_directory(BASE_DN, search_object, search_attr, connection):
    results = connection.search_s(BASE_DN, ldap.SCOPE_SUBTREE, search_object , search_attr)
    connection.unbind()
    return(results[:-4]) # cutting out irrelevant data rows 

def results_to_csv(path, active_directory_output):
    with open(path, 'w') as csv_file:  
        writer = csv.writer(csv_file)
        header = ['CN', 'GroupsMembership', 'UserAccountControl', 'LastLogon', 'LastPasswordSet'] 
        writer.writerow(header)
        for i in active_directory_output:
            cn = i[0]
            member_of = i[0],i[1].get('memberOf')
            user_account_control = int(i[1].get('userAccountControl')[0])
            last_logon = int(i[1].get('lastLogon')[0])
            pwd_last_set = int(i[1].get('pwdLastSet')[0])
            writer.writerow([cn, member_of ,user_account_control, last_logon, pwd_last_set])

# This function used as reference datetime for calculating delta between datetimes
def current_date_time():
    current_ts = datetime.datetime.now()
    current_date_time = current_ts.replace(microsecond=0)
    return(current_date_time)

# This function converts the 18-digit Active Directory timestamp to human readable datetime
def to_date_time(timestamp):
    date_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
    return(date_time.replace(microsecond=0))

def df_including_password_age():
    df = pd.read_csv(CSV_PATH)
    password_age_list = []
    for timestamp in df['LastPasswordSet']:
        if timestamp != 0:
            delta = current_date_time() - to_date_time(timestamp)
            password_age_list.append(delta.days)
        else:
            password_age_list.append(0)
    df['PasswordAge'] = password_age_list
    return(df)
    
def enabled_users(df):    
    df_enabled_users = df.loc[df['UserAccountControl'] & 2 == 0] 
    return(df_enabled_users)

def enabled_users_amount():    
    df = pd.DataFrame(df_including_password_age())    
    enabled_users_amount = enabled_users(df)['CN'].count()
    return(enabled_users_amount)

def enabled_inactive_users():
    df = pd.DataFrame(df_including_password_age())
    df_enabled_users = enabled_users(df)
    last_month_datetime = (current_date_time() + dateutil.relativedelta.relativedelta(months=-1))
    enabled_inactive_users_count = 0
    for timestamp in df_enabled_users['LastLogon']:
        if timestamp != 0:
            last_logon_datetime = to_date_time(timestamp) 
            if last_logon_datetime <= last_month_datetime:
                enabled_inactive_users_count += 1
        else:
            enabled_inactive_users_count += 1  
    return(enabled_inactive_users_count)   

# When PASSWD_NOTREQD flag is set, no password is required
def enabled_accounts_without_password():   
    df = pd.DataFrame(df_including_password_age())    
    df_enabled_accounts_without_password = df.loc[df['UserAccountControl'] & 0x0020 == 1] 
    df_enabled_accounts_without_password_amount = df_enabled_accounts_without_password['CN'].count()
    return(df_enabled_accounts_without_password_amount)

def enabled_domain_admins():   
    df = pd.DataFrame(df_including_password_age())
    df_enabled_users = enabled_users(df)
    search_list = ['Domain Admins', 'Administrator', 'Enterprise Admins']
    df_domain_admins = df_enabled_users.loc[df_enabled_users['GroupsMembership'].str.contains('|'.join(search_list))]
    df_domain_admins_amount = df_domain_admins['CN'].count()
    return(df_domain_admins)

def enabled_domain_admins_avg_password_age():
    df_enabled_domain_admins = enabled_domain_admins()
    avg_password_age = df_enabled_domain_admins['PasswordAge'].mean()
    return(int(avg_password_age))

def enabled_domain_admins_amount():   
    df_domain_admins = enabled_domain_admins()
    enabled_domain_admins_amount = df_domain_admins['CN'].count()
    return(enabled_domain_admins_amount)

# When SMARTCARD_REQUIRED flag is set, it forces the user to log on by using a smart card
def enabled_admins_card_req():   
    df_domain_admins = enabled_domain_admins()
    admins_card_req = df_domain_admins.loc[df_domain_admins['UserAccountControl'] & 0x40000 == 1]
    admins_card_req_amount = admins_card_req['CN'].count()
    return(admins_card_req_amount)

# When NOT_DELEGATED flag is set, the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation
def enabled_admins_account_not_delegated():   
    df_domain_admins = enabled_domain_admins()
    admins_non_delegated = df_domain_admins.loc[df_domain_admins['UserAccountControl'] & 0x100000 == 1]
    admins_non_delegated_amount = admins_non_delegated['CN'].count()
    return(admins_non_delegated_amount)

def main():
    connection = active_directory_conn(LDAP_SERVER, LDAP_LOGIN, LDAP_PASS)   
    active_directory_output = search_active_directory(BASE_DN, SEARCH_OBJECT, SEARCH_ATTR, connection)
    results_to_csv(CSV_PATH, active_directory_output) 
    print('\nAmount of enabled domain admins:', enabled_domain_admins_amount())
    print('\nAvarege password age of enabled domain admins:',enabled_domain_admins_avg_password_age(), 'days')
    print('\nAmount of enabled domain admins using card authentication:', enabled_admins_card_req())
    print('\nAmount of enabled domain admins with non delegated accounts:', enabled_admins_account_not_delegated())
    print('\nAmount of enabled accounts without password:', enabled_accounts_without_password())
    print('\nAmount of enabled domain users :', enabled_users_amount())
    print('\nAmount of enabled inactive domain users:', enabled_inactive_users(), '\n* Inactive users are users that did not logon for more than one month')
  
if __name__ == '__main__':
    main()

