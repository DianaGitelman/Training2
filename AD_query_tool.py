
import os
import ldap
import csv
import pandas as pd
import datetime
import dateutil.relativedelta


def active_directory_conn(ldap_server, ldap_login, ldap_pass):
    conn = ldap.initialize(ldap_server)
    conn.simple_bind_s(ldap_login, ldap_pass) 
    return(conn)

def search_active_directory(base_dn, search_object,  search_attr, connection):
    results = connection.search_s(base_dn, ldap.SCOPE_SUBTREE, search_object , search_attr)
    connection.unbind()
    return(results[:-4]) # cutting out irrelevant data rows 

def results_to_csv(path, active_directory_query):
    with open(path, 'w') as csv_file:  
        writer = csv.writer(csv_file)
        header = ['CN', 'GroupsMembership', 'UserAccountControl', 'LastLogon', 'LastPasswordSet'] 
        writer.writerow(header)
        for i in active_directory_query:
            cn = i[0]
            member_of = i[0],i[1].get('memberOf')
            user_account_control = int(i[1].get('userAccountControl')[0])
            last_logon = int(i[1].get('lastLogon')[0])
            pwd_last_set = int(i[1].get('pwdLastSet')[0])
            writer.writerow([cn, member_of ,user_account_control, last_logon, pwd_last_set])

def enabled_users(df):    
    enabled_users = df.loc[df['UserAccountControl'] & 2 == 0]
    return(enabled_users)

def enabled_users_amount():    
    df = pd.read_csv(csv_path)
    enabled_users_amount = enabled_users(df)['CN'].count()
    return(enabled_users_amount)

def current_date_time():
    current_ts = datetime.datetime.now()
    current_date_time = current_ts.replace(microsecond=0)
    return(current_date_time)

def to_date_time(timestamp):
    date_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
    return(date_time.replace(microsecond=0))

def password_age():
    df = pd.read_csv(csv_path)
    password_age_list = []
    for timestamp in df['LastPasswordSet']:
        if timestamp != 0:
            delta = current_date_time() - to_date_time(timestamp)
            password_age_list.append(delta.days)
        elif timestamp == 0:
            password_age_list.append(0)
    df['PasswordAge'] = password_age_list
    return(df)

def enabled_domain_admins_avg_password_age():
    df_incl_password_age = password_age()
    search_list = ['Domain Admins', 'Administrator']
    df_domain_admins = df_incl_password_age.loc[df_incl_password_age['GroupsMembership'].str.contains('|'.join(search_list))]
    df_enabled_domain_admins = enabled_users(df_domain_admins)
    avg_password_age = df_enabled_domain_admins['PasswordAge'].mean()
    return(int(avg_password_age))

def enabled_inactive_users():
    df = pd.read_csv(csv_path)
    df_enabled_users = enabled_users(df)
    last_month_datetime = (current_date_time() + dateutil.relativedelta.relativedelta(months=-1))
    enabled_inactive_users_count = 0
    for timestamp in df_enabled_users['LastLogon']:
        if timestamp != 0:
            last_logon_datetime = to_date_time(timestamp) 
            if last_logon_datetime <= last_month_datetime:
                enabled_inactive_users_count += 1
        elif timestamp == 0:
            enabled_inactive_users_count += 1  
    return(enabled_inactive_users_count)        

def main():
    connection = active_directory_conn('ldap://172.20.1.216:389', 'Administrator', 'Nhwk2iISxJuOZQa43IDch0J8z0hqB5jY')   
    active_directory_query = search_active_directory('DC=lab, DC=visiblerisk, DC=com', '(&(objectClass=user)(objectCategory=person))', ['userAccountControl', 'lastLogon', 'pwdLastSet', 'memberOf'], connection)
    results_to_csv(csv_path, active_directory_query) 
    print('\nAmount of enabled domain users :', enabled_users_amount(), '\n')
    password_age() 
    print('\nAvarege password age of enabled domain admins:',enabled_domain_admins_avg_password_age(), 'days\n')
    print('\nAmount of enabled inactive domain users:', enabled_inactive_users(), '\n* Inactive users are users that did not logon for more than one month')
    
csv_path = os.path.join('.', 'AD_output.csv')  # path and file name for AD query results dataset  

      
if __name__ == '__main__':
    main()

