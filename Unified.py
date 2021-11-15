#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov 14 12:30:49 2021

@author: DianaG
"""

import ldap
import csv
import pandas as pd
import datetime
import dateutil.relativedelta

# **** Part 1/2 ****

ldap_server = 'ldap://172.20.1.216:389'
base_dn = 'DC=lab, DC=visiblerisk, DC=com'
ldap_login = 'Administrator'
ldap_pass = 'Nhwk2iISxJuOZQa43IDch0J8z0hqB5jY'
search_object = '(&(objectClass=user)(objectCategory=person))'
search_attr = ['userAccountControl', 'lastLogon', 'PwdLastSet', 'memberOf']


conn = ldap.initialize(ldap_server)
conn.set_option(ldap.OPT_REFERRALS, 0)           
conn.simple_bind_s(ldap_login, ldap_pass)
result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_object , search_attr)
conn.unbind()

print(result[:-4])

with open('/Users/DianaG/Documents/Learning/Python/AD_out.csv', 'w') as f:  
    writer = csv.writer(f)
    header = ['CN', 'GroupsMembership', 'UserAccountControl', 'LastLogon', 'LastPasswordSet'] 
    writer.writerow(header)
    for i in result[:-4]:
        user_account_control = int(i[1].get('userAccountControl')[0])
        last_logon = int(i[1].get('lastLogon')[0])
        pwd_last_set = int(i[1].get('pwdLastSet')[0])
        writer.writerow([i[0],i[1].get('memberOf'),user_account_control, last_logon, pwd_last_set])


# **** Part 2/2 ****

df = pd.read_csv('/Users/DianaG/Documents/Learning/Python/AD_out.csv')
print(df.info() , '\n\n')

print('Unique flags of UserAccountControl:' , df.UserAccountControl.unique(), ':') 

### UserAccountControl flags meaning
for i in df.UserAccountControl.unique():
    if i == 66048:
        print(i, ':', 'Enabled Account, Password Doesn’t Expire')
    elif i == 66082:
        print(i, ':', 'Disabled Account, Password Doesn’t Expire & Not Required')
    elif i == 514:
        print(i, ':', 'Disabled Account')
    elif i == 512:
        print(i, ':', 'Enabled Normal Account')
    elif i ==546:
        print(i, ':', 'Disabled Account, Password Not Required')
    elif i == 2080:
        print(i, ':', 'Interdomain Trust Account, Password Not Required', '\n\n')  
    else:
        raise Warning('UserAccountControl contains undefined flag!!!', i, '\n\n')

### Enabled domain users  
EnabledUsers = df.loc[df['UserAccountControl'].isin([66048, 2080, 512])] 
print('Count of enabled domain users :', EnabledUsers['CN'].count(), '\n')  

# Date of reference - today:
Current_Date = datetime.date.today()

### Average passwords age of enabled domain admin in days 
PasswordAge = []
for l in df.LastPasswordSet:
    if l != 0:  
        LastPasswordSetTS = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=l/10000000)
        LastPasswordSetDate = LastPasswordSetTS.date()
#        print(l , LastPasswordSetDate)
        Timedelta = Current_Date - LastPasswordSetDate
        PasswordAge.append(Timedelta.days)
    elif l == 0:
        PasswordAge.append(0)
df['PasswordAge'] = PasswordAge
#print('Password age in days:\n' , df['PasswordAge'], '\n')

#print (df)

AvgPassAge = df.loc[(df['UserAccountControl'].isin([66048, 2080, 512]) & (df['GroupsMembership'].str.contains('CN=Domain Admins')))]['PasswordAge'].mean()
print ('Avg Pass age of enabled domain admin users:' , AvgPassAge, '\n')

### Amount of enabled inactive domain users. Inactive users: users that didn't log on in the past month + users that never loged on
LastLogonDate = []
for t in df.LastLogon:
    if t != 0:
        LastLogonTS = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=t/10000000) 
        LastLogonD = LastLogonTS.date()
        LastLogonDate.append(LastLogonD)
#        print(t , LastLogonD)
    elif t == 0:
        LastLogonDate.append(None)
df['LastLogonDate'] = LastLogonDate      
#print('Last Logon Date :\n' , df['LastLogonDate'], '\n')

df.to_csv('/Users/DianaG/Documents/Learning/Python/Analyzer.csv', index=False)

LastMonth = (Current_Date + dateutil.relativedelta.relativedelta(months=-1))
print('Last month date:', LastMonth, '\n')

InactiveUsers = (df.loc[(df['LastLogonDate'] <= LastMonth) | pd.isnull(df["LastLogonDate"])])
print ('InactiveUsers:\n', InactiveUsers)

InactiveUsers.to_csv('/Users/DianaG/Documents/Learning/Python/InactiveUsers.csv', index=False)
df1 = pd.read_csv('/Users/DianaG/Documents/Learning/Python/InactiveUsers.csv')
print(df1.info() , '\n\n')

InactiveEnabledUsers = df1.loc[df['UserAccountControl'].isin([66048, 2080, 512])] 
print('Count of Inactive Enabled domain users :', EnabledUsers['CN'].count(), '\n') 
