import csv
import codecs
import io
import random
import json
import time


#### Update the settings stored in the settings file.
#### This is the file that controls the security levels for the application
def jsonEditor(wantMessagesSigned,wantAssertionsSigned,signMetadata,validMessage,validAssertion,cve201711427,adminPanelEnabled=False,xswVulnerable=False):

    filename = 'saml/advanced_settings.json'
    with open(filename) as data_file:
        data_loaded = json.load(data_file)
        data_file.close()

    with open(filename) as data_file:
        data_loaded = json.load(data_file)
        data_loaded['security']['wantMessagesSigned'] = wantMessagesSigned
        data_loaded['security']['wantAssertionsSigned'] = wantAssertionsSigned
        data_loaded['security']['signMetadata'] = signMetadata
        data_loaded['security']['wantValidMessageSignature'] = validMessage
        data_loaded['security']['wantValidAssertionsSignature'] = validAssertion
        data_loaded['security']['cve-2017-11427'] = cve201711427
        data_loaded['security']['adminPanelEnabled'] = adminPanelEnabled
        data_loaded['security']['xswVulnerable'] = xswVulnerable
        print(data_loaded['security']['wantMessagesSigned'])
    data_file.close()

    with open(filename, 'w') as file:
        json.dump(data_loaded, file, indent=2)
    data_file.close()

    with open(filename) as data_file:
        data_loaded = json.load(data_file)
        data_file.close()

#### Read in the current settings and display them on the page
def jsonReader():
    filename = 'saml/advanced_settings.json'

    with open(filename) as data_file:
        data_loaded = json.load(data_file)
        wantMessagesSigned = data_loaded['security']['wantMessagesSigned']
        wantAssertionsSigned = data_loaded['security']['wantAssertionsSigned']
        signMetadata = data_loaded['security']['signMetadata']
        validMessage = data_loaded['security']['wantValidMessageSignature']
        validAssertion = data_loaded['security']['wantValidAssertionsSignature']
        cve201711427 = data_loaded['security']['cve-2017-11427']
        print(str(wantMessagesSigned))
    data_file.close()
	
    adminPanelEnabled = data_loaded['security'].get('adminPanelEnabled', False)
    xswVulnerable = data_loaded['security'].get('xswVulnerable', False)
    settingValues = {'wantMessagesSigned':str(wantMessagesSigned),'wantAssertionsSigned':str(wantAssertionsSigned),'signMetadata':str(signMetadata),'validMessage':str(validMessage),'validAssertion':str(validAssertion),'cve-2017-11427':str(cve201711427),'adminPanelEnabled':str(adminPanelEnabled),'xswVulnerable':str(xswVulnerable)}
    return settingValues

#### ---- Everything below this is responsible for the Admin Panel / User Management ---- ####

USERS_FILE = 'users/users.json'
GROUPS_FILE = 'groups/groups.json'


#### ---- Custom Group Management (Staff Panel) ---- ####

def jsonGroupsReader():
    """Read custom groups from groups.json"""
    try:
        with open(GROUPS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('custom_groups', {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def jsonGroupsWriter(custom_groups):
    """Write custom groups to groups.json"""
    with open(GROUPS_FILE, 'w') as f:
        json.dump({'custom_groups': custom_groups}, f, indent=2)

def jsonGroupAdd(group_name, permission_level):
    """Add a custom group. Returns True on success, False if already exists or protected."""
    protected = ['users', 'staffs', 'administrators', 'PlatformConfiguration']
    if group_name in protected:
        return False
    groups = jsonGroupsReader()
    if group_name in groups:
        return False
    groups[group_name] = {'permission_level': permission_level}
    jsonGroupsWriter(groups)
    return True

def jsonGroupDelete(group_name):
    """Delete a custom group. Returns True on success."""
    groups = jsonGroupsReader()
    if group_name in groups:
        del groups[group_name]
        jsonGroupsWriter(groups)
        return True
    return False

def jsonGroupGetPermission(group_name):
    """Get the effective permission level for a group name.
    Built-in groups return themselves; custom groups return their permission_level."""
    built_in = {
        'users': 'users',
        'staffs': 'staffs',
        'administrators': 'administrators',
        'PlatformConfiguration': 'PlatformConfiguration'
    }
    if group_name in built_in:
        return built_in[group_name]
    groups = jsonGroupsReader()
    if group_name in groups:
        return groups[group_name].get('permission_level', 'users')
    return 'users'

def jsonUsersReader():
    """Read all users from the users JSON file"""
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def jsonUsersWriter(users):
    """Write full user list to the users JSON file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def jsonUserAdd(newUser):
    """Add a new user. Returns True on success, False if username already exists."""
    users = jsonUsersReader()
    for u in users:
        if u['username'] == newUser['username']:
            return False
    users.append(newUser)
    jsonUsersWriter(users)
    return True

def jsonUserUpdate(username, updatedData):
    """Update an existing user by username. Returns True on success, False if not found."""
    users = jsonUsersReader()
    for i, u in enumerate(users):
        if u['username'] == username:
            users[i].update(updatedData)
            jsonUsersWriter(users)
            return True
    return False

def jsonUserDelete(username):
    """Delete a user by username. Returns True on success, False if not found."""
    users = jsonUsersReader()
    original_len = len(users)
    users = [u for u in users if u['username'] != username]
    if len(users) < original_len:
        jsonUsersWriter(users)
        return True
    return False

def jsonUserGet(username):
    """Get a single user by username. Returns dict or None."""
    users = jsonUsersReader()
    for u in users:
        if u['username'] == username:
            return u
    return None


#### ---- Everything below this is responsibile for the Complaints page and associated functionality ---- ####

#### Porting from CSV to JSON for greater flexibility.....glen might have been right, this one time
#### Read in all of the current complaints
def jsonComplaintReader():
    complaintFilename = 'complaints/complaints.json'
    with open(complaintFilename,'r') as complaint_file:
        data = json.load(complaint_file)
        return data

#### Write a new complaint to the json db file
def jsonComplaintWriter(newComplaint):
    complaintFilename = 'complaints/complaints.json'

    #read in the entire file stick it into a variable
    with open(complaintFilename,'r') as complaint_file:
        data = json.load(complaint_file)
    complaint_file.close()

    data.append(newComplaint)
    stringBlob = json.dumps(data)
    with open(complaintFilename, 'w') as complaint_file:
        complaint_file.write(stringBlob)

#### Delete 1 entry based on the 'id' number
def jsonSingleComplaintDelete(complaintID):
    complaintFilename = 'complaints/complaints.json'
    
    #read in the entire file stick it into a variable
    with open(complaintFilename,'r') as complaint_file:
        data = json.load(complaint_file)
    complaint_file.close()

    for entry in data:
        if entry['id'] == complaintID:
            data.remove(entry)
    
    stringBlob = json.dumps(data)
    with open(complaintFilename, 'w') as complaint_file:
        complaint_file.write(stringBlob)