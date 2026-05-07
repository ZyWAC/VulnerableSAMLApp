import os
import sys
import json
import time
import random
from shutil import copyfile

from flask import (Flask, request, render_template, redirect, session,
                   make_response)

from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils


## Import all of the complaint functions functions
from jsonparse import jsonComplaintWriter
from jsonparse import jsonComplaintReader
from jsonparse import jsonSingleComplaintDelete

## Import functions for the 'settings' page
from jsonparse import jsonEditor
from jsonparse import jsonReader

## Import functions for the admin panel / user management
from jsonparse import jsonUsersReader
from jsonparse import jsonUserAdd
from jsonparse import jsonUserUpdate
from jsonparse import jsonUserDelete
from jsonparse import jsonUserGet

## Import functions for the staff panel / group management
from jsonparse import jsonGroupsReader
from jsonparse import jsonGroupAdd
from jsonparse import jsonGroupDelete
from jsonparse import jsonGroupGetPermission

import logging
import requests
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'onelogindemopytoolkit'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')


def get_valid_groups():
    """Read valid group names from users.json and custom groups to validate SAML memberOf attributes."""
    try:
        users = jsonUsersReader()
        groups = set(u.get('memberOf', '') for u in users if u.get('memberOf'))
        # Also include custom groups from groups.json
        custom_groups = jsonGroupsReader()
        groups.update(custom_groups.keys())
        # Always include built-in groups
        groups.update({'users', 'staffs', 'administrators', 'PlatformConfiguration'})
        return groups
    except Exception as e:
        logger.error(f'Failed to read valid groups: {e}')
        return {'users', 'staffs', 'administrators', 'PlatformConfiguration'}


def validate_saml_attributes(attributes):
    """Validate SAML response attributes against application settings.
    
    Returns (is_valid: bool, error_message: str or None)
    """
    if not attributes:
        return False, 'No attributes found in SAML response'
    
    # Check if memberOf attribute exists
    member_of = attributes.get('memberOf', [])
    if not member_of:
        logger.warning('SAML response missing memberOf attribute')
        return False, 'SAML response is missing required memberOf attribute'
    
    # Validate memberOf value against known valid groups
    valid_groups = get_valid_groups()
    group_value = member_of[0] if member_of else None
    
    if group_value and group_value not in valid_groups:
        logger.warning(
            f'Invalid group membership in SAML response: "{group_value}". '
            f'Valid groups are: {valid_groups}'
        )
        return False, (
            f'Invalid group membership: "{group_value}". '
            f'This group does not exist in the application. '
            f'Valid groups: {", ".join(sorted(valid_groups))}'
        )
    
    # Check required attributes
    required_attrs = ['username']
    for attr_name in required_attrs:
        if attr_name not in attributes or not attributes[attr_name]:
            logger.warning(f'SAML response missing required attribute: {attr_name}')
            return False, f'SAML response is missing required attribute: {attr_name}'
    
    return True, None


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query_string
    }


@app.before_request
def redirect_localhost():
    """Redirect localhost requests to 127.0.0.1 for consistent SAML handling."""
    url_data = urlparse(request.url)
    if url_data.hostname == 'localhost':
        new_url = request.url.replace('://localhost', '://127.0.0.1', 1)
        return redirect(new_url, code=301)


@app.context_processor
def inject_user_role():
    """Inject the resolved user role into all templates for navbar rendering."""
    return {'user_role': get_user_role()}


@app.route('/', methods=['GET', 'POST'])
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in request.args:
        return redirect(auth.login())
    elif 'sso2' in request.args:
        return_to = '%sprofile/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return redirect(auth.logout(name_id=name_id, session_index=session_index))
    elif 'acs' in request.args:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        
        if len(errors) > 0:
            logger.error(f'SAML Response errors: {errors}')
            logger.error(f'Error reason: {auth.get_last_error_reason()}')
        
        if len(errors) == 0:
            saml_attributes = auth.get_attributes()
            logger.info(f'SAML attributes received: {saml_attributes}')
            
            # Validate SAML attributes (group membership, required fields)
            attrs_valid, validation_error = validate_saml_attributes(saml_attributes)
            
            if not attrs_valid:
                logger.warning(f'SAML attribute validation failed: {validation_error}')
                errors.append('invalid_attributes')
                return render_template(
                    'index.html',
                    errors=['invalid_attributes'],
                    error_detail=validation_error,
                    not_auth_warn=True,
                    success_slo=False,
                    attributes=False,
                    paint_logout=False
                )
            
            session['samlUserdata'] = saml_attributes
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()

            # JIT provisioning: auto-create user in SP database if not present
            try:
                username = saml_attributes.get('username', [None])[0]
                if username:
                    # Case-insensitive lookup to avoid duplicates
                    existing = jsonUserGet(username) or jsonUserGet(username.lower())
                    if not existing:
                        new_user = {
                            'username': username,
                            'password': '',
                            'firstName': saml_attributes.get('firstName', [''])[0],
                            'lastName': saml_attributes.get('lastName', [''])[0],
                            'emailAddress': saml_attributes.get('emailAddress', [''])[0],
                            'memberOf': saml_attributes.get('memberOf', ['users'])[0],
                        }
                        jsonUserAdd(new_user)
                        logger.info(f'JIT provisioned new user: {username}')
            except Exception as e:
                logger.warning(f'JIT provisioning failed for user: {e}')

            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
    elif 'sls' in request.args:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template(
        'index.html',
        errors=errors,
        error_detail=auth.get_last_error_reason() if errors else None,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout
    )

#### Page loads the users profile information
@app.route('/profile/')
def profile():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
    return render_template('profile.html', paint_logout=paint_logout,
                           attributes=attributes)

#### Application meta data for idp
@app.route('/metadata/')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp

#### Form to Adjust the security levels of the application
@app.route('/settings/')
def settingsPage():
    paint_logout = False
    attributes = False

    #### if the user account isn't a member of the 'PlatformConfiguration' group redirect to the root page
    #### this prevents direct references to the settings page
    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
            print(attributes)
            for attr in attributes:
                if attr[0] == 'memberOf':
                    if attr[1][0] == 'PlatformConfiguration':
                        currentSettings = jsonReader()

                        return render_template('settings.html', paint_logout=paint_logout,
                                attributes=attributes,currentSettings=currentSettings)
    
    return redirect('/')

#### Post action to Adjust the security levels of the application
@app.route('/update', methods=['POST'])
def update():
    attributes = False
    #### check group membership before processing post data if not in the 'PlatformConfiguration' group
    #### redirect to the root page. This prevents direct POST requests to adjust the security of the app
    if 'samlUserdata' in session:
        attributes = session['samlUserdata'].items()
        if len(session['samlUserdata']) > 0:
            for attr in attributes:
                if attr[0] == 'memberOf':
                    if attr[1][0] == 'PlatformConfiguration':
                        wantMessagesSigned = 'wantMessagesSigned' in request.form
                        wantAssertionsSigned = 'wantAssertionsSigned' in request.form
                        signMetadata = 'signMetadata' in request.form
                        validMessage = 'validMessage' in request.form
                        validAssertion = 'validAssertion' in request.form
                        cve201711427 = 'cve-2017-11427' in request.form
                        adminPanelEnabled = 'adminPanelEnabled' in request.form
                        xswVulnerable = 'xswVulnerable' in request.form
                        xxeVulnerable = 'xxeVulnerable' in request.form
                        xsltVulnerable = 'xsltVulnerable' in request.form
                        cve202241912 = 'cve-2022-41912' in request.form
                        cve202523369 = 'cve-2025-23369' in request.form
                        cve202525291 = 'cve-2025-25291' in request.form
                        cve202525292 = 'cve-2025-25292' in request.form
        
                        jsonEditor(wantMessagesSigned,wantAssertionsSigned,signMetadata,validMessage,validAssertion,cve201711427,adminPanelEnabled,xswVulnerable,xxeVulnerable,xsltVulnerable,cve202241912,cve202523369,cve202525291,cve202525292)

                        return redirect('/settings/')
    return redirect('/')

#### Static page that displays helpful information about SAML, terminiology, and resources.
@app.route('/learn/')
def learnPage():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
	    paint_logout = True

    return render_template('learn.html', paint_logout=paint_logout, attributes=attributes)

#### Page that rendors the complaints
@app.route('/complaints/')
def complaints():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()
    complaintDic = jsonComplaintReader()
    return render_template('complaints.html', paint_logout=paint_logout,attributes=attributes,dictionary=complaintDic)

#### Form page for taking in complaint details
@app.route('/filecomplaint/')
def filecomplaint():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
	    paint_logout = True

    return render_template('filecomplaint.html', paint_logout=paint_logout, attributes=attributes)

#### Post route that processes the results from the complaint form.
@app.route('/newcomplaint', methods=['POST'])
def newcomplaint():
    complaint = request.form['complaintDescription']
    severity = request.form['severity']
    victim = request.form['victim']
    
    #Generate a 'unique' event id
    complaintID = int(round(time.time() * 1000))
    complaintID = str(complaintID)
    complaintID = ''.join(random.sample(complaintID,len(complaintID)))

    jsonData = {'id':str(complaintID),'description':str(complaint),'complainer':str(victim),'severity':str(severity)}
    jsonComplaintWriter(jsonData)
    return redirect('/complaints/')

### Restore all of the complaints back to the original
@app.route('/restorecomplaints/')
def restoreComplaints():
    if 'samlUserdata' in session:
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
            for attr in attributes:
                if attr[0] == 'memberOf':
                    if attr[1][0] == 'PlatformConfiguration':
                        copyfile('complaints/complaints.json.bak', 'complaints/complaints.json')
            
    return redirect('/complaints/')

### Delete single complaint
@app.route('/deletecomplaint')
def deletecomplaint():
    complaintID = request.args.get('id')
    jsonSingleComplaintDelete(complaintID)
    return redirect('/complaints')


#### ---- Admin Panel / User Management ---- ####

def get_user_role():
    """Returns the current user's role: 'instructor', 'admin', 'staffs', or None."""
    if 'samlUserdata' in session and len(session['samlUserdata']) > 0:
        attrs = session['samlUserdata']
        member_of = attrs.get('memberOf', [])
        if member_of:
            group = member_of[0]
            if group == 'PlatformConfiguration':
                return 'instructor'
            elif group == 'administrators':
                return 'admin'
            elif group == 'staffs':
                return 'staffs'
            else:
                # Check if it's a custom group with a permission level
                perm = jsonGroupGetPermission(group)
                if perm == 'staffs':
                    return 'staffs'
    return None


def is_admin_panel_enabled():
    """Check if the admin panel is enabled (instruction mode) via settings."""
    try:
        settings = jsonReader()
        return settings.get('adminPanelEnabled', 'False') == 'True'
    except Exception:
        return False


def can_manage_user(role, target_user):
    """Check if the current role can manage the target user.
    instructor: can manage everyone
    admin: can manage everyone EXCEPT PlatformConfiguration (instructor) users
    """
    if role == 'instructor':
        return True
    elif role == 'admin':
        return target_user.get('memberOf', '') != 'PlatformConfiguration'
    return False


@app.route('/admin/')
def adminPanel():
    paint_logout = False
    attributes = False

    role = get_user_role()
    if role not in ('instructor', 'admin'):
        return redirect('/')

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    # Check if instruction mode (admin panel) is enabled
    admin_enabled = is_admin_panel_enabled()

    # If admin panel is NOT enabled and user is 'admin' (not instructor),
    # show restricted view
    if role == 'admin' and not admin_enabled:
        return render_template('admin.html', paint_logout=paint_logout,
                               attributes=attributes, users=[], role=role,
                               admin_restricted=True)

    users = jsonUsersReader()
    # Filter: admin cannot see/manage instructor (PlatformConfiguration) users
    if role == 'admin':
        visible_users = [u for u in users if u.get('memberOf') != 'PlatformConfiguration']
    else:
        visible_users = users

    custom_groups = jsonGroupsReader()

    return render_template('admin.html', paint_logout=paint_logout,
                           attributes=attributes, users=visible_users, role=role,
                           admin_restricted=False, custom_groups=custom_groups)


@app.route('/admin/add', methods=['POST'])
def adminAddUser():
    role = get_user_role()
    if role not in ('instructor', 'admin'):
        return redirect('/')

    # Block admin users when instruction mode is off
    if role == 'admin' and not is_admin_panel_enabled():
        return redirect('/admin/')

    new_member_of = request.form.get('memberOf', 'users')
    # admin cannot create PlatformConfiguration users
    if role == 'admin' and new_member_of == 'PlatformConfiguration':
        return redirect('/admin/')

    newUser = {
        'username': request.form.get('username', '').strip(),
        'password': request.form.get('password', ''),
        'firstName': request.form.get('firstName', '').strip(),
        'lastName': request.form.get('lastName', '').strip(),
        'emailAddress': request.form.get('emailAddress', '').strip(),
        'memberOf': new_member_of
    }

    if not newUser['username']:
        return redirect('/admin/')

    jsonUserAdd(newUser)

    # Sync group with IDP so next SAML assertion reflects the new group
    try:
        requests.post('http://idp/api/update_group', json={
            'username': newUser['username'],
            'group': new_member_of,
            'action': 'set',
            'source': 'admin'
        }, timeout=5)
    except Exception as e:
        logger.warning(f'Failed to sync new user group with IDP for {newUser["username"]}: {e}')

    return redirect('/admin/')


@app.route('/admin/edit/<username>', methods=['GET'])
def adminEditUserPage(username):
    paint_logout = False
    attributes = False

    role = get_user_role()
    if role not in ('instructor', 'admin'):
        return redirect('/')

    # Block admin users when instruction mode is off
    if role == 'admin' and not is_admin_panel_enabled():
        return redirect('/admin/')

    user = jsonUserGet(username)
    if not user:
        return redirect('/admin/')

    # admin cannot edit instructor users
    if not can_manage_user(role, user):
        return redirect('/admin/')

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    custom_groups = jsonGroupsReader()

    return render_template('admin_edit.html', paint_logout=paint_logout,
                           attributes=attributes, user=user, role=role,
                           custom_groups=custom_groups)


@app.route('/admin/edit/<username>', methods=['POST'])
def adminEditUser(username):
    role = get_user_role()
    if role not in ('instructor', 'admin'):
        return redirect('/')

    # Block admin users when instruction mode is off
    if role == 'admin' and not is_admin_panel_enabled():
        return redirect('/admin/')

    user = jsonUserGet(username)
    if not user:
        return redirect('/admin/')

    if not can_manage_user(role, user):
        return redirect('/admin/')

    new_member_of = request.form.get('memberOf', user.get('memberOf', 'users'))
    # admin cannot promote to PlatformConfiguration
    if role == 'admin' and new_member_of == 'PlatformConfiguration':
        new_member_of = user.get('memberOf', 'users')

    updatedData = {
        'firstName': request.form.get('firstName', user['firstName']).strip(),
        'lastName': request.form.get('lastName', user['lastName']).strip(),
        'emailAddress': request.form.get('emailAddress', user['emailAddress']).strip(),
        'memberOf': new_member_of
    }

    # Only update password if a new one was provided
    new_password = request.form.get('password', '')
    if new_password:
        updatedData['password'] = new_password

    jsonUserUpdate(username, updatedData)

    # Sync group with IDP so next SAML assertion reflects the updated group
    try:
        requests.post('http://idp/api/update_group', json={
            'username': username,
            'group': new_member_of,
            'action': 'set',
            'source': 'admin'
        }, timeout=5)
    except Exception as e:
        logger.warning(f'Failed to sync group change with IDP for {username}: {e}')

    return redirect('/admin/')


@app.route('/admin/delete/<username>', methods=['POST'])
def adminDeleteUser(username):
    role = get_user_role()
    if role not in ('instructor', 'admin'):
        return redirect('/')

    # Block admin users when instruction mode is off
    if role == 'admin' and not is_admin_panel_enabled():
        return redirect('/admin/')

    user = jsonUserGet(username)
    if not user:
        return redirect('/admin/')

    if not can_manage_user(role, user):
        return redirect('/admin/')

    jsonUserDelete(username)

    # Remove group override from IDP
    try:
        requests.post('http://idp/api/update_group', json={
            'username': username,
            'action': 'remove',
            'source': 'admin'
        }, timeout=5)
    except Exception as e:
        logger.warning(f'Failed to sync user deletion with IDP for {username}: {e}')

    return redirect('/admin/')


@app.route('/admin/restore', methods=['POST'])
def adminRestoreUsers():
    """Restore users to original state from backup."""
    role = get_user_role()
    if role != 'instructor':
        return redirect('/admin/')

    copyfile('users/users.json.bak', 'users/users.json')

    # Clear all group overrides on IDP
    try:
        requests.post('http://idp/api/update_group', json={
            'username': '__clear_all__',
            'action': 'clear_all',
            'source': 'admin'
        }, timeout=5)
    except Exception as e:
        logger.warning(f'Failed to clear IDP group overrides on restore: {e}')

    return redirect('/admin/')


# ============================================================
# Staff Panel Routes (HR-like group management)
# ============================================================

@app.route('/staff/')
def staffPanel():
    paint_logout = False
    attributes = False

    role = get_user_role()
    if role not in ('instructor', 'admin', 'staffs'):
        return redirect('/')

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    users = jsonUsersReader()
    # Staff can only see/manage users NOT in administrators or PlatformConfiguration
    visible_users = [u for u in users if u.get('memberOf') not in ('administrators', 'PlatformConfiguration')]

    custom_groups = jsonGroupsReader()
    # Build list of assignable groups (built-in non-admin + custom)
    assignable_groups = ['users', 'staffs'] + list(custom_groups.keys())

    return render_template('staff.html', paint_logout=paint_logout,
                           attributes=attributes, users=visible_users,
                           custom_groups=custom_groups,
                           assignable_groups=assignable_groups,
                           role=role)


@app.route('/staff/groups/add', methods=['POST'])
def staffAddGroup():
    role = get_user_role()
    if role not in ('instructor', 'admin', 'staffs'):
        return redirect('/')

    group_name = request.form.get('group_name', '').strip()
    permission_level = request.form.get('permission_level', 'users')

    if not group_name:
        return redirect('/staff/')

    # Block reserved group names
    reserved = {'administrators', 'PlatformConfiguration', 'users', 'staffs'}
    if group_name in reserved:
        return redirect('/staff/')

    if permission_level not in ('staffs', 'users'):
        permission_level = 'users'

    jsonGroupAdd(group_name, permission_level)
    return redirect('/staff/')


@app.route('/staff/groups/delete/<group_name>', methods=['POST'])
def staffDeleteGroup(group_name):
    role = get_user_role()
    if role not in ('instructor', 'admin', 'staffs'):
        return redirect('/')

    # Move any users in this group back to 'users'
    all_users = jsonUsersReader()
    for u in all_users:
        if u.get('memberOf') == group_name:
            jsonUserUpdate(u['username'], {'memberOf': 'users'})
            # Sync with IDP
            try:
                requests.post('http://idp/api/update_group', json={
                    'username': u['username'], 'group': 'users', 'action': 'set'
                }, timeout=5)
            except Exception as e:
                logger.warning(f'Failed to sync group deletion with IDP for {u["username"]}: {e}')

    jsonGroupDelete(group_name)
    return redirect('/staff/')


@app.route('/staff/user/<username>/group', methods=['POST'])
def staffUpdateUserGroup(username):
    role = get_user_role()
    if role not in ('instructor', 'admin', 'staffs'):
        return redirect('/')

    new_group = request.form.get('group', '').strip()
    if not new_group:
        return redirect('/staff/')

    # Cannot assign to admin/instructor groups
    if new_group in ('administrators', 'PlatformConfiguration'):
        return redirect('/staff/')

    user = jsonUserGet(username)
    if not user:
        return redirect('/staff/')

    # Staff cannot modify admin/instructor users
    if user.get('memberOf') in ('administrators', 'PlatformConfiguration'):
        return redirect('/staff/')

    # Validate the target group exists (built-in or custom)
    custom_groups = jsonGroupsReader()
    valid_targets = {'users', 'staffs'} | set(custom_groups.keys())
    if new_group not in valid_targets:
        return redirect('/staff/')

    # Update SP user database
    jsonUserUpdate(username, {'memberOf': new_group})

    # Sync with IDP so next SAML assertion reflects the new group
    try:
        requests.post('http://idp/api/update_group', json={
            'username': username,
            'group': new_group,
            'action': 'set'
        }, timeout=5)
    except Exception as e:
        logger.warning(f'Failed to sync group change with IDP for {username}: {e}')

    return redirect('/staff/')


@app.route('/staff/groups/restore', methods=['POST'])
def staffRestoreGroups():
    """Restore custom groups to original (empty) state from backup."""
    role = get_user_role()
    if role not in ('instructor', 'staffs'):
        return redirect('/staff/')

    # Reset any users in custom groups back to 'users'
    custom_groups = jsonGroupsReader()
    all_users = jsonUsersReader()
    for u in all_users:
        if u.get('memberOf') in custom_groups:
            jsonUserUpdate(u['username'], {'memberOf': 'users'})
            try:
                requests.post('http://idp/api/update_group', json={
                    'username': u['username'], 'group': 'users', 'action': 'set'
                }, timeout=5)
            except Exception as e:
                logger.warning(f'Failed to sync group restore with IDP for {u["username"]}: {e}')

    copyfile('groups/groups.json.bak', 'groups/groups.json')
    return redirect('/staff/')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
