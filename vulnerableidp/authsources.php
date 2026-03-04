<?php

$config = array(

    // This is a authentication source which handles admin authentication.
    'admin' => array(
        // The default is to use core:AdminPassword, but it can be replaced with
        // any authentication source.

        'core:AdminPassword',
    ),


    // An authentication source which can authenticate against both SAML 2.0
    // and Shibboleth 1.3 IdPs.
    'default-sp' => array(
        'saml:SP',

        // The entity ID of this SP.
        // Can be NULL/unset, in which case an entity ID is generated based on the metadata URL.
        'entityID' => null,

        // The entity ID of the IdP this should SP should contact.
        // Can be NULL/unset, in which case the user will be shown a list of available IdPs.
        'idp' => null,

        // The URL to the discovery service.
        // Can be NULL/unset, in which case a builtin discovery service will be used.
        'discoURL' => null,

        /*
         * WARNING: SHA-1 is disallowed starting January the 1st, 2014.
         *
         * Uncomment the following option to start using SHA-256 for your signatures.
         * Currently, SimpleSAMLphp defaults to SHA-1, which has been deprecated since
         * 2011, and will be disallowed by NIST as of 2014. Please refer to the following
         * document for more information:
         *
         * http://csrc.nist.gov/publications/nistpubs/800-131A/sp800-131A.pdf
         *
         * If you are uncertain about identity providers supporting SHA-256 or other
         * algorithms of the SHA-2 family, you can configure it individually in the
         * IdP-remote metadata set for those that support it. Once you are certain that
         * all your configured IdPs support SHA-2, you can safely remove the configuration
         * options in the IdP-remote metadata set and uncomment the following option.
         *
         * Please refer to the hosted SP configuration reference for more information.
          */
        //'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

        /*
         * The attributes parameter must contain an array of desired attributes by the SP.
         * The attributes can be expressed as an array of names or as an associative array
         * in the form of 'friendlyName' => 'name'. This feature requires 'name' to be set.
         * The metadata will then be created as follows:
         * <md:RequestedAttribute FriendlyName="friendlyName" Name="name" />
         */
        /*'name' => array(
             'en' => 'A service',
             'no' => 'En tjeneste',
          ),

          'attributes' => array(
            'attrname' => 'urn:oid:x.x.x.x',
        ),*/
        /*'attributes.required' => array (
            'urn:oid:x.x.x.x',
        ),*/
    ),


    /*
    'example-sql' => array(
        'sqlauth:SQL',
        'dsn' => 'mysql:host=localhost;port=5432;dbname=vds',
        'username' => 'root',
        'password' => 'yogibear',
        'query' => 'SELECT username, memberof FROM users WHERE username = :username AND AES_DECRYPT(password,"yogibear") = :password',
    ),*/


    /*
    'example-static' => array(
        'exampleauth:Static',
        'uid' => array('testuser'),
        'eduPersonAffiliation' => array('member', 'employee'),
        'cn' => array('Test User'),
    ),*/



    'jelly-parks' => array(
        'exampleauth:UserPass',

        // Give the user an option to save their username for future login attempts
        // And when enabled, what should the default be, to save the username or not
        //'remember.username.enabled' => FALSE,
        //'remember.username.checked' => FALSE,


        'yogi:bear' => array(
            'memberOf' => array('users'),
            'emailAddress' => array('yogi@jellystonep.com'),
            'firstName' => array('Yogi'),
            'lastName' => array('Bear'),
            'username' => array('yogi'),
        ),
        'admin:this-is-the-administrator-pasword-oh-no-is-that-a-typo-in-password' => array(
            'memberOf' => array('administrators'),
            'emailAddress' => array('admin@jellystonep.com'),
            'firstName' => array('Ranger'),
            'lastName' => array('Smith'),
            'username' => array('admin'),
        ),
        'cindy:$Up3rS3cr3tEmpl0y33P@ssw0rd' => array(
            'memberOf' => array('staffs'),
            'emailAddress' => array('cindy@jellystonep.com'),
            'firstName' => array('Cindy'),
            'lastName' => array('Bear'),
            'username' => array('cindy'),
        ),
        'instructor:G0od-LuckGu3ssingThisButHeyItCouldHappenRight?' => array(
            'memberOf' => array('PlatformConfiguration'),
            'emailAddress' => array('instructor@jellystonep.com'),
            'firstName' => array('Instructor'),
            'lastName' => array('Instructor'),
            'username' => array('Instructor'),
        ),
    ),
);

/*
 * Dynamically load registered users from JSON file.
 * These users are created via the /register page.
 */
$registeredUsersFile = '/var/simplesamlphp/data/registered_users.json';
if (file_exists($registeredUsersFile)) {
    $registeredUsers = json_decode(file_get_contents($registeredUsersFile), true);
    if (is_array($registeredUsers)) {
        foreach ($registeredUsers as $user) {
            if (!empty($user['username']) && !empty($user['password'])) {
                $key = $user['username'] . ':' . $user['password'];
                $config['jelly-parks'][$key] = array(
                    'memberOf' => array($user['memberOf'] ?? 'users'),
                    'emailAddress' => array($user['emailAddress'] ?? ''),
                    'firstName' => array($user['firstName'] ?? ''),
                    'lastName' => array($user['lastName'] ?? ''),
                    'username' => array($user['username']),
                );
            }
        }
    }
}

/*
 * Apply group overrides from the staff management panel.
 * When a staffs user reassigns a user to a custom group via the SP,
 * the SP calls the IDP API to write an override here.
 */
$overridesFile = '/var/simplesamlphp/data/group_overrides.json';
if (file_exists($overridesFile)) {
    $overrides = json_decode(file_get_contents($overridesFile), true);
    if (is_array($overrides)) {
        foreach ($config['jelly-parks'] as $key => &$value) {
            if (is_array($value) && isset($value['username'])) {
                $username = $value['username'][0];
                if (isset($overrides[$username])) {
                    $value['memberOf'] = array($overrides[$username]);
                }
            }
        }
        unset($value);
    }
}