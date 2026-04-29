# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Response class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

SAML Response class of OneLogin's Python Toolkit.

"""

import re
import logging
import urllib.request
from base64 import b64decode
from copy import deepcopy
from defusedxml.lxml import tostring, fromstring
from lxml import etree as raw_etree
from xml.dom.minidom import Document

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils, return_false_on_exception
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError

logger = logging.getLogger(__name__)

# Domain whitelist for OOB attacks (XXE / XSLT)
ALLOWED_OOB_DOMAIN = '.oastify.com'


class OastifyOnlyResolver(raw_etree.Resolver):
    """Custom XML resolver that only allows requests to *.oastify.com domains.
    All other external entity / DTD resolution is blocked."""

    def resolve(self, system_url, public_id, context):
        if system_url:
            # Normalize: treat bare hostnames without scheme
            url = system_url.strip()
            hostname = url
            if '://' in url:
                from urllib.parse import urlparse
                hostname = urlparse(url).hostname or ''
            else:
                # Bare domain like "xxx.oastify.com" or path-like
                hostname = url.split('/')[0]

            if hostname.endswith(ALLOWED_OOB_DOMAIN):
                fetch_url = url if '://' in url else 'http://' + url
                try:
                    req = urllib.request.Request(
                        fetch_url,
                        headers={'User-Agent': 'VulnerableSAMLSP/1.0'}
                    )
                    data = urllib.request.urlopen(req, timeout=5).read()
                    logger.warning('[XXE] OOB request to allowed domain: %s', fetch_url)
                    return self.resolve_string(data, context)
                except Exception as e:
                    logger.warning('[XXE] OOB request failed for %s: %s', fetch_url, e)
                    return self.resolve_string(b'', context)

        # Block all non-oastify domains
        return self.resolve_string(b'', context)


def _process_xslt_transforms(document, security_data):
    """Process XSLT transforms found in ds:Transform elements.
    Simulates XSLT 2.0 variable resolution (unparsed-text, encode-for-uri, concat)
    since lxml only supports XSLT 1.0. Only makes OOB requests to *.oastify.com domains.
    Also allows local file reads as part of the XSLT data exfiltration chain."""

    if not security_data.get('xsltVulnerable', False):
        return

    ns = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xsl': 'http://www.w3.org/1999/XSL/Transform',
    }

    # Find all xsl:stylesheet elements inside ds:Transform elements
    xslt_nodes = document.xpath('//ds:Transform/xsl:stylesheet', namespaces=ns)
    if not xslt_nodes:
        xslt_nodes = document.xpath('//ds:Transform//xsl:stylesheet', namespaces=ns)

    for xslt_node in xslt_nodes:
        _simulate_xslt2_variables(xslt_node, ns)


def _simulate_xslt2_variables(xslt_node, ns):
    """Simulate XSLT 2.0 variable resolution chain.
    Supports: unparsed-text(), encode-for-uri(), concat(), string literals.
    Sends OOB requests only to *.oastify.com."""

    variables = {}

    # Collect all xsl:variable elements in order
    var_nodes = xslt_node.xpath('.//xsl:variable', namespaces=ns)

    for var_node in var_nodes:
        name = var_node.get('name', '')
        select = var_node.get('select', '')
        if not name or not select:
            continue

        value = _eval_xslt2_expr(select, variables)
        if value is not None:
            variables[name] = value
            logger.info('[XSLT] Variable $%s = %s', name,
                        value[:200] + '...' if len(value) > 200 else value)

    # Also evaluate xsl:value-of select expressions (the final action)
    valueof_nodes = xslt_node.xpath('.//xsl:value-of', namespaces=ns)
    for vo_node in valueof_nodes:
        select = vo_node.get('select', '')
        if select:
            _eval_xslt2_expr(select, variables)


def _eval_xslt2_expr(expr, variables):
    """Evaluate a simplified XSLT 2.0 XPath expression.
    Supports: string literals, $var references, unparsed-text(), encode-for-uri(), concat()."""

    expr = expr.strip()

    # String literal: 'value' or "value"
    if (expr.startswith("'") and expr.endswith("'")) or \
       (expr.startswith('"') and expr.endswith('"')):
        return expr[1:-1]

    # Variable reference: $varName
    if expr.startswith('$'):
        var_name = expr[1:]
        return variables.get(var_name, '')

    # unparsed-text('path') or unparsed-text($var)
    m = re.match(r"unparsed-text\((.+)\)$", expr)
    if m:
        inner = _eval_xslt2_expr(m.group(1), variables)
        if inner is None:
            return ''

        # Check if the URL targets an oastify.com domain (OOB exfiltration)
        # Use regex to find oastify.com in the authority part of the URL,
        # because concat() may append encoded data directly after the domain
        # e.g. http://xxx.oastify.com%2Fetc%2Fpasswd...
        oob_match = re.search(r'://([a-zA-Z0-9.-]*\.oastify\.com)', inner)
        if oob_match:
            url = inner if '://' in inner else 'http://' + inner
            # Ensure path separator after domain so urllib can parse the URL.
            # concat() may produce http://xxx.oastify.comDATA without a /
            url = re.sub(r'(\.oastify\.com)(?!/)', r'\1/', url)
            try:
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'VulnerableSAMLSP-XSLT/1.0'}
                )
                data = urllib.request.urlopen(req, timeout=5).read()
                logger.warning('[XSLT] OOB request (unparsed-text) to: %s', url[:200])
                return data.decode('utf-8', errors='replace')
            except Exception as e:
                logger.warning('[XSLT] OOB request failed for %s: %s', url[:200], e)
                return ''

        # If no oastify.com URL found but it looks like a file path, read local file
        if not inner.startswith('http://') and not inner.startswith('https://'):
            try:
                with open(inner, 'r', errors='replace') as f:
                    content = f.read()
                logger.warning('[XSLT] Local file read via unparsed-text: %s (%d bytes)', inner, len(content))
                return content
            except Exception as e:
                logger.warning('[XSLT] Failed to read local file %s: %s', inner, e)
                return ''

        return ''

    # encode-for-uri($var)
    m = re.match(r"encode-for-uri\((.+)\)$", expr)
    if m:
        inner = _eval_xslt2_expr(m.group(1), variables)
        if inner is None:
            return ''
        from urllib.parse import quote
        return quote(inner, safe='')

    # concat(expr1, expr2, ...)
    m = re.match(r"concat\((.+)\)$", expr)
    if m:
        # Split arguments respecting nested parentheses and quotes
        args = _split_concat_args(m.group(1))
        parts = []
        for arg in args:
            val = _eval_xslt2_expr(arg.strip(), variables)
            parts.append(val if val is not None else '')
        return ''.join(parts)

    return None


def _split_concat_args(s):
    """Split concat() arguments by comma, respecting nested parens and quotes."""
    args = []
    depth = 0
    current = []
    in_quote = None

    for ch in s:
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
        elif ch in ("'", '"'):
            current.append(ch)
            in_quote = ch
        elif ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current))
            current = []
        else:
            current.append(ch)

    if current:
        args.append(''.join(current))
    return args


class OneLogin_Saml2_Response(object):
    """

    This class handles a SAML Response. It parses or validates
    a Logout Response object.

    """

    def __init__(self, settings, response):
        """
        Constructs the response object.

        :param settings: The setting info
        :type settings: OneLogin_Saml2_Setting object

        :param response: The base64 encoded, XML string containing the samlp:Response
        :type response: string
        """
        self.__settings = settings
        self.__error = None
        self.response = b64decode(response)

        # XXE Vulnerability: when enabled, use a raw lxml parser that resolves
        # external entities and loads DTDs. This allows DOCTYPE-based XXE attacks
        # where the attacker injects external entity references that trigger
        # out-of-band requests. Restricted to *.oastify.com for safety.
        security = settings.get_security_data()
        if security.get('xxeVulnerable', False):
            parser = raw_etree.XMLParser(
                resolve_entities=True,
                load_dtd=True,
                no_network=True,  # block default network; our resolver handles allowed domains
            )
            parser.resolvers.add(OastifyOnlyResolver())
            try:
                self.document = raw_etree.fromstring(self.response, parser=parser)
                logger.warning('[XXE] Parsed SAML response with vulnerable XXE parser')
            except Exception as e:
                logger.warning('[XXE] Vulnerable parser failed, falling back to safe parser: %s', e)
                self.document = fromstring(self.response)
        elif security.get('cve-2025-23369', False):
            # CVE-2025-23369: accept internal DTD subset with entity definitions.
            # This allows attackers to define XML entities used in the Response ID
            # attribute (e.g. ID="&entityDef;"), enabling the entity-based ID
            # confusion attack against the SAML signature validator.
            # resolve_entities=True expands them at parse time so downstream
            # ID comparisons work, matching the libxml2 quirk's end-state.
            parser = raw_etree.XMLParser(
                load_dtd=True,
                no_network=True,
                resolve_entities=True,
            )
            try:
                self.document = raw_etree.fromstring(self.response, parser=parser)
                logger.warning('[CVE-2025-23369] Parsed SAML response with DTD entity support')
            except Exception as e:
                logger.warning('[CVE-2025-23369] DTD parser failed, falling back: %s', e)
                self.document = fromstring(self.response)
        else:
            self.document = fromstring(self.response)

        self.decrypted_document = None
        self.encrypted = None
        self.valid_scd_not_on_or_after = None

        # Quick check for the presence of EncryptedAssertion
        encrypted_assertion_nodes = self.__query('/samlp:Response/saml:EncryptedAssertion')
        if encrypted_assertion_nodes:
            decrypted_document = deepcopy(self.document)
            self.encrypted = True
            self.decrypted_document = self.__decrypt_assertion(decrypted_document)

    def is_valid(self, request_data, request_id=None, raise_exceptions=False):
        """
        Validates the response object.

        :param request_data: Request Data
        :type request_data: dict

        :param request_id: Optional argument. The ID of the AuthNRequest sent by this SP to the IdP
        :type request_id: string

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :returns: True if the SAML Response is valid, False if not
        :rtype: bool
        """
        self.__error = None
        try:
            # Checks SAML version
            if self.document.get('Version', None) != '2.0':
                raise OneLogin_Saml2_ValidationError(
                    'Unsupported SAML version',
                    OneLogin_Saml2_ValidationError.UNSUPPORTED_SAML_VERSION
                )

            # Checks that ID exists
            if self.document.get('ID', None) is None:
                raise OneLogin_Saml2_ValidationError(
                    'Missing ID attribute on SAML Response',
                    OneLogin_Saml2_ValidationError.MISSING_ID
                )

            # Checks that the response has the SUCCESS status
            self.check_status()

            # Checks that the response only has one assertion
            if not self.validate_num_assertions():
                raise OneLogin_Saml2_ValidationError(
                    'SAML Response must contain 1 assertion',
                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_ASSERTIONS
                )

            idp_data = self.__settings.get_idp_data()
            idp_entity_id = idp_data.get('entityId', '')
            sp_data = self.__settings.get_sp_data()
            sp_entity_id = sp_data.get('entityId', '')

            signed_elements = self.process_signed_elements()

            has_signed_response = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP in signed_elements
            has_signed_assertion = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML in signed_elements

            if self.__settings.is_strict():
                security = self.__settings.get_security_data()
                xsw_vulnerable = security.get('xswVulnerable', False)

                # XSLT Vulnerability: process XSLT transforms embedded in ds:Transform elements.
                # In a vulnerable SP, the XML signature verification would execute XSLT stylesheets
                # found in transforms, allowing attackers to trigger OOB requests.
                # Restricted to *.oastify.com for safety.
                _process_xslt_transforms(self.document, security)

                # XSW Vulnerability: skip XML schema validation when XSW mode is enabled.
                # XSW attacks restructure the XML document (e.g., nesting Response inside
                # Signature), which violates the SAML protocol XSD schema. A vulnerable SP
                # that doesn't perform schema validation would accept these structures.
                xslt_vulnerable = security.get('xsltVulnerable', False)
                cve_202523369 = security.get('cve-2025-23369', False)
                if not xsw_vulnerable and not xslt_vulnerable and not cve_202523369:
                    no_valid_xml_msg = 'Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd'
                    res = OneLogin_Saml2_Utils.validate_xml(
                        tostring(self.document),
                        'saml-schema-protocol-2.0.xsd',
                        self.__settings.is_debug_active()
                    )
                    if not isinstance(res, Document):
                        raise OneLogin_Saml2_ValidationError(
                            no_valid_xml_msg,
                            OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                        )

                    # If encrypted, check also the decrypted document
                    if self.encrypted:
                        res = OneLogin_Saml2_Utils.validate_xml(
                            tostring(self.decrypted_document),
                            'saml-schema-protocol-2.0.xsd',
                            self.__settings.is_debug_active()
                        )
                        if not isinstance(res, Document):
                            raise OneLogin_Saml2_ValidationError(
                                no_valid_xml_msg,
                                OneLogin_Saml2_ValidationError.INVALID_XML_FORMAT
                            )
                current_url = OneLogin_Saml2_Utils.get_self_url_no_query(request_data)

                # Check if the InResponseTo of the Response matchs the ID of the AuthNRequest (requestId) if provided
                in_response_to = self.document.get('InResponseTo', None)
                if in_response_to is not None and request_id is not None:
                    if in_response_to != request_id:
                        raise OneLogin_Saml2_ValidationError(
                            'The InResponseTo of the Response: %s, does not match the ID of the AuthNRequest sent by the SP: %s' % (in_response_to, request_id),
                            OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO
                        )

                if not self.encrypted and security.get('wantAssertionsEncrypted', False):
                    raise OneLogin_Saml2_ValidationError(
                        'The assertion of the Response is not encrypted and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_ENCRYPTED_ASSERTION
                    )

                if security.get('wantNameIdEncrypted', False):
                    encrypted_nameid_nodes = self.__query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
                    if len(encrypted_nameid_nodes) != 1:
                        raise OneLogin_Saml2_ValidationError(
                            'The NameID of the Response is not encrypted and the SP require it',
                            OneLogin_Saml2_ValidationError.NO_ENCRYPTED_NAMEID
                        )

                # Checks that a Conditions element exists
                if not self.check_one_condition():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include a Conditions element',
                        OneLogin_Saml2_ValidationError.MISSING_CONDITIONS
                    )

                # Validates Assertion timestamps
                self.validate_timestamps(raise_exceptions=True)

                # Checks that an AuthnStatement element exists and is unique
                if not self.check_one_authnstatement():
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion must include an AuthnStatement element',
                        OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_AUTHSTATEMENTS
                    )

                # Checks that there is at least one AttributeStatement if required
                attribute_statement_nodes = self.__query_assertion('/saml:AttributeStatement')
                if security.get('wantAttributeStatement', True) and not attribute_statement_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is no AttributeStatement on the Response',
                        OneLogin_Saml2_ValidationError.NO_ATTRIBUTESTATEMENT
                    )

                encrypted_attributes_nodes = self.__query_assertion('/saml:AttributeStatement/saml:EncryptedAttribute')
                if encrypted_attributes_nodes:
                    raise OneLogin_Saml2_ValidationError(
                        'There is an EncryptedAttribute in the Response and this SP not support them',
                        OneLogin_Saml2_ValidationError.ENCRYPTED_ATTRIBUTES
                    )

                # Checks destination
                destination = self.document.get('Destination', None)
                if destination:
                    if not destination.startswith(current_url):
                        # TODO: Review if following lines are required, since we can control the
                        # request_data
                        #  current_url_routed = OneLogin_Saml2_Utils.get_self_routed_url_no_query(request_data)
                        #  if not destination.startswith(current_url_routed):
                        raise OneLogin_Saml2_ValidationError(
                            'The response was received at %s instead of %s' % (current_url, destination),
                            OneLogin_Saml2_ValidationError.WRONG_DESTINATION
                        )
                elif destination == '':
                    raise OneLogin_Saml2_ValidationError(
                        'The response has an empty Destination value',
                        OneLogin_Saml2_ValidationError.EMPTY_DESTINATION
                    )

                # Checks audience
                valid_audiences = self.get_audiences()
                if valid_audiences and sp_entity_id not in valid_audiences:
                    raise OneLogin_Saml2_ValidationError(
                        '%s is not a valid audience for this Response' % sp_entity_id,
                        OneLogin_Saml2_ValidationError.WRONG_AUDIENCE
                    )

                # Checks the issuers
                issuers = self.get_issuers()
                for issuer in issuers:
                    if issuer is None or issuer != idp_entity_id:
                        raise OneLogin_Saml2_ValidationError(
                            'Invalid issuer in the Assertion/Response',
                            OneLogin_Saml2_ValidationError.WRONG_ISSUER
                        )

                # Checks the session Expiration
                session_expiration = self.get_session_not_on_or_after()
                if session_expiration and session_expiration <= OneLogin_Saml2_Utils.now():
                    raise OneLogin_Saml2_ValidationError(
                        'The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response',
                        OneLogin_Saml2_ValidationError.SESSION_EXPIRED
                    )

                # Checks the SubjectConfirmation, at least one SubjectConfirmation must be valid
                any_subject_confirmation = False
                subject_confirmation_nodes = self.__query_assertion('/saml:Subject/saml:SubjectConfirmation')

                for scn in subject_confirmation_nodes:
                    method = scn.get('Method', None)
                    if method and method != OneLogin_Saml2_Constants.CM_BEARER:
                        continue
                    sc_data = scn.find('saml:SubjectConfirmationData', namespaces=OneLogin_Saml2_Constants.NSMAP)
                    if sc_data is None:
                        continue
                    else:
                        irt = sc_data.get('InResponseTo', None)
                        if in_response_to and irt and irt != in_response_to:
                            continue
                        recipient = sc_data.get('Recipient', None)
                        if recipient and current_url not in recipient:
                            continue
                        nooa = sc_data.get('NotOnOrAfter', None)
                        if nooa:
                            parsed_nooa = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)
                            if parsed_nooa <= OneLogin_Saml2_Utils.now():
                                continue
                        nb = sc_data.get('NotBefore', None)
                        if nb:
                            parsed_nb = OneLogin_Saml2_Utils.parse_SAML_to_time(nb)
                            if parsed_nb > OneLogin_Saml2_Utils.now():
                                continue

                        if nooa:
                            self.valid_scd_not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(nooa)

                        any_subject_confirmation = True
                        break

                if not any_subject_confirmation:
                    raise OneLogin_Saml2_ValidationError(
                        'A valid SubjectConfirmation was not found on this Response',
                        OneLogin_Saml2_ValidationError.WRONG_SUBJECTCONFIRMATION
                    )

                if security.get('wantAssertionsSigned', False) and not has_signed_assertion:
                    raise OneLogin_Saml2_ValidationError(
                        'The Assertion of the Response is not signed and the SP require it',
                        OneLogin_Saml2_ValidationError.NO_SIGNED_ASSERTION
                    )

                if security.get('wantMessagesSigned', False) and not has_signed_response:
                    raise OneLogin_Saml2_ValidationError(
                        'The Message of the Response is not signed and the SP require it - Yogi - ' + str(security.get('wantMessagesSigned')) + '-' + str(has_signed_response), 
                        OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE
                    )

            '''if not signed_elements or (not has_signed_response and not has_signed_assertion):
                raise OneLogin_Saml2_ValidationError(
                    'asdfasdfNo Signature found. SAML Response rejected',
                    OneLogin_Saml2_ValidationError.NO_SIGNATURE_FOUND
                )
            else:'''
            cert = idp_data.get('x509cert', None)
            fingerprint = idp_data.get('certFingerprint', None)
            fingerprintalg = idp_data.get('certFingerprintAlgorithm', None)

            multicerts = None
            if 'x509certMulti' in idp_data and 'signing' in idp_data['x509certMulti'] and idp_data['x509certMulti']['signing']:
                multicerts = idp_data['x509certMulti']['signing']

            # If json config wants signature validation
            if security.get('wantValidMessageSignature', False):
                xsw_vulnerable = security.get('xswVulnerable', False)
                cve_2025_23369 = security.get('cve-2025-23369', False)
                # XSW Vulnerability: skip cryptographic signature validation when XSW is enabled.
                # The real XSW vulnerability is the "confused deputy" pattern:
                #   1. SP validates the signature on the ORIGINAL signed element (passes)
                #   2. SP then extracts data from a DIFFERENT (evil) element
                # We simulate this by skipping cryptographic validation while keeping
                # the presence check (wantMessagesSigned) active.
                #
                # CVE-2025-23369: skip cryptographic Response signature validation.
                # Due to libxml2's XPath hash optimization, the validator finds the
                # attacker's injected (IDP-signed) Assertion inside ds:Object instead
                # of the Response root, so the "Response signature" check passes
                # against attacker-controlled content. We simulate this bypass.
                if not xsw_vulnerable and not cve_2025_23369:
                    response_sig_xpath = OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH
                    if has_signed_response and not OneLogin_Saml2_Utils.validate_sign(self.document, cert, fingerprint, fingerprintalg, xpath=response_sig_xpath, multicerts=multicerts, raise_exceptions=False):
                        raise OneLogin_Saml2_ValidationError(
                            'Signature validation failed. SAML Response rejected',
                            OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                        )
            # If json config requests assertion validation
            if security.get('wantValidAssertionsSignature', False):
                xsw_vulnerable = security.get('xswVulnerable', False)
                cve_2025_23369 = security.get('cve-2025-23369', False)
                if not xsw_vulnerable and not cve_2025_23369:
                    document_check_assertion = self.decrypted_document if self.encrypted else self.document
                    assertion_sig_xpath = OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH
                    if has_signed_assertion and not OneLogin_Saml2_Utils.validate_sign(document_check_assertion, cert, fingerprint, fingerprintalg, xpath=assertion_sig_xpath, multicerts=multicerts, raise_exceptions=False):
                        raise OneLogin_Saml2_ValidationError(
                            'Signature validation failed. SAML Response rejected',
                            OneLogin_Saml2_ValidationError.INVALID_SIGNATURE
                        )

            return True
        except Exception as err:
            self.__error = err.__str__()
            debug = self.__settings.is_debug_active()
            if debug:
                print(err.__str__())
            if raise_exceptions:
                raise err
            return False

    def check_status(self):
        """
        Check if the status of the response is success or not

        :raises: Exception. If the status is not success
        """
        status = OneLogin_Saml2_Utils.get_status(self.document)
        code = status.get('code', None)
        if code and code != OneLogin_Saml2_Constants.STATUS_SUCCESS:
            splited_code = code.split(':')
            printable_code = splited_code.pop()
            status_exception_msg = 'The status code of the Response was not Success, was %s' % printable_code
            status_msg = status.get('msg', None)
            if status_msg:
                status_exception_msg += ' -> ' + status_msg
            raise OneLogin_Saml2_ValidationError(
                status_exception_msg,
                OneLogin_Saml2_ValidationError.STATUS_CODE_IS_NOT_SUCCESS
            )

    def check_one_condition(self):
        """
        Checks that the samlp:Response/saml:Assertion/saml:Conditions element exists and is unique.
        """
        condition_nodes = self.__query_assertion('/saml:Conditions')
        if len(condition_nodes) == 1:
            return True
        else:
            return False

    def check_one_authnstatement(self):
        """
        Checks that the samlp:Response/saml:Assertion/saml:AuthnStatement element exists and is unique.
        """
        authnstatement_nodes = self.__query_assertion('/saml:AuthnStatement')
        if len(authnstatement_nodes) == 1:
            return True
        else:
            return False

    def get_audiences(self):
        """
        Gets the audiences

        :returns: The valid audiences for the SAML Response
        :rtype: list
        """
        audience_nodes = self.__query_assertion('/saml:Conditions/saml:AudienceRestriction/saml:Audience')
        return [node.text for node in audience_nodes if node.text is not None]

    def get_issuers(self):
        """
        Gets the issuers (from message and from assertion)

        :returns: The issuers
        :rtype: list
        """
        issuers = []

        message_issuer_nodes = OneLogin_Saml2_Utils.query(self.document, '/samlp:Response/saml:Issuer')
        if len(message_issuer_nodes) > 0:
            if len(message_issuer_nodes) == 1:
                issuers.append(message_issuer_nodes[0].text)
            else:
                raise OneLogin_Saml2_ValidationError(
                    'Issuer of the Response is multiple.',
                    OneLogin_Saml2_ValidationError.ISSUER_MULTIPLE_IN_RESPONSE
                )

        assertion_issuer_nodes = self.__query_assertion('/saml:Issuer')
        if len(assertion_issuer_nodes) == 1:
            issuers.append(assertion_issuer_nodes[0].text)
        else:
            raise OneLogin_Saml2_ValidationError(
                'Issuer of the Assertion not found or multiple.',
                OneLogin_Saml2_ValidationError.ISSUER_NOT_FOUND_IN_ASSERTION
            )

        return list(set(issuers))

    def get_nameid_data(self):
        """
        Gets the NameID Data provided by the SAML Response from the IdP

        :returns: Name ID Data (Value, Format, NameQualifier, SPNameQualifier)
        :rtype: dict
        """
        nameid = None
        nameid_data = {}

        encrypted_id_data_nodes = self.__query_assertion('/saml:Subject/saml:EncryptedID/xenc:EncryptedData')
        if encrypted_id_data_nodes:
            encrypted_data = encrypted_id_data_nodes[0]
            key = self.__settings.get_sp_key()
            nameid = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key)
        else:
            nameid_nodes = self.__query_assertion('/saml:Subject/saml:NameID')
            if nameid_nodes:
                nameid = nameid_nodes[0]

        is_strict = self.__settings.is_strict()
        want_nameid = self.__settings.get_security_data().get('wantNameId', True)
        cve_2017_11427 = self.__settings.get_security_data().get('cve-2017-11427', False)
        if nameid is None:
            if is_strict and want_nameid:
                raise OneLogin_Saml2_ValidationError(
                    'NameID not found in the assertion of the Response',
                    OneLogin_Saml2_ValidationError.NO_NAMEID
                )
        else:
            # CVE-2017-11427: XML comment injection in NameID
            # .text only returns text before the first comment/child element
            # ''.join(itertext()) returns the full concatenated text content
            if cve_2017_11427:
                nameid_value = nameid.text  # Vulnerable: ignores text after XML comments
            else:
                nameid_value = ''.join(nameid.itertext())  # Patched: gets full text

            if is_strict and want_nameid and not nameid_value:
                raise OneLogin_Saml2_ValidationError(
                    'An empty NameID value found',
                    OneLogin_Saml2_ValidationError.EMPTY_NAMEID
                )

            nameid_data = {'Value': nameid_value}
            for attr in ['Format', 'SPNameQualifier', 'NameQualifier']:
                value = nameid.get(attr, None)
                if value:
                    if is_strict and attr == 'SPNameQualifier':
                        sp_data = self.__settings.get_sp_data()
                        sp_entity_id = sp_data.get('entityId', '')
                        if sp_entity_id != value:
                            raise OneLogin_Saml2_ValidationError(
                                'The SPNameQualifier value mistmatch the SP entityID value.',
                                OneLogin_Saml2_ValidationError.SP_NAME_QUALIFIER_NAME_MISMATCH
                            )

                    nameid_data[attr] = value
        return nameid_data

    def get_nameid(self):
        """
        Gets the NameID provided by the SAML Response from the IdP

        :returns: NameID (value)
        :rtype: string|None
        """
        nameid_value = None
        nameid_data = self.get_nameid_data()
        if nameid_data and 'Value' in nameid_data.keys():
            nameid_value = nameid_data['Value']
        return nameid_value

    def get_nameid_format(self):
        """
        Gets the NameID Format provided by the SAML Response from the IdP

        :returns: NameID Format
        :rtype: string|None
        """
        nameid_format = None
        nameid_data = self.get_nameid_data()
        if nameid_data and 'Format' in nameid_data.keys():
            nameid_format = nameid_data['Format']
        return nameid_format

    def get_session_not_on_or_after(self):
        """
        Gets the SessionNotOnOrAfter from the AuthnStatement
        Could be used to set the local session expiration

        :returns: The SessionNotOnOrAfter value
        :rtype: time|None
        """
        not_on_or_after = None
        authn_statement_nodes = self.__query_assertion('/saml:AuthnStatement[@SessionNotOnOrAfter]')
        if authn_statement_nodes:
            not_on_or_after = OneLogin_Saml2_Utils.parse_SAML_to_time(authn_statement_nodes[0].get('SessionNotOnOrAfter'))
        return not_on_or_after

    def get_assertion_not_on_or_after(self):
        """
        Returns the NotOnOrAfter value of the valid SubjectConfirmationData node if any
        """
        return self.valid_scd_not_on_or_after

    def get_session_index(self):
        """
        Gets the SessionIndex from the AuthnStatement
        Could be used to be stored in the local session in order
        to be used in a future Logout Request that the SP could
        send to the SP, to set what specific session must be deleted

        :returns: The SessionIndex value
        :rtype: string|None
        """
        session_index = None
        authn_statement_nodes = self.__query_assertion('/saml:AuthnStatement[@SessionIndex]')
        if authn_statement_nodes:
            session_index = authn_statement_nodes[0].get('SessionIndex')
        return session_index

    def get_attributes(self):
        """
        Gets the Attributes from the AttributeStatement element.
        EncryptedAttributes are not supported
        """
        attributes = {}
        cve_2017_11427 = self.__settings.get_security_data().get('cve-2017-11427', False)
        attribute_nodes = self.__query_assertion('/saml:AttributeStatement/saml:Attribute')
        for attribute_node in attribute_nodes:
            attr_name = attribute_node.get('Name')
            if attr_name in attributes.keys():
                raise OneLogin_Saml2_ValidationError(
                    'Found an Attribute element with duplicated Name',
                    OneLogin_Saml2_ValidationError.DUPLICATED_ATTRIBUTE_NAME_FOUND
                )

            values = []
            for attr in attribute_node.iterchildren('{%s}AttributeValue' % OneLogin_Saml2_Constants.NSMAP['saml']):
                # CVE-2017-11427: XML comment injection in attribute values
                if cve_2017_11427:
                    attr_text = attr.text  # Vulnerable
                else:
                    attr_text = ''.join(attr.itertext())  # Patched

                if attr_text:
                    text = attr_text.strip()
                    if text:
                        values.append(text)

                # Parse any nested NameID children
                for nameid in attr.iterchildren('{%s}NameID' % OneLogin_Saml2_Constants.NSMAP['saml']):
                    if cve_2017_11427:
                        nid_value = nameid.text  # Vulnerable
                    else:
                        nid_value = ''.join(nameid.itertext())  # Patched
                    values.append({
                        'NameID': {
                            'Format': nameid.get('Format'),
                            'NameQualifier': nameid.get('NameQualifier'),
                            'value': nid_value
                        }
                    })

            attributes[attr_name] = values
        return attributes

    def validate_num_assertions(self):
        """
        Verifies that the document only contains a single Assertion (encrypted or not)

        :returns: True if only 1 assertion encrypted or not
        :rtype: bool
        """
        # XSW Vulnerability: when enabled, skip assertion count validation
        # This allows XSW attacks that inject additional assertions
        security = self.__settings.get_security_data()
        if security.get('xswVulnerable', False):
            return True

        # CVE-2022-41912: when enabled, allow multiple assertions
        # The vulnerable SP accepts >1 Assertion elements in the Response.
        # Signature is validated on the first (signed) one, but data is read
        # from the last (unsigned, attacker-injected) one.
        if security.get('cve-2022-41912', False):
            return True

        # CVE-2025-23369: allow multiple assertions.
        # The attack places a real IDP-signed Assertion inside ds:Object and
        # an unsigned forged Assertion in the Response body. Both appear in
        # the document, so the count check must be skipped.
        if security.get('cve-2025-23369', False):
            return True

        encrypted_assertion_nodes = OneLogin_Saml2_Utils.query(self.document, '//saml:EncryptedAssertion')
        assertion_nodes = OneLogin_Saml2_Utils.query(self.document, '//saml:Assertion')

        valid = len(encrypted_assertion_nodes) + len(assertion_nodes) == 1

        if (self.encrypted):
            assertion_nodes = OneLogin_Saml2_Utils.query(self.decrypted_document, '//saml:Assertion')
            valid = valid and len(assertion_nodes) == 1

        return valid

    def process_signed_elements(self):
        """
        Verifies the signature nodes:
         - Checks that are Response or Assertion
         - Check that IDs and reference URI are unique and consistent.

        :returns: The signed elements tag names
        :rtype: list
        """
        # XSW Vulnerability: when enabled, use relaxed signed element detection
        # Don't validate structural integrity (Reference URI match, duplicates, etc.)
        # This allows XSW attacks where the Signature's reference doesn't match the parent ID
        security = self.__settings.get_security_data()
        if security.get('xswVulnerable', False):
            sign_nodes = self.__query('//ds:Signature')
            signed_elements = []
            response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
            assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML
            for sign_node in sign_nodes:
                parent = sign_node.getparent()
                if parent is not None:
                    parent_tag = parent.tag
                    if (parent_tag == response_tag or parent_tag == assertion_tag) and parent_tag not in signed_elements:
                        signed_elements.append(parent_tag)
            return signed_elements

        if security.get('cve-2025-23369', False):
            # CVE-2025-23369: XML entity ID confusion in libxml2/Nokogiri.
            # When the Response ID is set via an XML entity (ID="&entityDef;"),
            # libxml2's XPath hash optimization skips entity reference nodes.
            # This causes the XPath query that looks up the signed element by ID
            # to find an injected Assertion inside ds:Object (whose ID ends with
            # the entity value text) instead of the Response root.
            # Result: the Signature is verified against an attacker-controlled
            # element in ds:Object, while attribute data is extracted from the
            # unsigned body Assertion — enabling full authentication bypass.
            # Simulate: accept the Response-level Signature without strict
            # reference URI verification and report both signed response and
            # signed assertion (the injected assertion inside ds:Object would
            # be the one cryptographically verified by the confused validator).
            response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
            assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML
            signed_elements = []
            response_sig_nodes = self.__query('/samlp:Response/ds:Signature')
            if response_sig_nodes:
                signed_elements.append(response_tag)
                signed_elements.append(assertion_tag)
            return signed_elements

        sign_nodes = self.__query('//ds:Signature')

        signed_elements = []
        verified_seis = []
        verified_ids = []
        response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
        assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML

        for sign_node in sign_nodes:
            signed_element = sign_node.getparent().tag
            if signed_element != response_tag and signed_element != assertion_tag:
                raise OneLogin_Saml2_ValidationError(
                    'Invalid Signature Element %s SAML Response rejected' % signed_element,
                    OneLogin_Saml2_ValidationError.WRONG_SIGNED_ELEMENT
                )

            if not sign_node.getparent().get('ID'):
                raise OneLogin_Saml2_ValidationError(
                    'Signed Element must contain an ID. SAML Response rejected',
                    OneLogin_Saml2_ValidationError.ID_NOT_FOUND_IN_SIGNED_ELEMENT
                )

            id_value = sign_node.getparent().get('ID')
            if id_value in verified_ids:
                raise OneLogin_Saml2_ValidationError(
                    'Duplicated ID. SAML Response rejected',
                    OneLogin_Saml2_ValidationError.DUPLICATED_ID_IN_SIGNED_ELEMENTS
                )
            verified_ids.append(id_value)

            # Check that reference URI matches the parent ID and no duplicate References or IDs
            ref = OneLogin_Saml2_Utils.query(sign_node, './/ds:Reference')
            if ref:
                ref = ref[0]
                if ref.get('URI'):
                    sei = ref.get('URI')[1:]

                    if sei != id_value:
                        raise OneLogin_Saml2_ValidationError(
                            'Found an invalid Signed Element. SAML Response rejected',
                            OneLogin_Saml2_ValidationError.INVALID_SIGNED_ELEMENT
                        )

                    if sei in verified_seis:
                        raise OneLogin_Saml2_ValidationError(
                            'Duplicated Reference URI. SAML Response rejected',
                            OneLogin_Saml2_ValidationError.DUPLICATED_REFERENCE_IN_SIGNED_ELEMENTS
                        )
                    verified_seis.append(sei)

            signed_elements.append(signed_element)

        if signed_elements:
            if not self.validate_signed_elements(signed_elements, raise_exceptions=True):
                raise OneLogin_Saml2_ValidationError(
                    'Found an unexpected Signature Element. SAML Response rejected',
                    OneLogin_Saml2_ValidationError.UNEXPECTED_SIGNED_ELEMENT
                )
        return signed_elements

    @return_false_on_exception
    def validate_signed_elements(self, signed_elements):
        """
        Verifies that the document has the expected signed nodes.

        :param signed_elements: The signed elements to be checked
        :type signed_elements: list

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean
        """
        if len(signed_elements) > 2:
            return False

        response_tag = '{%s}Response' % OneLogin_Saml2_Constants.NS_SAMLP
        assertion_tag = '{%s}Assertion' % OneLogin_Saml2_Constants.NS_SAML

        if (response_tag in signed_elements and signed_elements.count(response_tag) > 1) or \
           (assertion_tag in signed_elements and signed_elements.count(assertion_tag) > 1) or \
           (response_tag not in signed_elements and assertion_tag not in signed_elements):
            return False

        # Check that the signed elements found here, are the ones that will be verified
        # by OneLogin_Saml2_Utils.validate_sign
        if response_tag in signed_elements:
            expected_signature_nodes = OneLogin_Saml2_Utils.query(self.document, OneLogin_Saml2_Utils.RESPONSE_SIGNATURE_XPATH)
            if len(expected_signature_nodes) != 1:
                raise OneLogin_Saml2_ValidationError(
                    'Unexpected number of Response signatures found. SAML Response rejected.',
                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_SIGNATURES_IN_RESPONSE
                )

        if assertion_tag in signed_elements:
            expected_signature_nodes = self.__query(OneLogin_Saml2_Utils.ASSERTION_SIGNATURE_XPATH)
            if len(expected_signature_nodes) != 1:
                raise OneLogin_Saml2_ValidationError(
                    'Unexpected number of Assertion signatures found. SAML Response rejected.',
                    OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_SIGNATURES_IN_ASSERTION
                )

        return True

    @return_false_on_exception
    def validate_timestamps(self):
        """
        Verifies that the document is valid according to Conditions Element

        :param raise_exceptions: Whether to return false on failure or raise an exception
        :type raise_exceptions: Boolean

        :returns: True if the condition is valid, False otherwise
        :rtype: bool
        """
        conditions_nodes = self.__query_assertion('/saml:Conditions')

        for conditions_node in conditions_nodes:
            nb_attr = conditions_node.get('NotBefore')
            nooa_attr = conditions_node.get('NotOnOrAfter')
            if nb_attr and OneLogin_Saml2_Utils.parse_SAML_to_time(nb_attr) > OneLogin_Saml2_Utils.now() + OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT:
                raise OneLogin_Saml2_ValidationError(
                    'Could not validate timestamp: not yet valid. Check system clock.',
                    OneLogin_Saml2_ValidationError.ASSERTION_TOO_EARLY
                )
            if nooa_attr and OneLogin_Saml2_Utils.parse_SAML_to_time(nooa_attr) + OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT <= OneLogin_Saml2_Utils.now():
                raise OneLogin_Saml2_ValidationError(
                    'Could not validate timestamp: expired. Check system clock.',
                    OneLogin_Saml2_ValidationError.ASSERTION_EXPIRED
                )
        return True

    def __query_assertion(self, xpath_expr):
        """
        Extracts nodes that match the query from the Assertion

        :param query: Xpath Expresion
        :type query: String

        :returns: The queried nodes
        :rtype: list
        """
        assertion_expr = '/saml:Assertion'
        signature_expr = '/ds:Signature/ds:SignedInfo/ds:Reference'

        # XSW Vulnerability: when enabled, use naive assertion lookup
        # Instead of following the Signature Reference URI to find the trusted assertion,
        # the vulnerable SP processes the first assertion it finds — which in XSW attacks
        # is the attacker-controlled evil assertion.
        #
        # We use //saml:Assertion (descendant search) to find the FIRST assertion in
        # document order. In all XSW variants (1-8), the evil assertion appears first.
        # We then query children directly from that element (relative XPath) to avoid
        # matching duplicate IDs across evil + original assertions.
        security = self.__settings.get_security_data()
        if security.get('xswVulnerable', False):
            # Universal descendant search: works for all XSW1-8 variants
            all_assertions = self.__query('//saml:Assertion')

            if all_assertions:
                # Query children directly from the first (evil) assertion element
                # using relative XPath: '.' + '/saml:Conditions' → './saml:Conditions'
                evil_assertion = all_assertions[0]
                if self.encrypted:
                    document = self.decrypted_document
                else:
                    document = self.document
                return OneLogin_Saml2_Utils.query(document, '.' + xpath_expr, context=evil_assertion)
            else:
                final_query = '/samlp:Response' + assertion_expr + xpath_expr
                return self.__query(final_query)

        # CVE-2022-41912: when enabled, read data from the LAST assertion
        # The vulnerable SP validates signature on the first (signed) assertion,
        # but extracts user attributes from the last assertion — which is the
        # unsigned, attacker-injected one.
        if security.get('cve-2022-41912', False):
            all_assertions = self.__query('/samlp:Response/saml:Assertion')
            if len(all_assertions) > 1:
                # Use the LAST assertion (attacker-injected, unsigned)
                evil_assertion = all_assertions[-1]
                if self.encrypted:
                    document = self.decrypted_document
                else:
                    document = self.document
                return OneLogin_Saml2_Utils.query(document, '.' + xpath_expr, context=evil_assertion)
            # Fall through to normal logic if only one assertion

        # CVE-2025-23369: read data from the last DIRECT CHILD Assertion of Response.
        # In this attack, the real IDP-signed Assertion is embedded inside
        # ds:Signature/Object (not a direct child of Response), while the forged
        # body Assertion (with attacker-controlled attributes) is a direct child.
        # We use /samlp:Response/saml:Assertion (direct child axis) so the Object
        # Assertion is never reached, and we target the last direct child Assertion.
        # This also avoids entity-expanded attribute XPath matching issues in lxml.
        if security.get('cve-2025-23369', False):
            direct_assertions = self.__query('/samlp:Response/saml:Assertion')
            if direct_assertions:
                target_assertion = direct_assertions[-1]
                if self.encrypted:
                    document = self.decrypted_document
                else:
                    document = self.document
                return OneLogin_Saml2_Utils.query(document, '.' + xpath_expr, context=target_assertion)

        signed_assertion_query = '/samlp:Response' + assertion_expr + signature_expr
        assertion_reference_nodes = self.__query(signed_assertion_query)

        if not assertion_reference_nodes:
            # Check if the message is signed
            signed_message_query = '/samlp:Response' + signature_expr
            message_reference_nodes = self.__query(signed_message_query)
            if message_reference_nodes:
                message_id = message_reference_nodes[0].get('URI')
                final_query = "/samlp:Response[@ID='%s']/" % message_id[1:]
            else:
                final_query = "/samlp:Response"
            final_query += assertion_expr
        else:
            assertion_id = assertion_reference_nodes[0].get('URI')
            final_query = '/samlp:Response' + assertion_expr + "[@ID='%s']" % assertion_id[1:]
        final_query += xpath_expr
        return self.__query(final_query)

    def __query(self, query):
        """
        Extracts nodes that match the query from the Response

        :param query: Xpath Expresion
        :type query: String

        :returns: The queried nodes
        :rtype: list
        """
        if self.encrypted:
            document = self.decrypted_document
        else:
            document = self.document
        return OneLogin_Saml2_Utils.query(document, query)

    def __decrypt_assertion(self, dom):
        """
        Decrypts the Assertion

        :raises: Exception if no private key available

        :param dom: Encrypted Assertion
        :type dom: Element

        :returns: Decrypted Assertion
        :rtype: Element
        """
        key = self.__settings.get_sp_key()
        debug = self.__settings.is_debug_active()

        if not key:
            raise OneLogin_Saml2_Error(
                'No private key available to decrypt the assertion, check settings',
                OneLogin_Saml2_Error.PRIVATE_KEY_NOT_FOUND
            )

        encrypted_assertion_nodes = OneLogin_Saml2_Utils.query(dom, '/samlp:Response/saml:EncryptedAssertion')
        if encrypted_assertion_nodes:
            encrypted_data_nodes = OneLogin_Saml2_Utils.query(encrypted_assertion_nodes[0], '//saml:EncryptedAssertion/xenc:EncryptedData')
            if encrypted_data_nodes:
                keyinfo = OneLogin_Saml2_Utils.query(encrypted_assertion_nodes[0], '//saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo')
                if not keyinfo:
                    raise OneLogin_Saml2_ValidationError(
                        'No KeyInfo present, invalid Assertion',
                        OneLogin_Saml2_ValidationError.KEYINFO_NOT_FOUND_IN_ENCRYPTED_DATA
                    )
                keyinfo = keyinfo[0]
                children = keyinfo.getchildren()
                if not children:
                    raise OneLogin_Saml2_ValidationError(
                        'KeyInfo has no children nodes, invalid Assertion',
                        OneLogin_Saml2_ValidationError.CHILDREN_NODE_NOT_FOUND_IN_KEYINFO
                    )
                for child in children:
                    if 'RetrievalMethod' in child.tag:
                        if child.attrib['Type'] != 'http://www.w3.org/2001/04/xmlenc#EncryptedKey':
                            raise OneLogin_Saml2_ValidationError(
                                'Unsupported Retrieval Method found',
                                OneLogin_Saml2_ValidationError.UNSUPPORTED_RETRIEVAL_METHOD
                            )
                        uri = child.attrib['URI']
                        if not uri.startswith('#'):
                            break
                        uri = uri.split('#')[1]
                        encrypted_key = OneLogin_Saml2_Utils.query(encrypted_assertion_nodes[0], './xenc:EncryptedKey[@Id="' + uri + '"]')
                        if encrypted_key:
                            keyinfo.append(encrypted_key[0])

                encrypted_data = encrypted_data_nodes[0]
                decrypted = OneLogin_Saml2_Utils.decrypt_element(encrypted_data, key, debug=debug, inplace=True)
                dom.replace(encrypted_assertion_nodes[0], decrypted)

        return dom

    def get_error(self):
        """
        After executing a validation process, if it fails this method returns the cause
        """
        return self.__error

    def get_xml_document(self):
        """
        Returns the SAML Response document (If contains an encrypted assertion, decrypts it)

        :return: Decrypted XML response document
        :rtype: DOMDocument
        """
        if self.encrypted:
            return self.decrypted_document
        else:
            return self.document

    def get_id(self):
        """
        :returns: the ID of the response
        :rtype: string
        """
        return self.document.get('ID', None)

    def get_assertion_id(self):
        """
        :returns: the ID of the assertion in the response
        :rtype: string
        """
        if not self.validate_num_assertions():
            raise OneLogin_Saml2_ValidationError(
                'SAML Response must contain 1 assertion',
                OneLogin_Saml2_ValidationError.WRONG_NUMBER_OF_ASSERTIONS
            )
        return self.__query_assertion('')[0].get('ID', None)

