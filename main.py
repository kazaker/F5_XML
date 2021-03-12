import xml.etree.ElementTree as ET
import static
import func_module

tree = ET.parse(static.source_file)
root = tree.getroot()
f = open(static.result_file, 'w')

policy_table_list = ['Policy Name', 'Description', 'Policy Type', 'Parent Policy', 'Policy Template',
                     'Application Language', 'Enforcement Mode', 'Policy Building Learning Mode',
                     'Enforcement Readiness Period in days', 'Server Technologies', 'Policy is Case Sensitive',
                     'Event Correlation Reporting', 'Mask Credit Card Numbers in Request Log',
                     'Maximum HTTP Header Length', 'Maximum Cookie Header Length', 'Allowed Response Status Codes',
                     'Trigger ASM iRule Events Mode', 'Trust XFF Header', 'Handle Path Parameters']

# Auto-Apply Policy?
# Learning Speed? Multiple parameters
# Differentiate between HTTP/WS and HTTPS/WSS URLs?

policy_allowed_response_code = []  # Allowed Response Status Codes
for x in root.findall('allowed_response_code'):
    policy_allowed_response_code.append(x.text)

# server_technologies
policy_server_technology = []  # server_technology_name
for x in root.findall('server_technologies'):
    for y in x.iter('server_technology'):
        for z in y.findall('server_technology_name'):
            policy_server_technology.append(z.text)

policy_encoding = root.find('encoding').text  # Policy Name
policy_description = root.find('description').text  # Description
policy_type = root.find('type').text  # Policy Type
policy_encoding = root.find('encoding').text  # Application Language
if policy_type != 'Parent':
    test = root.find('parent_policy_name')
    if root.find('parent_policy_name') != None:
        policy_parent_policy_name = root.find('parent_policy_name').text  # Parent Policy
    else:
        policy_parent_policy_name = 'None'
policy_case_insensitive = root.find('case_insensitive').text  # Policy is Case Sensitive
policy_template = root.find('policy_template').text  # Policy Template
policy_trust_xff = root.find('trust_xff').text  # Trust XFF Header

for x in root.iter('policy_version'):
    policy_name = x.find('policy_name').text  # Policy Name

for x in root.iter('general'):
    policy_path_parameter_handling = x.find('path_parameter_handling').text  # Handle Path Parameters
    policy_mask_sensitive = x.find('mask_sensitive').text  # Mask Credit Card Numbers in Request Logs
    policy_trigger_asm_irule_event = x.find('trigger_asm_irule_event').text  # Trigger ASM iRule Events Mode
    policy_staging_period_in_days = x.find('staging_period_in_days').text  # Enforcement Readiness Period
    policy_enable_correlation = x.find('enable_correlation').text  # Event Correlation Reporting
    if x.find('dynamic_session_id_in_url'):  # Dynamic Session ID in URL
        policy_dynamic_session_id_in_url = 'true'
    else:
        policy_dynamic_session_id_in_url = 'false'

for x in root.iter('policy_builder'):
    policy_learning_mode = x.find('learning_mode').text  # Policy Building Learning Mode

for x in root.iter('header_settings'):
    policy_maximum_http_length = x.find('maximum_http_length').text  # Maximum HTTP Header Length

for x in root.iter('cookie_settings'):
    if x.find('maximum_cookie_length').text == '0':  # Maximum Cookie Header Length
        policy_maximum_cookie_length = 'Any'
    else:
        policy_maximum_cookie_length = x.find('maximum_cookie_length').text

# blocking
policy_violations = []
policy_alarm_block_learn = []
policy_evasions_name = []
policy_evasions_status = []
policy_http_protocol_compliance_setting_name = []
policy_http_protocol_compliance_setting_status = []
policy_invalid_violations = ['Mitigation action determined by Threat Analysis Platform', 'Leaked Credentials Detection']
policy_web_services_security_settings_name = []
policy_web_services_security_settings_status = []

for x in root.iter('blocking'):
    policy_enforcement_mode = x.find('enforcement_mode').text  # Enforcement Mode
    policy_passive_mode = x.find('passive_mode').text
    for y in x.iter('violation'):
        temp = y.get('name')
        temp_list = []
        if temp in policy_invalid_violations:
            continue
        else:
            policy_violations.append(temp)
            for z in y.findall('learn'):
                temp_list.append(z.text)
            for z in y.findall('alarm'):
                temp_list.append(z.text)
            for z in y.findall('block'):
                temp_list.append(z.text)
            policy_alarm_block_learn.append(temp_list)
    for y in x.iter('evasion_setting'):
        temp = y.get('name')
        temp_list = []
        if temp == 'Multiple decoding':
            policy_evasions_name.append(
                temp + ' (considered an evasion after ' + y.get('max_decoding_passes') + ' decoding passes)')
            temp_list.append(y.text)
            temp_list.append(y.get('policy_builder_tracking'))
            policy_evasions_status.append(temp_list)
        else:
            policy_evasions_name.append(temp)
            temp_list.append(y.text)
            temp_list.append(y.get('policy_builder_tracking'))
            policy_evasions_status.append(temp_list)
    for y in x.iter('http_protocol_compliance_setting'):
        temp = y.get('name')
        temp_list = []
        if temp == 'Check maximum number of headers':
            policy_http_protocol_compliance_setting_name.append(
                temp + ' (maximum ' + y.get('maximum_headers') + ' headers)')
            temp_list.append(y.text)
            temp_list.append(y.get('policy_builder_tracking'))
            policy_http_protocol_compliance_setting_status.append(temp_list)
        elif temp == 'Check maximum number of parameters':
            policy_http_protocol_compliance_setting_name.append(
                temp + ' (maximum ' + y.get('maximum_parameters') + ' parameters)')
            temp_list.append(y.text)
            temp_list.append(y.get('policy_builder_tracking'))
            policy_http_protocol_compliance_setting_status.append(temp_list)
        else:
            policy_http_protocol_compliance_setting_name.append(temp)
            temp_list.append(y.text)
            temp_list.append(y.get('policy_builder_tracking'))
            policy_http_protocol_compliance_setting_status.append(temp_list)
    for y in x.iter('web_services_security_settings'):
        if y.get('name'):
            temp_list = [y.get('policy_builder_tracking'), y.text]
            policy_web_services_security_settings_status.append(temp_list)
            temp = y.get('name').split('_')
            policy_web_services_security_settings_name.append(' '.join(temp[2:]).capitalize())

policy_attack_signature_sets = []
signatures_alarm_block_learn = []
signature_names = []
signature_status = []

for x in root.iter('attack_signatures'):
    for y in x.iter('signature_set'):
        temp_list = []
        for z in y.findall('set'):
            policy_attack_signature_sets.append(z.get('name'))
        for z in y.findall('learn'):
            temp_list.append(z.text)
        for z in y.findall('alarm'):
            temp_list.append(z.text)
        for z in y.findall('block'):
            temp_list.append(z.text)
        signatures_alarm_block_learn.append(temp_list)
    for y in x.iter('signature'):
        signature_names.append(y.get('signature_id'))
        for z in y.findall('enabled'):
            signature_status.append(z.text)
    signatures_enable_staging = x.find('enable_staging').text
    place_signatures_in_staging = x.find('place_signatures_in_staging').text
    min_accuracy_for_auto_added_signatures = x.find('min_accuracy_for_auto_added_signatures').text
    attack_signature_false_positive_mode = x.find('attack_signature_false_positive_mode').text

f.writelines('###Общие настройки политики###')
f.writelines('\n')
f.writelines('Параметр,Значение,Комментарий')
f.writelines('\n')
f.writelines(policy_table_list[0] + ',' + policy_name + ',')
f.writelines('\n')
f.writelines(policy_table_list[1] + ',' + policy_description + ',')
f.writelines('\n')
f.writelines(policy_table_list[2] + ',' + policy_type + ',')
f.writelines('\n')
if policy_type != 'Parent':
    f.writelines(policy_table_list[3] + ',' + policy_parent_policy_name + ',')
    f.writelines('\n')
f.writelines(policy_table_list[4] + ',' + policy_template + ',')
f.writelines('\n')
f.writelines(policy_table_list[5] + ',' + policy_encoding + ',')
f.writelines('\n')
f.writelines(policy_table_list[6] + ',' + policy_enforcement_mode + ',')
f.writelines('\n')
f.writelines(policy_table_list[7] + ',' + policy_learning_mode + ',')
f.writelines('\n')
f.writelines(policy_table_list[8] + ',' + policy_staging_period_in_days + ',')
f.writelines('\n')
f.writelines(policy_table_list[9] + ',' + 'shpongle'.join(policy_server_technology) + ',')
f.writelines('\n')
f.writelines(policy_table_list[10] + ',' + policy_case_insensitive + ',')
f.writelines('\n')
f.writelines(policy_table_list[11] + ',' + policy_enable_correlation + ',')
f.writelines('\n')
f.writelines(policy_table_list[12] + ',' + policy_mask_sensitive + ',')
f.writelines('\n')
f.writelines(policy_table_list[13] + ',' + policy_maximum_http_length + ',')
f.writelines('\n')
f.writelines(policy_table_list[14] + ',' + policy_maximum_cookie_length + ',')
f.writelines('\n')
f.writelines(policy_table_list[15] + ',' + 'shpongle'.join(policy_allowed_response_code) + ',')
f.writelines('\n')
f.writelines(policy_table_list[16] + ',' + policy_trigger_asm_irule_event + ',')
f.writelines('\n')
f.writelines(policy_table_list[17] + ',' + policy_trust_xff + ',')
f.writelines('\n')
f.writelines(policy_table_list[18] + ',' + policy_path_parameter_handling + ',')
f.writelines('\n')
f.writelines('\n')

disabled_signatures = []
for index, value in enumerate(signature_status):
    if value == 'false':
        disabled_signatures.append(signature_names[index])
f.writelines('###Globally Disabled Signatures###')
f.writelines('\n')
for item in disabled_signatures:
    f.writelines(item)
    f.writelines('\n')


# Learning Threat Campaign options
for x in root.iter('threat_campaign_attributes'):
    threat_enable_staging = x.find('enable_staging').text
    staging_period_in_days = x.find('staging_period_in_days').text

# Learning cookies options
for x in root.iter('policy_builder_cookie'):
    learn_cookies = x.find('learn_cookies').text
    maximum_allowed_modified_cookies = x.find('maximum_allowed_modified_cookies').text
    collapse_cookies = x.find('collapse_cookies').text
    collapse_cookies_occurrences = x.find('collapse_cookies_occurrences').text
    flg_enforce_unmodified_cookies = x.find('flg_enforce_unmodified_cookies').text

# Learning files options
for x in root.iter('policy_builder_filetype'):
    learn_file_types = x.find('learn_file_types').text
    maximum_file_types = x.find('maximum_file_types').text

# Learning parameter options
for x in root.iter('policy_builder_parameter'):
    learn_parameters = x.find('learn_parameters').text
    parameters_integer_value = x.find('parameters_integer_value').text
    maximum_parameters = x.find('maximum_parameters').text
    parameter_level = x.find('parameter_level').text
    collapse_parameters = x.find('collapse_parameters').text
    collapse_parameters_occurrences = x.find('collapse_parameters_occurrences').text
    classify_parameters = x.find('classify_parameters').text
    for y in x.findall('dynamic_parameters'):
        unique_value_sets = y.find('unique_value_sets').text
        hidden_fields = y.find('hidden_fields').text
        use_statistics_forms = y.find('use_statistics_forms').text
        use_statistics_links = y.find('use_statistics_links').text

# Learning URLs options
for x in root.iter('policy_builder_url'):
    learn_urls = x.find('learn_urls').text
    learn_websocket_urls = x.find('learn_websocket_urls').text
    maximum_urls = x.find('maximum_urls').text
    maximum_websocket_urls = x.find('maximum_websocket_urls').text
    collapse_urls = x.find('collapse_urls').text
    collapse_urls_occurrences = x.find('collapse_urls_occurrences').text
    classify_urls = x.find('classify_urls').text
    classify_websocket_urls = x.find('classify_websocket_urls').text
    set_method_override_on_url = x.find('set_method_override_on_url').text
    url_filetypes = []
    for y in x.findall('filetype'):
        url_filetypes.append(y.text)

# Learning headers options
for x in root.iter('policy_builder_header'):
    valid_host_names = x.find('valid_host_names').text
    maximum_hosts = x.find('maximum_hosts').text


# Learning redirection options
for x in root.iter('policy_builder_redirection_protection'):
    learn_redirection_domains = x.find('learn_redirection_domains').text
    maximum_redirection_domains = x.find('maximum_redirection_domains').text

# Learning session options
for x in root.iter('policy_builder_sessions_and_logins'):
    flg_learn_login_pages = x.find('flg_learn_login_pages').text

# Learning Server tech options
for x in root.iter('policy_builder_server_technologies'):
    learn_server_technologies = x.find('learn_server_technologies').text

f.writelines('\n')
f.writelines('###Настройки обучения и блокировок###')
f.writelines('\n')
f.writelines('Name,Learn,Alarm,Block,Comment')
f.writelines('\n')

f.writelines('Antivirus')
f.writelines('\n')
f.writelines('Virus detected' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Virus detected')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Attack Signatures')
f.writelines('\n')
for index, item in enumerate(policy_attack_signature_sets):
    f.writelines(item + ',' + ','.join(signatures_alarm_block_learn[index]))
    f.writelines('\n')
f.writelines('Auto-Added Signature Accuracy' + ',' + min_accuracy_for_auto_added_signatures)
f.writelines('\n')
f.writelines('Enable Signature Staging' + ',' + signatures_enable_staging)
f.writelines('\n')
place_signatures_in_staging = 'Retain previous rule enforcement and place updated rule in staging' if place_signatures_in_staging == 'true' else 'Enforce updated rule immediately for non-staged signatures'
f.writelines('Updated Signature Enforcement' + ',' + place_signatures_in_staging)
f.writelines('\n')
f.writelines('Attack Signature False Positive Mode' + ',' + attack_signature_false_positive_mode)
f.writelines('\n')
f.writelines('\n')


f.writelines('CSRF Protection')
f.writelines('\n')
f.writelines('CSRF authentication expired' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('CSRF authentication expired')]))
f.writelines('\n')
f.writelines(
    'CSRF attack detected' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('CSRF attack detected')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Content Profiles')
f.writelines('\n')
f.writelines('GWT data does not comply with format settings' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('GWT data does not comply with format settings')]))
f.writelines('\n')
f.writelines('Illegal attachment in SOAP message' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal attachment in SOAP message')]))
f.writelines('\n')
f.writelines('JSON data does not comply with JSON schema' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('JSON data does not comply with JSON schema')]))
f.writelines('\n')
f.writelines('JSON data does not comply with format settings' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('JSON data does not comply with format settings')]))
f.writelines('\n')
f.writelines(
    'Malformed GWT data' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Malformed GWT data')]))
f.writelines('\n')
f.writelines(
    'Malformed JSON data' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Malformed JSON data')]))
f.writelines('\n')
f.writelines(
    'Malformed XML data' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Malformed XML data')]))
f.writelines('\n')
f.writelines('Plain text data does not comply with format settings' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Plain text data does not comply with format settings')]))
f.writelines('\n')
f.writelines('SOAP method not allowed' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('SOAP method not allowed')]))
f.writelines('\n')
f.writelines('XML data does not comply with format settings' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('XML data does not comply with format settings')]))
f.writelines('\n')
f.writelines('XML data does not comply with schema or WSDL document' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('XML data does not comply with schema or WSDL document')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Web Services Security failure' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Web Services Security failure')]))
f.writelines('\n')
f.writelines('Name,Enable,Learn')
f.writelines('\n')
for index, item in enumerate(policy_web_services_security_settings_name):
    f.writelines(
        item + ',' + ','.join(policy_web_services_security_settings_status[index]))
    f.writelines('\n')
f.writelines('\n')

f.writelines('Cookies')
f.writelines('\n')
f.writelines('Learn New Cookies' + ',' + learn_cookies)
f.writelines('\n')
if learn_cookies != 'Never':
    f.writelines('Maximum Learned Cookies' + ',' + maximum_allowed_modified_cookies)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned Cookies' + ',' + '-')
    f.writelines('\n')
f.writelines('Learn and enforce new unmodified cookies' + ',' + flg_enforce_unmodified_cookies)
f.writelines('\n')
f.writelines('Cookie not RFC-compliant' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Cookie not RFC-compliant')]))
f.writelines('\n')
f.writelines(
    'Expired timestamp' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Expired timestamp')]))
f.writelines('\n')
f.writelines('Illegal cookie length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal cookie length')]))
f.writelines('\n')
f.writelines(
    'Modified ASM cookie' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Modified ASM cookie')]))
f.writelines('\n')
f.writelines('Modified domain cookie(s)' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Modified domain cookie(s)')]))
f.writelines('\n')
f.writelines('Collapse many common Cookies into one wildcard Cookie after ' + collapse_cookies_occurrences + ' occurences' + ',' + collapse_cookies)
f.writelines('\n')
f.writelines('\n')

f.writelines('Data Guard')
f.writelines('\n')
f.writelines('Data Guard: Information leakage detected' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Data Guard: Information leakage detected')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Evasion technique detected' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Evasion technique detected')]))
f.writelines('\n')
f.writelines('Name,Enable,Learn')
f.writelines('\n')
for index, item in enumerate(policy_evasions_name):
    f.writelines(item + ',' + ','.join(policy_evasions_status[index]))
    f.writelines('\n')
f.writelines('\n')

f.writelines('File Types')
f.writelines('\n')
f.writelines('Learn New File Types' + ',' + learn_file_types)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned File Types' + ',' + maximum_file_types)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned File Types' + ',' + '-')
    f.writelines('\n')
f.writelines('Illegal POST data length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal POST data length')]))
f.writelines('\n')
f.writelines(
    'Illegal URL length' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal URL length')]))
f.writelines('\n')
f.writelines(
    'Illegal file type' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal file type')]))
f.writelines('\n')
f.writelines('Illegal query string length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal query string length')]))
f.writelines('\n')
f.writelines('Illegal request length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal request length')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('General Settings')
f.writelines('\n')
f.writelines('Blocking Condition Detected' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Blocking Condition Detected')]))
f.writelines('\n')
f.writelines('Failed to convert character' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Failed to convert character')]))
f.writelines('\n')
f.writelines(
    'Illegal Base64 value' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal Base64 value')]))
f.writelines('\n')
f.writelines('Illegal HTTP status in response' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal HTTP status in response')]))
f.writelines('\n')
f.writelines('Illegal session ID in URL' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal session ID in URL')]))
f.writelines('\n')
f.writelines('Request length exceeds defined buffer size' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Request length exceeds defined buffer size')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Headers')
f.writelines('\n')
f.writelines(
    'Host name mismatch' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Host name mismatch')]))
f.writelines('\n')
f.writelines('Illegal header length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal header length')]))
f.writelines('\n')
f.writelines(
    'Illegal host name' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal host name')]))
f.writelines('\n')
f.writelines('Illegal meta character in header' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal meta character in header')]))
f.writelines('\n')
f.writelines('Illegal method' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal method')]))
f.writelines('\n')
f.writelines('Mandatory HTTP header is missing' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Mandatory HTTP header is missing')]))
f.writelines('\n')
f.writelines('Learn Host Names' + ',' + valid_host_names)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned Host Names' + ',' + maximum_hosts)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned Host Names' + ',' + '-')
    f.writelines('\n')
f.writelines('\n')

f.writelines('HTTP protocol compliance failed' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('HTTP protocol compliance failed')]))
f.writelines('\n')
f.writelines('Name,Enable,Learn')
f.writelines('\n')
for index, item in enumerate(policy_http_protocol_compliance_setting_name):
    f.writelines(
        item + ',' + ','.join(policy_http_protocol_compliance_setting_status[index]))
    f.writelines('\n')
f.writelines('\n')

f.writelines('IP Addresses and Geolocations')
f.writelines('\n')
f.writelines('Access from disallowed Geolocation' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Access from disallowed Geolocation')]))
f.writelines('\n')
f.writelines('Access from malicious IP address' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Access from malicious IP address')]))
f.writelines('\n')
f.writelines(
    'Bad Actor Detected' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Bad Actor Detected')]))
f.writelines('\n')
f.writelines(
    'IP is blacklisted' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('IP is blacklisted')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Parameters')
f.writelines('\n')
f.writelines('Learn New Parameters' + ',' + learn_parameters)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned Parameters' + ',' + maximum_parameters)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned Parameters' + ',' + '-')
    f.writelines('\n')
f.writelines('Disallowed file upload content detected' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Disallowed file upload content detected')]))
f.writelines('\n')
f.writelines('Illegal dynamic parameter value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal dynamic parameter value')]))
f.writelines('\n')
f.writelines('Illegal empty parameter value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal empty parameter value')]))
f.writelines('\n')
f.writelines('Illegal meta character in parameter name' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal meta character in parameter name')]))
f.writelines('\n')
f.writelines('Illegal meta character in value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal meta character in value')]))
f.writelines('\n')
f.writelines(
    'Illegal parameter' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal parameter')]))
f.writelines('\n')
f.writelines('Illegal parameter array value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal parameter array value')]))
f.writelines('\n')
f.writelines('Illegal parameter data type' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal parameter data type')]))
f.writelines('\n')
f.writelines('Illegal parameter location' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal parameter location')]))
f.writelines('\n')
f.writelines('Illegal parameter numeric value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal parameter numeric value')]))
f.writelines('\n')
f.writelines('Illegal parameter value length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal parameter value length')]))
f.writelines('\n')
f.writelines('Illegal repeated parameter name' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal repeated parameter name')]))
f.writelines('\n')
f.writelines('Illegal static parameter value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal static parameter value')]))
f.writelines('\n')
f.writelines('Mandatory parameter is missing' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Mandatory parameter is missing')]))
f.writelines('\n')
f.writelines('Null in multi-part parameter value' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Null in multi-part parameter value')]))
f.writelines('\n')
f.writelines('Parameter value does not comply with regular expression' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Parameter value does not comply with regular expression')]))
f.writelines('\n')
f.writelines('Parameter Level' + ',' + parameter_level)
f.writelines('\n')
f.writelines('Collapse many common Parameters into one wildcard Parameter after ' + collapse_parameters_occurrences + ' occurences' + ',' + collapse_parameters)
f.writelines('\n')
f.writelines('Classify Value Content of Learned Parameters' + ',' + classify_parameters)
f.writelines('\n')
f.writelines('Learn Integer Parameters' + ',' + parameters_integer_value)
f.writelines('\n')
f.writelines('\n')

f.writelines('Redirection Domains')
f.writelines('\n')
f.writelines('Learn New Redirection Domains' + ',' + learn_redirection_domains)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned Redirection Domains' + ',' + maximum_redirection_domains)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned Redirection Domains' + ',' + '-')
    f.writelines('\n')
f.writelines('Illegal redirection attempt' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal redirection attempt')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Server Technologies')
f.writelines('\n')
f.writelines('Enable Server Technology Detection' + ',' + learn_server_technologies)
f.writelines('\n')
f.writelines('\n')

f.writelines('Sessions and Logins')
f.writelines('\n')
f.writelines('Detect login pages' + ',' + flg_learn_login_pages)
f.writelines('\n')
f.writelines(
    'ASM Cookie Hijacking' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('ASM Cookie Hijacking')]))
f.writelines('\n')
f.writelines('Access from disallowed User/Session/IP/Device ID' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Access from disallowed User/Session/IP/Device ID')]))
f.writelines('\n')
f.writelines(
    'Bad Actor Convicted' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Bad Actor Convicted')]))
f.writelines('\n')
f.writelines('Brute Force: Maximum login attempts are exceeded' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Brute Force: Maximum login attempts are exceeded')]))
f.writelines('\n')
f.writelines(
    'Login URL bypassed' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Login URL bypassed')]))
f.writelines('\n')
f.writelines(
    'Login URL expired' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Login URL expired')]))
f.writelines('\n')
f.writelines('\n')

f.writelines('Threat Campaigns')
f.writelines('\n')
f.writelines('Threat Campaign detected' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Threat Campaign detected')]))
f.writelines('\n')
f.writelines('Enable Threat Campaign Staging' + ',' + threat_enable_staging)
f.writelines('\n')
f.writelines('Threat Campaign Enforcement Readiness Period' + ',' + staging_period_in_days + ' day')
f.writelines('\n')
f.writelines('\n')

f.writelines('URLs')
f.writelines('\n')
f.writelines('Learn New HTTP URLs' + ',' + learn_urls)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned HTTP URLs' + ',' + maximum_urls)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned HTTP URLs' + ',' + '-')
    f.writelines('\n')
f.writelines('Learn New WebSocket URLs' + ',' + learn_websocket_urls)
f.writelines('\n')
if learn_file_types != 'Never':
    f.writelines('Maximum Learned WebSocket URLs' + ',' + maximum_websocket_urls)
    f.writelines('\n')
else:
    f.writelines('Maximum Learned WebSocket URLs' + ',' + '-')
    f.writelines('\n')
f.writelines('Binary content found in text only WebSocket' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Binary content found in text only WebSocket')]))
f.writelines('\n')
f.writelines('Illegal URL' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal URL')]))
f.writelines('\n')
f.writelines('Illegal WebSocket binary message length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal WebSocket binary message length')]))
f.writelines('\n')
f.writelines('Illegal WebSocket extension' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal WebSocket extension')]))
f.writelines('\n')
f.writelines('Illegal WebSocket frame length' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal WebSocket frame length')]))
f.writelines('\n')
f.writelines('Illegal cross-origin request' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal cross-origin request')]))
f.writelines('\n')
f.writelines(
    'Illegal entry point' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal entry point')]))
f.writelines('\n')
f.writelines(
    'Illegal flow to URL' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('Illegal flow to URL')]))
f.writelines('\n')
f.writelines('Illegal meta character in URL' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal meta character in URL')]))
f.writelines('\n')
f.writelines('Illegal number of frames per message' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal number of frames per message')]))
f.writelines('\n')
f.writelines('Illegal number of mandatory parameters' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal number of mandatory parameters')]))
f.writelines('\n')
f.writelines('Illegal query string or POST data' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal query string or POST data')]))
f.writelines('\n')
f.writelines('Illegal request content type' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Illegal request content type')]))
f.writelines('\n')
f.writelines('Mandatory request body is missing' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Mandatory request body is missing')]))
f.writelines('\n')
f.writelines('Text content found in binary only WebSocket' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Text content found in binary only WebSocket')]))
f.writelines('\n')
f.writelines('Classify Request Content of Learned HTTP URLs' + ',' + classify_urls)
f.writelines('\n')
f.writelines('Classify Client Message Payload Format of Learned WebSocket URLs' + ',' + classify_websocket_urls)
f.writelines('\n')
f.writelines('Learn Allowed Methods on HTTP URLs' + ',' + set_method_override_on_url)
f.writelines('\n')
f.writelines('Collapse many common HTTP URLs into one wildcard HTTP URL after ' + collapse_urls_occurrences + ' occurences' + ',' + collapse_urls)
f.writelines('\n')
f.writelines('File types for which wildcard HTTP URLs will be configured' + ',' + 'shpongle'.join(url_filetypes))
f.writelines('\n')
f.writelines('\n')

f.writelines('WebSocket Protocol Compliance')
f.writelines('\n')
f.writelines('Bad WebSocket handshake request' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Bad WebSocket handshake request')]))
f.writelines('\n')
f.writelines('Failure in WebSocket framing protocol' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Failure in WebSocket framing protocol')]))
f.writelines('\n')
f.writelines('Mask not found in client frame' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Mask not found in client frame')]))
f.writelines('\n')
f.writelines('Null character found in WebSocket text message' + ',' + ','.join(
    policy_alarm_block_learn[policy_violations.index('Null character found in WebSocket text message')]))
f.writelines('\n')
f.writelines('\n')

# inheritance
inheritance_types = []
inheritance_parent_status = []
inheritance_child_status = []
for x in root.findall('sections'):
    for v in x.iter('section'):
        inheritance_types.append(v.get('type'))
    for y in x.iter('parent_inheritance_status'):
        inheritance_parent_status.append(y.text)
    for z in x.iter('child_inheritance_status'):
        inheritance_child_status.append(z.text)

f.writelines('Policy Section,Parent Inheritance Settings,Child Inheritance Settings,Comment')
f.writelines('\n')
for index, item in enumerate(inheritance_types):
    if inheritance_parent_status[index] == 'none':
        f.writelines(item + ',' + inheritance_parent_status[index] + ',' + 'Not Inherited' + ',')
    else:
        f.writelines(
            item + ',' + inheritance_parent_status[index] + ',' + inheritance_child_status[index] + ',')
    f.writelines('\n')
f.writelines('\n')

# list of fields for resulting table
parameters_table_list = ['Parameter Name', 'Is Mandatory Parameter', 'Allow Empty Value', 'Parameter Value Type',
                         'Minimum Length', 'Maximum Length', 'Mask Value in Logs',
                         'Check characters on this parameter name',
                         'Check characters on this parameter value',
                         'Check attack signatures and threat campaigns on this parameter',
                         'Allow Repeated Occurrences', 'Base64 Decoding', 'Allowed Meta Characters',
                         'Disabled Attack Signatures', 'Data Type', 'Parameter Type']

# define list for each useful field for XML
parameter_name = []  # Parameter Name
parameter_type = []  # Parameter Type
parameter_is_mandatory = []  # Is Mandatory Parameter
parameter_allow_empty_value = []  # Allow Empty Value
parameter_value_type = []  # Parameter Value Type
parameter_minimum_length = []  # Minimum Length
parameter_is_sensitive = []  # Mask Value in Logs
parameter_maximum_length = []  # Maximum Length
parameter_parameter_name_metachars = []  # Check characters on this parameter name
parameter_check_metachars = []  # Check characters on this parameter value
parameter_check_attack_signatures = []  # Check attack signatures and threat campaigns on this parameter
parameter_allow_repeated_parameter_name = []  # Allow Repeated Occurrences
parameter_is_base64 = []  # Base64 Decoding
parameter_disabled_metachar = []  # Allowed Meta Characters
parameter_disabled_signatures = []  # Disabled Attack Signatures
parameter_data_type = []  # Data Type
# parse "parameters" section, choose only important parameters
for x in root.iter('parameter'):
    parameter_name.append(x.attrib['name'])
    parameter_type.append(x.attrib['type'])
    # location =x.find('location').text
    parameter_is_mandatory.append(x.find('is_mandatory').text)
    parameter_allow_empty_value.append(x.find('allow_empty_value').text)
    parameter_value_type.append(x.find('value_type').text)
    # user_input_format = x.find('user_input_format').text
    # parameter_data_type.append(x.find('user_input_format').text)
    if x.attrib['type'] != 'wildcard':
         if x.find('user_input_format') != None:
            temp = x.find('user_input_format').text
            if temp == 'binary':
                parameter_data_type.append('File Upload')
            else:
                parameter_data_type.append('Alpha-Numeric')
         else:
             parameter_data_type.append('Ignore value')
    else:
        parameter_data_type.append('-')
    # minimum_value = x.find('minimum_value').text
    # maximum_value = x.find('maximum_value').text
    if x.find('minimum_length').text == '0':
        parameter_minimum_length.append('Any')
    # maximum_length = x.find('maximum_length').text
    # is_header = x.find('is_header').text
    # is_cookie = x.find('is_cookie').text
    # match_regular_expression = x.find('match_regular_expression').text
    parameter_is_sensitive.append(x.find('is_sensitive').text)
    if x.find('check_maximum_length').text == 'false':
        parameter_maximum_length.append('Any')
    else:
        parameter_maximum_length.append(x.find('maximum_length').text)
    # check_minimum_length = x.find('check_minimum_length').text
    # check_maximum_value = x.find('check_maximum_value').text
    # check_minimum_value = x.find('check_minimum_value').text
    parameter_parameter_name_metachars.append(x.find('parameter_name_metachars').find('check_metachars').text)
    parameter_check_metachars.append(x.find('check_metachars').text)
    parameter_check_attack_signatures.append(x.find('check_attack_signatures').text)
    parameter_allow_repeated_parameter_name.append(x.find('allow_repeated_parameter_name').text)
    # disallow_file_upload_of_executables = x.find('disallow_file_upload_of_executables').text
    parameter_is_base64.append(x.find('is_base64').text)
    # nested key in this section
    disabled_metachar_local = []
    for y in x.findall('metachar'):
        temp = y.get('character')
        temp = temp.split("0x", 1)[1]
        disabled_metachar_local.append(func_module.ascii_dict(temp))
    parameter_disabled_metachar.append('shpongle'.join(disabled_metachar_local))
    # nested key in this section
    disabled_signatures_local = []
    for y in x.findall('attack_signature'):
        temp = y.get('sig_id')
        disabled_signatures_local.append(temp)
    parameter_disabled_signatures.append('shpongle'.join(disabled_signatures_local))


f.writelines('###Параметры###')
f.writelines('\n')
f.writelines('Параметр,Значение,Комментарий')
f.writelines('\n')
for index, item in enumerate(parameter_name):
    f.writelines(parameters_table_list[0] + ',' + item + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[15] + ',' + parameter_type[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[1] + ',' + parameter_is_mandatory[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[2] + ',' + parameter_allow_empty_value[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[3] + ',' + parameter_value_type[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[14] + ',' + parameter_data_type[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[4] + ',' + parameter_minimum_length[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[5] + ',' + parameter_minimum_length[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[6] + ',' + parameter_is_sensitive[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[7] + ',' + parameter_parameter_name_metachars[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[8] + ',' + parameter_check_metachars[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[9] + ',' + parameter_check_attack_signatures[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[10] + ',' + parameter_allow_repeated_parameter_name[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[11] + ',' + parameter_is_base64[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[12] + ',' + parameter_disabled_metachar[index] + ',')
    f.writelines('\n')
    f.writelines(parameters_table_list[13] + ',' + parameter_disabled_signatures[index] + ',')
    f.writelines('\n')
    f.writelines('\n')

# Now let's export allowed and disalowed file types
files_table_list = ['File Type', 'URL Length', 'Request Length', 'Query String Length', 'POST Data Length',
                    'Apply Response Signatures']

allowed_file_type = []
file_url_length = []
file_request_length = []
file_query_string_length = []
file_post_data_length = []
file_check_response = []

for x in root.iter("file_types"):
    for y in x.findall('file_type'):
        allowed_file_type.append(y.get('name'))
        if y.find('check_url_length').text == 'false':
            file_url_length.append('Any')
        else:
            file_url_length.append(y.find('url_length').text)
        if y.find('check_request_length').text == 'false':
            file_request_length.append('Any')
        else:
            file_request_length.append(y.find('request_length').text)
        if y.find('check_query_string_length').text == 'false':
            file_query_string_length.append('Any')
        else:
            file_query_string_length.append(y.find('query_string_length').text)
        if y.find('check_post_data_length').text == 'false':
            file_post_data_length.append('Any')
        else:
            file_post_data_length.append(y.find('post_data_length').text)
        file_check_response.append(y.find('check_response').text)

# write results in the file in csv-like format
for item in files_table_list:
    f.writelines(item + ',')
f.writelines('\n')

for index, item in enumerate(allowed_file_type):
    f.writelines(
        item + ',' + file_url_length[index] + ',' + file_request_length[index] + ',' + file_query_string_length[
            index] + ',' + file_post_data_length[index] + ',' + file_check_response[index])
    f.writelines('\n')
f.writelines('\n')

disallowed_file_type = []
for x in root.iter("disallowed_file_types"):
    for y in x.findall('file_type'):
        disallowed_file_type.append(y.get('name'))
f.writelines('Disallowed File Types' + ',' + 'shpongle'.join(disallowed_file_type))
f.writelines('\n')
f.writelines('\n')

# Now let's export URLs
urls_table_list = ['URL Name', 'URL Type', 'Clickjacking Protection', 'Check Flows to this URL', 'URL is Entry Point',
                   'URL is Referrer', 'URL can change Domain Cookie', 'Body is Mandatory',
                   'Wildcard Match Includes Slashes', 'Check attack signatures and threat campaigns on this URL',
                   'Check characters on this URL', 'Method Enforcement', 'Disabled Attack Signatures']

url_name = []
url_type = []
url_protocol = []
url_method = []
url_clickjacking_protection = []
url_check_flows = []
url_is_entry_point = []
url_is_referrer = []
url_can_change_domain_cookie = []
url_flg_wildcard_includes_slash = []
url_check_methods = []
url_check_metachars = []
url_mandatory_body = []
url_check_attack_signatures = []
url_disallowed_metachars = []
disabled_metachar_local = []
disabled_signatures_local = []
url_disabled_signatures = []

for x in root.iter('urls'):
    for z in root.iter('clickjacking_protection'):
        url_clickjacking_protection.append(z.find('enabled').text)
    for y in x.findall('url'):
        url_name.append(y.get('name'))
        url_type.append(y.get('type'))
        url_protocol.append(y.get('protocol'))
        url_method.append(y.get('method'))

        url_check_methods.append(y.find('check_methods').text)
        url_check_metachars.append(y.find('check_metachars').text)
        url_mandatory_body.append(y.find('mandatory_body').text)
        url_check_attack_signatures.append(y.find('check_attack_signatures').text)

        if y.get('type') == 'wildcard':
            url_flg_wildcard_includes_slash.append(y.find('flg_wildcard_includes_slash').text)
            url_check_flows.append('-')
            url_is_entry_point.append('-')
            url_is_referrer.append('-')
            url_can_change_domain_cookie.append('-')
        else:
            url_flg_wildcard_includes_slash.append('-')
            url_check_flows.append(y.find('check_flows').text)
            if y.find('check_flows').text == 'true':
                url_is_entry_point.append(y.find('is_entry_point').text)
                url_is_referrer.append(y.find('is_referrer').text)
                url_can_change_domain_cookie.append(y.find('can_change_domain_cookie').text)
            else:
                url_is_entry_point.append('-')
                url_is_referrer.append('-')
                url_can_change_domain_cookie.append('-')
        disabled_signatures_local = []
        for z in y.findall('attack_signature'):
            temp = z.get('sig_id')
            disabled_signatures_local.append(temp)
        url_disabled_signatures.append('shpongle'.join(disabled_signatures_local))

f.writelines('###URLs###')
f.writelines('\n')
f.writelines('Параметр,Значение,Комментарий')
f.writelines('\n')
# write results to file in csv-like format
for index, item in enumerate(url_name):
    f.writelines(urls_table_list[0] + ',' + 'Protocol: ' + url_protocol[index] + 'shpongle' + 'Methods: ' + url_method[
        index] + 'shpongle' + 'URL: ' + item + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[1] + ',' + url_type[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[2] + ',' + url_clickjacking_protection[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[3] + ',' + url_check_flows[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[4] + ',' + url_is_entry_point[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[5] + ',' + url_is_referrer[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[6] + ',' + url_can_change_domain_cookie[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[7] + ',' + url_mandatory_body[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[8] + ',' + url_flg_wildcard_includes_slash[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[9] + ',' + url_check_attack_signatures[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[10] + ',' + url_check_metachars[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[11] + ',' + url_check_methods[index] + ',')
    f.writelines('\n')
    f.writelines(urls_table_list[12] + ',' + url_disabled_signatures[index] + ',')
    f.writelines('\n')
    f.writelines('\n')
f.writelines('\n')

# Now let's export cookies
cookies_table_list = ['Cookie Name', 'Cookie Type', 'Perform Staging', 'Insert HttpOnly attribute', 'Insert SameSite attribute',
                   'Insert Secure attribute', 'Base64 Decoding', 'Mask Value in Logs', 'Check attack signatures and threat campaigns on this cookie', 'Disabled Attack Signatures']
cookie_name = []
cookie_type = []
cookie_in_staging = []
cookie_enforcement_mode = []
cookie_http_only = []
cookie_secure = []
cookie_check_signatures = []
cookie_is_base64 = []
cookie_mask_value = []
cookie_same_site_attribute = []
cookie_disabled_signatures = []
disabled_signatures_local = []

for x in root.iter('headers'):
    for y in x.findall('allowed_modified_cookie'):
        cookie_name.append(y.get('name'))
        cookie_type.append(y.get('type'))
        cookie_in_staging.append(y.find('in_staging').text)
        cookie_enforcement_mode.append(y.find('enforcement_mode').text)
        cookie_http_only.append(y.find('http_only').text)
        cookie_secure.append(y.find('secure').text)
        cookie_check_signatures.append(y.find('check_signatures').text)
        cookie_is_base64.append(y.find('is_base64').text)
        cookie_mask_value.append(y.find('mask_value').text)
        cookie_same_site_attribute.append(y.find('same_site_attribute').text)
        disabled_signatures_local = []
        for z in y.findall('attack_signature'):
            temp = z.get('sig_id')
            disabled_signatures_local.append(temp)
        cookie_disabled_signatures.append('shpongle'.join(disabled_signatures_local))

f.writelines('###Cookies###')
f.writelines('\n')
f.writelines('Параметр,Значение,Комментарий')
f.writelines('\n')
# write results to file in csv-like format
for index, item in enumerate(cookie_name):
    f.writelines(cookies_table_list[0] + ',' + item + 'shpongle' + cookie_type[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[1] + ',' + cookie_enforcement_mode[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[2] + ',' + cookie_in_staging[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[3] + ',' + cookie_http_only[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[4] + ',' + cookie_same_site_attribute[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[5] + ',' + cookie_secure[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[6] + ',' + cookie_is_base64[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[7] + ',' + cookie_mask_value[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[8] + ',' + cookie_check_signatures[index] + ',')
    f.writelines('\n')
    f.writelines(cookies_table_list[9] + ',' + cookie_disabled_signatures[index] + ',')
    f.writelines('\n')
    f.writelines('\n')


f.writelines('\n')


headers_name = []
headers_type = []
headers_is_mandatory = []
headers_check_signatures = []
headers_is_base64 = []
headers_percent_normalization = []
headers_uri_normalization = []
headers_html_normalization = []
headers_is_default = []
headers_mask_value = []
headers_normalization_settings = []
headers_disabled_signatures = []
disabled_signatures_local = []


for y in root.findall('header'):
    headers_name.append(y.get('name'))
    headers_type.append(y.get('type'))
    headers_is_mandatory.append(y.find('is_mandatory').text)
    headers_check_signatures.append(y.find('check_signatures').text)
    headers_is_base64.append(y.find('is_base64').text)
    headers_is_default.append(y.find('is_default').text)
    headers_mask_value.append(y.find('mask_value').text)

    headers_normalization_settings_temp = ''
    if y.find('percent_normalization').text == 'true':
        headers_normalization_settings_temp += 'Percent Decodingshpongle'
    if y.find('uri_normalization').text == 'true':
        headers_normalization_settings_temp += 'Url Normalizationshpongle'
    if y.find('html_normalization').text == 'true':
        headers_normalization_settings_temp += 'HTML Normalizationshpongle'
    headers_normalization_settings.append(headers_normalization_settings_temp)
    disabled_signatures_local = []
    for z in y.findall('attack_signature'):
        temp = z.get('sig_id')
        disabled_signatures_local.append(temp)
    headers_disabled_signatures.append('shpongle'.join(disabled_signatures_local))

# list of fields for resulting table
headers_table_list = ['Header Name', 'Type', 'Default Header', 'Mandatory', 'Check Attack Signatures and Threat Campaigns',
                         'Base64 Decoding', 'Normalization Settings', 'Evasion Techniques Violations',
                         'Mask Value in Logs', 'Disabled Attack Signatures']
f.writelines('###Заголовки###')
f.writelines('\n')
f.writelines('Параметр,Значение,Комментарий')
f.writelines('\n')
for index, item in enumerate(headers_name):
    f.writelines(headers_table_list[0] + ',' + item + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[1] + ',' + headers_type[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[2] + ',' + headers_is_default[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[3] + ',' + headers_is_mandatory[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[4] + ',' + headers_check_signatures[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[5] + ',' + headers_is_base64[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[6] + ',' + headers_normalization_settings[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[7] + ',' + ' ' + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[8] + ',' + headers_mask_value[index] + ',')
    f.writelines('\n')
    f.writelines(headers_table_list[9] + ',' + headers_disabled_signatures[index] + ',')
    f.writelines('\n')
    f.writelines('\n')