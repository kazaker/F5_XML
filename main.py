import xml.etree.ElementTree as ET


# Convert 0xNN format numbers to human-readable ASCII-symbols
def ascii_dict(i):
    if i == 'a':
        return 'LF'
    if i == 'd':
        return 'CR'
    if i == '9':
        return 'TAB'
    if i == '1':
        return 'SOH'
    return bytes.fromhex(i).decode('utf-8')


# path to XML configure from F5
tree = ET.parse('C:/Users/MAY/PycharmProjects/XML/data.xml')
root = tree.getroot()
# path to result csv
f = open('C:/Users/MAY/PycharmProjects/XML/result.txt', 'w')

policy_table_list = ['Policy Name', 'Description', 'Policy Type', 'Parent Policy', 'Policy Template', 'Application Language', 'Enforcement Mode', 'Policy Building Learning Mode', '', 'Enforcement Readiness Period', 'Server Technologies', 'Policy is Case Sensitive', 'Event Correlation Reporting', 'Mask Credit Card Numbers in Request Log', 'Maximum HTTP Header Length', 'Maximum Cookie Header Length', 'Allowed Response Status Codes', 'Trigger ASM iRule Events Mode', 'Trust XFF Header', 'Handle Path Parameters']

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

# inheritance
policy_inheritance_types = []
policy_parent_inheritance_status = []
policy_child_inheritance_status = []
for x in root.findall('sections'):
    for v in x.iter('section'):
        policy_inheritance_types.append(v.get('type'))
    for y in x.iter('parent_inheritance_status'):
        policy_parent_inheritance_status.append(y.text)
    for z in x.iter('child_inheritance_status'):
        policy_child_inheritance_status.append(z.text)

# blocking
policy_violations = []
policy_alarm_block_learn = []
for x in root.iter('blocking'):
    policy_enforcement_mode = x.find('enforcement_mode').text  # Enforcement Mode
    policy_passive_mode = x.find('passive_mode').text
    for y in x.iter('violation'):
        temp = []
        policy_violations.append(y.get('name'))
        for z in y.findall('alarm'):
            temp.append(z.text)
        for z in y.findall('block'):
            temp.append(z.text)
        for z in y.findall('learn'):
            temp.append(z.text)
        policy_alarm_block_learn.append(temp)

policy_encoding = root.find('encoding').text  # Policy Name
policy_description = root.find('description').text  # Description
policy_type = root.find('type').text  # Policy Type
policy_encoding = root.find('encoding').text  # Application Language
policy_parent_policy_name = root.find('parent_policy_name').text  # Parent Policy
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
    if x.find('dynamic_session_id_in_url'):   # Dynamic Session ID in URL
        policy_dynamic_session_id_in_url = 'true'
    else:
        policy_dynamic_session_id_in_url = 'false'

for x in root.iter('policy_builder'):
    policy_learning_mode = x.find('learning_mode').text  # Policy Building Learning Mode

for x in root.iter('header_settings'):
    policy_maximum_http_length = x.find('maximum_http_length').text  # Maximum HTTP Header Length

for x in root.iter('cookie_settings'):
    policy_maximum_cookie_length = x.find('maximum_cookie_length').text  # Maximum Cookie Header Length

# list of fields for resulting table
parameters_table_list = ['Parameter Name', 'Is Mandatory Parameter', 'Allow Empty Value', 'Parameter Value Type',
                         'Minimum Length', 'Maximum Length', 'Mask Value in Logs', 'Check characters on this parameter name',
                         'Check characters on this parameter value', 'Check attack signatures and threat campaigns on this parameter',
                         'Allow Repeated Occurrences', 'Base64 Decoding', 'Allowed Meta Characters',
                         'Disabled Attack Signatures', 'Data Type']

# define list for each useful field for XML
parameter_name = []
parameter_is_mandatory = []
parameter_allow_empty_value = []
parameter_value_type = []
parameter_minimum_length = []
parameter_is_sensitive = []
parameter_maximum_length = []
parameter_parameter_name_metachars = []
parameter_check_metachars = []
parameter_check_attack_signatures = []
parameter_allow_repeated_parameter_name = []
parameter_is_base64 = []
parameter_disabled_metachar = []
parameter_disabled_signatures = []
parameter_data_type = []
# parse "parameters" section, choose only important parameters
for x in root.iter('parameter'):
    parameter_name.append(x.attrib['name'])
    # location =x.find('location').text
    parameter_is_mandatory.append(x.find('is_mandatory').text)
    parameter_allow_empty_value.append(x.find('allow_empty_value').text)
    parameter_value_type.append(x.find('value_type').text)
    # user_input_format = x.find('user_input_format').text
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
        disabled_metachar_local.append(ascii_dict(temp))
    parameter_disabled_metachar.append('shpongle'.join(disabled_metachar_local))
    # nested key in this section
    disabled_signatures_local = []
    for y in x.findall('attack_signature'):
        temp = y.get('sig_id')
        disabled_signatures_local.append(temp)
    parameter_disabled_signatures.append('shpongle'.join(disabled_signatures_local))
    temp = x.find('user_input_format').text
    if temp == 'binary':
        parameter_data_type.append('File Upload')
    else:
        parameter_data_type.append('Alpha-Numeric')

# print(parameters_table_list[0] + ',' + ','.join(name))
# print(parameters_table_list[1] + ',' + ','.join(is_mandatory))
# print(parameters_table_list[2] + ',' + ','.join(allow_empty_value))
# print(parameters_table_list[3] + ',' + ','.join(value_type))
# print(parameters_table_list[4] + ',' + ','.join(minimum_length))
# print(parameters_table_list[5] + ',' + ','.join(is_sensitive))
# print(parameters_table_list[6] + ',' + ','.join(maximum_length))
# print(parameters_table_list[7] + ',' + ','.join(parameter_name_metachars))
# print(parameters_table_list[8] + ',' + ','.join(check_metachars))
# print(parameters_table_list[9] + ',' + ','.join(check_attack_signatures))
# print(parameters_table_list[10] + ',' + ','.join(allow_repeated_parameter_name))
# print(parameters_table_list[11] + ',' + ','.join(is_base64))
# print(parameters_table_list[13] + ',' + crap)

# write results to file in csv-like format
length = len(parameter_name)
i = 0
while i < length:
    f.writelines(parameters_table_list[0] + ',' + parameter_name[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[1] + ',' + parameter_is_mandatory[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[2] + ',' + parameter_allow_empty_value[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[3] + ',' + parameter_value_type[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[14] + ',' + parameter_data_type[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[4] + ',' + parameter_minimum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[5] + ',' + parameter_minimum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[6] + ',' + parameter_maximum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[7] + ',' + parameter_parameter_name_metachars[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[8] + ',' + parameter_check_metachars[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[9] + ',' + parameter_check_attack_signatures[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[10] + ',' + parameter_allow_repeated_parameter_name[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[11] + ',' + parameter_is_base64[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[12] + ',' + parameter_disabled_metachar[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[13] + ',' + parameter_disabled_signatures[i])
    f.writelines('\n')
    f.writelines('\n')
    i += 1

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

# lenght = len(allowed_file_type)
# i=0
# while i < lenght:
#     f.writelines(files_table_list[0] + ',' + allowed_file_type[i])
#     f.writelines('\n')
#     f.writelines(files_table_list[1] + ',' + file_url_length[i])
#     f.writelines('\n')
#     f.writelines(files_table_list[2] + ',' + file_request_length[i])
#     f.writelines('\n')
#     f.writelines(files_table_list[3] + ',' + file_query_string_length[i])
#     f.writelines('\n')
#     f.writelines(files_table_list[4] + ',' + file_post_data_length[i])
#     f.writelines('\n')
#     f.writelines(files_table_list[5] + ',' + file_check_response[i])
#     f.writelines('\n')
#     f.writelines('\n')
#     i += 1

# write results in the file in csv-like format
for i in files_table_list:
    f.writelines(i + ',')
f.writelines('\n')

length = len(allowed_file_type)
i = 0
while i < length:
    f.writelines(
        allowed_file_type[i] + ',' + file_url_length[i] + ',' + file_request_length[i] + ',' + file_query_string_length[
            i] + ',' + file_post_data_length[i] + ',' + file_check_response[i])
    f.writelines('\n')
    i += 1
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
                   'Check characters on this URL', 'Method Enforcement']

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

# write results to file in csv-like format
length = len(url_name)
i = 0
while i < length:
    f.writelines(urls_table_list[0] + ',' + 'Protocol: ' + url_protocol[i] + 'shpongle' + 'Methods: ' + url_method[
        i] + 'shpongle' + 'URL: ' + url_name[i])
    f.writelines('\n')
    f.writelines(urls_table_list[1] + ',' + url_type[i])
    f.writelines('\n')
    f.writelines(urls_table_list[2] + ',' + url_clickjacking_protection[i])
    f.writelines('\n')
    f.writelines(urls_table_list[3] + ',' + url_check_flows[i])
    f.writelines('\n')
    f.writelines(urls_table_list[4] + ',' + url_is_entry_point[i])
    f.writelines('\n')
    f.writelines(urls_table_list[5] + ',' + url_is_referrer[i])
    f.writelines('\n')
    f.writelines(urls_table_list[6] + ',' + url_can_change_domain_cookie[i])
    f.writelines('\n')
    f.writelines(urls_table_list[7] + ',' + url_mandatory_body[i])
    f.writelines('\n')
    f.writelines(urls_table_list[8] + ',' + url_flg_wildcard_includes_slash[i])
    f.writelines('\n')
    f.writelines(urls_table_list[9] + ',' + url_check_attack_signatures[i])
    f.writelines('\n')
    f.writelines(urls_table_list[10] + ',' + url_check_metachars[i])
    f.writelines('\n')
    f.writelines(urls_table_list[11] + ',' + url_check_methods[i])
    f.writelines('\n')
    f.writelines('\n')
    i += 1
