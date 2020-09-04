import xml.etree.ElementTree as ET

# Conver 0xNN format numbers to human-readable ASCII-symbols
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

# list of fields for resulting table
parameters_table_list = ['Parameter Name', 'Is Mandatory Parameter', 'Allow Empty Value', 'Parameter Value Type', 'Minimum Length', 'Maximum Length', 'Mask Value in Logs', 'Check characters on this', 'parameter value', 'Check attack signatures and threat campaigns on this parameter', 'Allow Repeated Occurrences', 'Base64 Decoding', 'Allowed Meta Characters', 'Disabled Attack Signatures']

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

# parse "parameters" section, choose only important parameters
for x in root.iter("parameter"):
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
    disabled_metachar_local = []
    for y in x.findall('metachar'):
        temp = y.get('character')
        temp = temp.split("0x", 1)[1]
        disabled_metachar_local.append(ascii_dict(temp))
    parameter_disabled_metachar.append('shpongle'.join(disabled_metachar_local))
    disabled_signatures_local = []
    for y in x.findall('attack_signature'):
        temp = y.get('sig_id')
        disabled_signatures_local.append(temp)
    parameter_disabled_signatures.append('shpongle'.join(disabled_signatures_local))

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

lenght = len(parameter_name)
i=0
while i < lenght:
    f.writelines(parameters_table_list[0] + ',' + parameter_name[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[1] + ',' + parameter_is_mandatory[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[2] + ',' + parameter_allow_empty_value[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[3] + ',' + parameter_value_type[i])
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

files_table_list = ['File Type', 'URL Length', 'Request Length', 'Query String Length', 'POST Data Length', 'Apply Response Signatures']

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

lenght = len(allowed_file_type)
i=0
while i < lenght:
    f.writelines(files_table_list[0] + ',' + allowed_file_type[i])
    f.writelines('\n')
    f.writelines(files_table_list[1] + ',' + file_url_length[i])
    f.writelines('\n')
    f.writelines(files_table_list[2] + ',' + file_request_length[i])
    f.writelines('\n')
    f.writelines(files_table_list[3] + ',' + file_query_string_length[i])
    f.writelines('\n')
    f.writelines(files_table_list[4] + ',' + file_post_data_length[i])
    f.writelines('\n')
    f.writelines(files_table_list[5] + ',' + file_check_response[i])
    f.writelines('\n')
    f.writelines('\n')
    i += 1

disallowed_file_type = []
for x in root.iter("disallowed_file_types"):
    for y in x.findall('file_type'):
        disallowed_file_type.append(y.get('name'))
f.writelines('Disallowed File Types' + ',' + 'shpongle'.join(disallowed_file_type))