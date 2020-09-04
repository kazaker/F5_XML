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
name = []
is_mandatory = []
allow_empty_value = []
value_type = []
minimum_length = []
is_sensitive = []
maximum_length = []
parameter_name_metachars = []
check_metachars = []
check_attack_signatures = []
allow_repeated_parameter_name = []
is_base64 = []
disabled_metachar = []
disabled_signatures = []

# parse "parameters" section, choose only important parameters
for x in root.iter("parameter"):
    name.append(x.attrib['name'])
    # location =x.find('location').text
    is_mandatory.append(x.find('is_mandatory').text)
    allow_empty_value.append(x.find('allow_empty_value').text)
    value_type.append(x.find('value_type').text)
    # user_input_format = x.find('user_input_format').text
    # minimum_value = x.find('minimum_value').text
    # maximum_value = x.find('maximum_value').text
    if x.find('minimum_length').text == '0':
        minimum_length.append('Any')
    # maximum_length = x.find('maximum_length').text
    # is_header = x.find('is_header').text
    # is_cookie = x.find('is_cookie').text
    # match_regular_expression = x.find('match_regular_expression').text
    is_sensitive.append(x.find('is_sensitive').text)
    if x.find('check_maximum_length').text == 'false':
        maximum_length.append('Any')
    else:
        maximum_length.append(x.find('maximum_length').text)
    # check_minimum_length = x.find('check_minimum_length').text
    # check_maximum_value = x.find('check_maximum_value').text
    # check_minimum_value = x.find('check_minimum_value').text
    parameter_name_metachars.append(x.find('parameter_name_metachars').find('check_metachars').text)
    check_metachars.append(x.find('check_metachars').text)
    check_attack_signatures.append(x.find('check_attack_signatures').text)
    allow_repeated_parameter_name.append(x.find('allow_repeated_parameter_name').text)
    # disallow_file_upload_of_executables = x.find('disallow_file_upload_of_executables').text
    is_base64.append(x.find('is_base64').text)
    disabled_metachar_local = []
    for y in x.findall('metachar'):
        temp = y.get('character')
        temp = temp.split("0x", 1)[1]
        disabled_metachar_local.append(ascii_dict(temp))
    disabled_metachar.append('halo'.join(disabled_metachar_local))
    disabled_signatures_local = []
    for y in x.findall('attack_signature'):
        temp = y.get('sig_id')
        disabled_signatures_local.append(temp)
    disabled_signatures.append('halo'.join(disabled_signatures_local))

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

lenght = len(name)
i=0
while i < lenght:
    f.writelines(parameters_table_list[0] + ',' + name[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[1] + ',' + is_mandatory[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[2] + ',' + allow_empty_value[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[3] + ',' + value_type[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[4] + ',' + minimum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[5] + ',' + minimum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[6] + ',' + maximum_length[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[7] + ',' + parameter_name_metachars[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[8] + ',' + check_metachars[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[9] + ',' + check_attack_signatures[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[10] + ',' + allow_repeated_parameter_name[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[11] + ',' + is_base64[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[12] + ',' + disabled_metachar[i])
    f.writelines('\n')
    f.writelines(parameters_table_list[13] + ',' + disabled_signatures[i])
    f.writelines('\n')
    f.writelines('\n')
    i += 1

file_type = []
for x in root.iter("disallowed_file_types"):
    for y in x.findall('file_type'):
        file_type.append(y.get('name'))
