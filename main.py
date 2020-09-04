import xml.etree.ElementTree as ET


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
parameters_table_header = "Parameter Name, Parameter Level, Is Mandatory Parameter, Allow Empty Value, Parameter Value Type, " \
       "Minimum Length, Maximum Length, Mask Value in Logs, Check characters on this " \
       "parameter value, Check attack signatures and threat campaigns on this parameter, Allow Repeated Occurrences, " \
       "Base64 Decoding, Allowed Meta Characters, Disabled Attack Signatures\n"
f.writelines(parameters_table_header)
print(parameters_table_header)
for x in root.iter("parameter"):
    name = x.attrib['name']
    # location =x.find('location').text
    is_mandatory = x.find('is_mandatory').text
    allow_empty_value = x.find('allow_empty_value').text
    value_type = x.find('value_type').text
    # user_input_format = x.find('user_input_format').text
    # minimum_value = x.find('minimum_value').text
    # maximum_value = x.find('maximum_value').text
    if x.find('minimum_length').text == '0':
        minimum_length = 'Any'
    # maximum_length = x.find('maximum_length').text
    # is_header = x.find('is_header').text
    # is_cookie = x.find('is_cookie').text
    # match_regular_expression = x.find('match_regular_expression').text
    is_sensitive = x.find('is_sensitive').text
    if x.find('check_maximum_length').text == 'false':
        maximum_length = 'Any'
    else:
        maximum_length = x.find('maximum_length').text
    # check_minimum_length = x.find('check_minimum_length').text
    # check_maximum_value = x.find('check_maximum_value').text
    # check_minimum_value = x.find('check_minimum_value').text
    parameter_name_metachars = x.find('parameter_name_metachars').find('check_metachars').text
    check_metachars = x.find('check_metachars').text
    check_attack_signatures = x.find('check_attack_signatures').text
    allow_repeated_parameter_name = x.find('allow_repeated_parameter_name').text
    # disallow_file_upload_of_executables = x.find('disallow_file_upload_of_executables').text
    is_base64 = x.find('is_base64').text
    disabled_metachar = []
    for y in x.findall('metachar'):
        temp = y.get('character')
        temp = temp.split("0x", 1)[1]
#         print(temp)
#         print(ascii_dict(temp))
        disabled_metachar.append(ascii_dict(temp))
    meta = 'halo'.join(disabled_metachar)
    disabled_signatures = []
    for y in x.findall('attack_signature'):
        temp = y.get('sig_id')
        disabled_signatures.append(temp)
    sign = 'halo'.join(disabled_signatures)
    str1 = str(name) + ',' + 'Global' + ',' + str(is_mandatory) + ',' + str(allow_empty_value) + ',' + str(
        value_type) + ',' + str(minimum_length) + ',' + str(maximum_length) + ',' + str(is_sensitive) + ',' + str(check_metachars) + ',' + str(check_attack_signatures) + ',' + str(
        allow_repeated_parameter_name) + ',' + str(is_base64) + ',' + str(meta) + ',' + str(sign) + str('\n')
    f.writelines(str1)
    #print(parameter_name_metachars)