# path to XML configure from F5
# source_file = 'C:/Users/MAY/PycharmProjects/XML/data.xml'
source_file = 'C:/Users/Cynic/PycharmProjects/F5_XML/data.xml'

# path to result csv
# result_file = 'C:/Users/MAY/PycharmProjects/XML/result.txt'
result_file = 'C:/Users/Cynic/PycharmProjects/F5_XML/result.txt'

# Extracted from XML (counting position from zero)
# 4. Web Services Security failure
# 7. Evasion technique detected
# 11. HTTP protocol compliance failed
policy_sections = ['Antivirus Protection', 'CSRF Protection', 'Content Profiles', 'Cookies', 'Data Guard', 'File Types', 'General Settings', 'Headers', 'IP Addresses and Geolocations', 'Parameters', 'Redirection Domains', 'Server Technologies' , 'Sessions and Logins', 'Threat Campaigns', 'URLs', 'WebSocket Protocol Compliance']
file_in = open("violations.txt")
file_out = open("test.txt", 'w')
violations = file_in.read().splitlines()
str = R"f.writelines('\n')"
for x in violations:
    file_out.writelines("f.writelines('" + x + "' + ',' + ','.join(policy_alarm_block_learn[policy_violations.index('" + x + "')]))")
    file_out.writelines('\n')
    file_out.writelines(str)
    file_out.writelines('\n')