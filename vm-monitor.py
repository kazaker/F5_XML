import json
import requests
import re
import time
from shutil import copyfile

vm = [{'name': 'vm1', 'status': 'POWERED_ON', 'previous_status': 'POWERED_ON', 'monitoring_started': 1601510400, 'inactivity_period': 0, 'inactive_too_long': False, 'vm_exists': True},
      {'name': 'vm2', 'status': 'POWERED_OFF', 'previous_status': 'POWERED_OFF', 'monitoring_started': 1601510400, 'inactivity_period': 0, 'inactive_too_long': False, 'vm_exists': True}]  # 1601510400 in epoch -  01 Oct 2020 00:00:00 GMT
fields = ['name', 'status', 'previous_status', 'monitoring_started', 'inactivity_period', 'inactive_too_long', 'vm_exists']
choice = input("Please choose starting mode:\nSelect 1 to start a clear run.\nSelect 2 to restore data from previous run.\n")
while True:
    if choice == '1':
        break
    elif choice == '2':
        filein = open('vm_status.txt', "r")
        data = filein.readlines()
        # Create the table's row data
        for line in data[2:]:
            temp_dict = {}
            row = line.split("#")
            for item in fields:
                temp_dict[item] = row[fields.index(item)]
            vm.append(temp_dict)
        break
    else:
        choice = input("Please choose starting mode:\nSelect 1 to start a clear run.\nSelect 2 to restore data from previous run.\n")



while True:
    copyfile('vm_status.txt', 'vm_status.txt.back')
    for x in vm:
        x['vm_exists'] = False
    auth_url = "https://10.31.32.10/rest/com/vmware/cis/session"

    auth_payload = {}
    auth_headers = {'Authorization': 'Basic YXkubWFydXNvdkB2c3BoZXJlLmxvY2FsOm9jYXAyVUJ1'}

    auth_response = requests.request("POST", auth_url, headers=auth_headers, data=auth_payload, verify=False)

    print(auth_response.text)
    find_api_key = re.compile('(?P<trash>{\"value\":\")(?P<value>[a-z0-9]+)(?P<also_trash>\"})')
    api_key = re.match(find_api_key, auth_response.text).group('value')

    status_url = 'https://10.31.32.10/rest/vcenter/vm'
    status_headers = {'vmware-api-session-id': api_key}

    status_response = requests.request("GET", status_url, headers=status_headers, verify=False)

    data = json.loads(status_response.text)
    # with open("vms.txt") as json_file:
    #    data = json.load(json_file)

    # i = 0
    # while i < len(data['value']):
    #     print(data['value'][i]['name'], data['value'][i]['power_state'], sep='#')
    #     print('\n')
    #     i += 1

    f = open('vm_status.txt', 'w')
    f.writelines(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
    f.writelines('\n')
    f.writelines('VM Name#Current Status#Previous Status#Powered off at#Powered off for#Warning (>30 days)#vm_exists')
    f.writelines('\n')
    i = 0
    while i < len(data['value']):
        name = data['value'][i]['name']
        state = data['value'][i]['power_state']
        i += 1
        flag = 0
        for x in vm:
            if name == x.get('name'):
                x['status'] = state
                x['vm_exists'] = True
                flag = 0
                break
            else:
                flag = 1
        if flag == 1:
            vm.append({'name': name, 'status': state,
                   'previous_status': 'POWERED_OFF', 'monitoring_started': time.time(), 'inactivity_period': 0, 'inactive_too_long': False, 'vm_exists': True})
    for x in vm:
        if x['vm_exists'] == False:
            vm.remove(x)
    for x in vm:
        if x['status'] == 'POWERED_ON':
            if x['previous_status'] == 'POWERED_ON':
                x['inactivity_period'] = 0
                x['previous_status'] = x['status']
                x['inactive_too_long'] = False
                continue
            if x['previous_status'] == 'POWERED_OFF':
                x['inactivity_period'] = 0
                x['monitoring_started'] = 0
                x['previous_status'] = x['status']
                x['inactive_too_long'] = False
                continue
        if x['status'] == 'POWERED_OFF':
            if x['previous_status'] == 'POWERED_ON':
                x['monitoring_started'] = time.time()
                x['previous_status'] = x['status']
                continue
            if x['previous_status'] == 'POWERED_OFF':
                x['inactivity_period'] = time.time() - float(x['monitoring_started'])
                x['previous_status'] = x['status']
                if x['inactivity_period'] > 2592000:
                    x['inactive_too_long'] = True
                continue
    for x in vm:
        f.writelines(x.get('name') + '#' + x.get('status') + '#' + x.get('previous_status') + '#' + str(x.get('monitoring_started')) + '#' + str(x.get('inactivity_period')) + '#' + str(x.get('inactive_too_long'))+ '#' + str(x.get('vm_exists')))
        f.writelines('\n')

    f.close()

    filein = open('vm_status.txt', "r")
    fileout = open("html-table.html", "w")
    data = filein.readlines()

    table = "<table>\n"

    # Create the table's column headers
    header = data[1].split("#")
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"

    # Create the table's row data
    for line in data[2:]:
        row = line.split("#")
        table += "  <tr>\n"
        for column in row:
            table += "    <td>{0}</td>\n".format(column.strip())
        table += "  </tr>\n"

    table += "</table>"

    fileout.writelines(table)
    fileout.close()
    filein.close()
    time.sleep(30)