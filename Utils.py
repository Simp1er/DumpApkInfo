# coding:utf-8

import re
import json




def calc_blank(line_data):
    i = 0
    for bit in line_data:
        if bit == ' ':
            i += 1
            continue
        else:
            break
    return i


def recursion(dic, index, data_list, list_length):
    for j in range(index +1,list_length):
        if data_list[j].strip().startswith('A:'):
            key_value = data_list[j][3:].split('=')
            dic[key_value[0]] = key_value[1].replace('\"', "")
        else:
            return dic


def parse_to_dict(data):
    result = {}
    # start, end = False, True
    first = True
    data = re.sub(u"\\(.*?\\)", "", data)
    # print(data)
    data_list = data.split('\n')
    list_length = len(data_list)
    for i in range(0, list_length):
        data_list[i] = data_list[i].strip()
    all_dict = []
    # tmp = 0
    for i in range(0, list_length):
        if data_list[i].startswith('E:'):
            dic = {data_list[i][3:]: {}}
            for j in range(i+1, list_length):
                if data_list[j].startswith('A:'):
                    key_value = data_list[j][3:].split('=')
                    dic[data_list[i][3:]][key_value[0]] = key_value[1].replace('\"', "")
                    # tmp = j
                    continue
                else:
                    all_dict.append(dic)
                    break
    return all_dict





def parse_xml(data):
    #print(data)
    result = parse_to_dict(data)
    # print(result)
    parse_data = {'package-name': [],
                  'version-name': [],
                  'minSDK': [],
                  'maxSDK': [],
                  'permissions': [],
                  'application-name': [],
                  'launcher-activity': []}
    for i in range(0, len(result)):
        item = result[i]
        #print(type(item))
        if list(item.keys())[0] == 'manifest':
            parse_data['package-name'].append(item['manifest']['package'])
            #print(parse_data)
            parse_data['version-name'].append(item['manifest']['android:versionName'])
            # print(parse_data)
        if list(item.keys())[0] == 'uses-permission':
            parse_data['permissions'].append(item['uses-permission']['android:name'])
        if list(item.keys())[0] == 'application':
            try:
                parse_data['application-name'].append(item['application']['android:name'])
            except Exception as f:
                continue
        if list(item.keys())[0] == 'category' and 'LAUNCHER' in item['category']['android:name'] \
                and result[i - 3] is not None and list(result[i - 3].keys())[0] == 'activity':
            parse_data['launcher-activity'].append(result[i-3]['activity']['android:name'])
        if list(item.keys())[0] == 'uses-sdk':
            parse_data['minSDK'].append(int(item['uses-sdk']['android:minSdkVersion'], 16))
            parse_data['maxSDK'].append(int(item['uses-sdk']['android:targetSdkVersion'], 16))
    # print(parse_data)
    return parse_data


def parse_label(data):
    for line in data:
        #print(aaptline)
        # application-label: '222'
        label_name = ''
        if line.find('application-label:') > -1:
            pattern = r'label:\'(\S*)\''
            m = re.search(pattern, line)
            if m:
                label_name = m.group(1)
                return label_name
                # break
    return

def parse_sign(data):
    sign_info = ''
    for line in data:
        #print(line)
        # application-label: '222'

        if line.find('所有者:') > -1 or line.find('Owner:') > -1:
            pattern = re.compile('^(所有者|Owner):.*$')
            m = re.search(pattern, line)
            if m:
                sign_info = m[0]
                # print(sign_info)
                #return sign_info
                # break
        if line.find('发布者:') > -1 or line.find('Issuer:') > -1:
            pattern = re.compile('^(发布者|Issuer):.*$')
            m = re.search(pattern, line)
            if m:
                sign_info += '\n%51s' % ' ' + m[0]
                # print(sign_info)
                # return sign_info
                # break
    if sign_info != '':
        return sign_info
    else:
        return data
