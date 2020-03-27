# coding:utf-8

import re
import json




def calc_blank(line_data):
    i = 0
    for bit in line_data:
        if bit == ' ':
            i+=1
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
                    dic[data_list[i][3:]][key_value[0]] = key_value[1].replace('\"',"")
                    # tmp = j
                    continue
                else:
                    all_dict.append(dic)
                    break
    return all_dict





def parse_xml(data):
    #print(data)
    result = parse_to_dict(data)
    #print(result)
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
            parse_data['version-name'].append(item['manifest']['android:versionName'])
        if list(item.keys())[0] == 'uses-sdk':
            parse_data['minSDK'].append(int(item['uses-sdk']['android:minSdkVersion'], 16))
            parse_data['maxSDK'].append(int(item['uses-sdk']['android:targetSdkVersion'], 16))
        if list(item.keys())[0] == 'uses-permission':
            parse_data['permissions'].append(item['uses-permission']['android:name'])
        if list(item.keys())[0] == 'application':
            parse_data['application-name'].append(item['application']['android:name'])
        if list(item.keys())[0] == 'category' and 'LAUNCHER' in item['category']['android:name'] \
                and result[i - 3] is not None and list(result[i - 3].keys())[0] == 'activity':
            parse_data['launcher-activity'].append(result[i-3]['activity']['android:name'])
    #print(parse_data)
    return parse_data




