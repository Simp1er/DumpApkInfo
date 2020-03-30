#!/usr/bin/env python
# coding: utf-8

import os
import re
import platform
import zipfile
import sys
import getopt
import constant
import Utils
import json


class DumpApkInfo:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.dic = {}
        self.xmltree = {}  # 通过aapt获取的manifest.xml
        self.signInfo = ''
        self.wrapper_sdk = constant.NOWRAPPER
        self.lastError = ''
        self.label = ''
        self.so_compile = {}
        self.app_compile = {}
        self.zipnamelist = []
        self.init()

    def init(self):
        so_feature = constant.SO_FEATURE
        app_feature = constant.APPLICATION_FEATURE
        # print(so_feature)
        for (key, value) in so_feature.items():
            self.so_compile[key] = re.compile(value, re.I)
        for (key, value) in app_feature.items():
            self.app_compile[key] = re.compile(value, re.I)

    def setPlatform(self):
        sysInfo = platform.system()
        if 'Linux' in sysInfo:
            self.dic["aapt_path"] = "./tools/aapt-linux"
            self.dic['keytool_path'] = './tools/sign/keytool-linux'
        if 'Darwin' in sysInfo:
            self.dic["aapt_path"] = "./tools/aapt-mac"
            self.dic['keytool_path'] = './tools/sign/keytool-mac'
        if 'Windows' in sysInfo:
            self.dic["aapt_path"] = "tools\\aapt.exe"
            self.dic['keytool_path'] = 'tools\\sign\\keytool.exe'
    # 读取APK文件名列表
    def getZipNameList(self):
        self.lastError = ''
        # print(self.apk_path)
        if not os.path.exists(self.apk_path):
            self.lastError = u'apk文件不存在'
            return False
        if not zipfile.is_zipfile(self.apk_path):
            self.lastError = u'非法的apk文件'
            return False
        try:
            zfobj = zipfile.ZipFile(self.apk_path)
            self.zipnamelist = zfobj.namelist()

            zfobj.close()
        except Exception as e:
            # print "%s" % e
            self.lastError = u'获取apk中文件列表异常'
            return False
        return True

    def getLabelName(self):
        global dic
        self.lastError = ''
        cmd = "%s d badging %s" % (
            self.dic['aapt_path'], self.apk_path)

        try:
            ret = os.popen(cmd)
            self.label = Utils.parse_label(ret.readlines())
            if self.label != None:
                return self.label
            else:
                return 'Fail to get it'
            #print(self.label)
        except Exception as e:
            self.lastError = 'aapt get label name error'
            return


    # 通过aapt获取的manifest.xml
    def getXmlInfo(self):
        global dic
        self.lastError = ''
        xml_cmd = "%s d xmltree %s AndroidManifest.xml " % (
            self.dic['aapt_path'], self.apk_path)
        try:
            strxml = os.popen(xml_cmd)
            self.xmltree = Utils.parse_xml(strxml.read())
            # print(self.xmltree)
        except Exception as e:
            # print(e)
            # print "aapt Mainfestxml error"
            self.lastError = 'aapt get AndroidManifest.xml error'
            return False
        return True

    # 从xml中检测加壳信息
    def getWrapperByManifest(self):
        if not self.getXmlInfo():
            return
        for (key, value) in self.app_compile.items():
            # print(self.xmltree['application-name'][0])
            try:
                result = value.search(self.xmltree['application-name'][0])
                if result:
                    # print(key)
                    return key
            except Exception as f:
                return constant.NOWRAPPER
        return constant.NOWRAPPER

    # 根据so文件判断是否加固
    def getWrapperBySo(self):
        self.lastError = ''
        if not self.getZipNameList():
            return
        try:
            # print(self.zipnamelist)
            for fileName in self.zipnamelist:
                # print(fileName)
                for (key, value) in self.so_compile.items():
                    result = value.search(fileName)
                    # print(fileName)
                    if result:
                        return key
            return constant.NOWRAPPER
        except Exception as e:
            # print(e)
            # print "parser wrap sdk error: "
            # logging.error(e)
            self.lastError = 'parser wrap lib error'
            return

    def detectShell(self):
        result_Manifest = self.getWrapperByManifest()
        if self.lastError != '' or result_Manifest is None:
            result_Manifest = self.lastError
            # print(self.lastError)
        result_So = self.getWrapperBySo()
        if self.lastError != '' or result_So is None:
            result_So = self.lastError
            # print(self.lastError)
        return result_Manifest, result_So

    def detectSenstive_Permissions(self):
        if self.xmltree is None:
            self.getXmlInfo()
        permissions = []
        # print(self.xmltree)
        try:
            for permission in self.xmltree['permissions']:
                permission_name = permission.split('.')[-1]
                try:
                    if constant.SENSTIVE_PERMISSIONS[permission_name] is not None:
                        permissions.append(constant.SENSTIVE_PERMISSIONS[permission_name])
                except KeyError as e:
                    continue
            return permissions
        except KeyError as e:
            return []

    def getPackageName(self):
        if self.xmltree is None:
            self.getXmlInfo()
            # if self.lastError == '':
        try:
            return self.xmltree['package-name'][0]
        except IndexError and KeyError as f:
            self.lastError = 'can\'t get package name from the file'
            return constant.UNKNOWN

    def getVersionName(self):
        if self.xmltree is None:
            self.getXmlInfo()
        # if self.lastError == '':
        try:
            return self.xmltree['version-name'][0]
        except IndexError and KeyError as f:
            self.lastError = 'can\'t get version name from the file'
            return constant.UNKNOWN

    def getMinSDK(self):
        if self.xmltree is None:
            self.getXmlInfo()
        #if self.lastError == '':
        try:
            return constant.SDK[self.xmltree['minSDK'][0]]
        except IndexError and KeyError as f:
            self.lastError = 'can\'t get min SDK from the file'
            return constant.UNKNOWN

    def getMaxSDK(self):
        if self.xmltree is None:
            self.getXmlInfo()
        # if self.lastError == '':
        try:
            return constant.SDK[self.xmltree['maxSDK'][0]]
        except IndexError and KeyError as f:
            self.lastError = 'can\'t get max SDK from the file'
            return constant.UNKNOWN

    def getLauncherActivity(self):
        if self.xmltree is None:
            self.getXmlInfo()
        #if self.lastError == '':
        try:
            return self.xmltree['launcher-activity'][0]
        except IndexError and KeyError as f:
            self.lastError = 'can\'t get launcher activity from the file'
            return constant.UNKNOWN

    def getSignInfo1(self):
        info = os.popen('java -jar ' + constant.CheckAndroidV2SignatureByAPKSig + ' ' + self.apk_path)
        #print(type(info.read()))
        #if code == 0:
        msg_dic = json.loads(info.read())

        if msg_dic['isV1OK']:  # 如果使用了v1签名，不管是否使用了v2签名检测v1签名
            data = os.popen(self.dic['keytool_path'] + ' -printcert ' + '-jarfile ' + self.apk_path)
            self.signInfo = Utils.parse_sign(data.readlines())
            # print(self.signInfo)

            #return code, info
    def getSignInfo2(self):
        # print(self.zipnamelist)
        if len(self.zipnamelist) == 0 :
            # print('yes')
            if not self.getZipNameList():
                return
        for name in self.zipnamelist:
            if name.startswith('META-INF') and name.endswith('.RSA'):
                z = zipfile.ZipFile(self.apk_path, 'r')
                if not os.path.exists('./tmp'):
                    os.mkdir('tmp', 0o777)
                fd = open('tmp/' + name.split('/')[-1],  'wb')
                fd.write(z.read(name))
                fd.close()
                data = os.popen(self.dic['keytool_path'] + ' -printcert ' + '-file ' + 'tmp/' + name.split('/')[-1])
                self.signInfo = Utils.parse_sign(data.readlines())
                # print(self.signInfo)
                os.remove('tmp/' + name.split('/')[-1])
    def getSignInfo(self):
        self.getSignInfo1()
        if len(self.signInfo) == 0:
            self.getSignInfo2()





def print_banner():
    banner = """
                    _____      .___ __              _____                      ________   
      _____/ ____\____ |   |  | ________   /  _  \ ______   _____  __ _\______ \  
     /  _ \   __\/    \|   |  |/ /\____ \ /  /_\  \\\\____ \ /     \|  |  \    |  \ 
    (  <_> )  | |   |  \   |    < |  |_> >    |    \  |_> >  Y Y  \  |  /    `   \\
     \____/|__| |___|  /___|__|_ \|   __/\____|__  /   __/|__|_|  /____/_______  /
                     \/         \/|__|           \/|__|         \/             \/ 
    """
    print('\t' + banner)


def usage():
    print_banner()
    print("%100s" % "\n\tUSAGE: \t python DumpApkInfo.py  -h")
    print("%45s" % "\t python DumpApkInfo.py  -a app.apk\n")


def parse_args():
    global detectedApk
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:", ["apk=", ])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    if len(opts) <= 0:
        usage()
        sys.exit()
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        if opt in ("-a", "--apk"):
            detectedApk = arg
    print_banner()
    print("%50s" % 'Input  Name: ', detectedApk.split(os.sep)[-1])


def main():
    global detectedApk
    global dic
    parse_args()
    # dic = {}
    # dic['aapt_path'] = detectedApk
    # print(dic)

    apk_info = DumpApkInfo(detectedApk)
    apk_info.setPlatform()
    apk_info.getSignInfo()
    result_Manifest, result_So = apk_info.detectShell()
    permissions = apk_info.detectSenstive_Permissions()

    print("%50s" % 'Package     Name: ', apk_info.getPackageName())
    print("%50s" % 'APK     Name: ', apk_info.getLabelName())
    print("%50s" % 'Version     Name: ', apk_info.getVersionName())
    print("%50s" % 'Launch Acitivity: ', apk_info.getLauncherActivity())
    print("%50s" % 'Minimum      platform: ', apk_info.getMinSDK())
    print("%50s" % 'Target      platform: ', apk_info.getMaxSDK())
    print("%50s" % 'Dangerous Permissions: ', permissions)
    print("%50s" % 'Maybe packed by : ', result_Manifest, "|", result_So)
    print("%50s" % 'Sign Info : ', apk_info.signInfo)


if __name__ == "__main__":
    # parse_args()
    main()
    # dic = {}
