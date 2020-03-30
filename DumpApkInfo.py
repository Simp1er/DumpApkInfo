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


class DumpApkInfo:
    def __init__(self, dic):
        self.apk_path = dic['apk_path']
        self.aapt_path = dic['aapt_path']
        self.xmltree = {}  # 通过aapt获取的manifest.xml
        self.signInfo = ''
        self.wrapper_sdk = constant.NOWRAPPER
        self.lastError = ''
        self.label = ''
        self.so_compile = {}
        self.app_compile = {}
        self.init()

    def init(self):
        so_feature = constant.SO_FEATURE
        app_feature = constant.APPLICATION_FEATURE
        # print(so_feature)
        for (key, value) in so_feature.items():
            self.so_compile[key] = re.compile(value, re.I)
        for (key, value) in app_feature.items():
            self.app_compile[key] = re.compile(value, re.I)

    # 读取APK文件名列表
    def getZipNameList(self, apk_path):
        self.lastError = ''
        # print(self.apk_path)
        if not os.path.exists(apk_path):
            self.lastError = u'apk文件不存在'
            return False
        if not zipfile.is_zipfile(apk_path):
            self.lastError = u'非法的apk文件'
            return False
        try:
            zfobj = zipfile.ZipFile(apk_path)
            self.zipnamelist = zfobj.namelist()

            zfobj.close()
        except Exception as e:
            # print "%s" % e
            self.lastError = u'获取apk中文件列表异常'
            return False
        return True

    def getLabelName(self):
        self.lastError = ''
        cmd = "%s d badging %s" % (
            self.aapt_path, self.apk_path)

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
        self.lastError = ''
        xml_cmd = "%s d xmltree %s AndroidManifest.xml " % (
            self.aapt_path, self.apk_path)
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

            result = value.search(self.xmltree['application-name'][0])
            if result:
                # print(key)
                return key
        return constant.NOWRAPPER

    # 根据so文件判断是否加固
    def getWrapperBySo(self):
        self.lastError = ''
        # print('111')
        # so_result = constant.NOWRAPPER
        if not self.getZipNameList(self.apk_path):
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
            print(e)
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
        for permission in self.xmltree['permissions']:
            permission_name = permission.split('.')[-1]
            try:
                if constant.SENSTIVE_PERMISSIONS[permission_name] is not None:
                    permissions.append(constant.SENSTIVE_PERMISSIONS[permission_name])
            except KeyError as e:
                continue
        return permissions

    def getPackageName(self):
        if self.xmltree is None:
            self.getXmlInfo()
            # if self.lastError == '':
        try:
            return self.xmltree['package-name'][0]
        except IndexError as f:
            self.lastError = 'can\'t get package name from the file'
            return constant.UNKNOWN

    def getVersionName(self):
        if self.xmltree is None:
            self.getXmlInfo()
        # if self.lastError == '':
        try:
            return self.xmltree['version-name'][0]
        except IndexError as f:
            self.lastError = 'can\'t get version name from the file'
            return constant.UNKNOWN

    def getMinSDK(self):
        if self.xmltree is None:
            self.getXmlInfo()
        #if self.lastError == '':
        try:
            return constant.SDK[self.xmltree['minSDK'][0]]
        except IndexError as f:
            self.lastError = 'can\'t get min SDK from the file'
            return constant.UNKNOWN

    def getMaxSDK(self):
        if self.xmltree is None:
            self.getXmlInfo()
        # if self.lastError == '':
        try:
            return constant.SDK[self.xmltree['maxSDK'][0]]
        except IndexError as f:
            self.lastError = 'can\'t get max SDK from the file'
            return constant.UNKNOWN

    def getLauncherActivity(self):
        if self.xmltree is None:
            self.getXmlInfo()
        #if self.lastError == '':
        try:
            return self.xmltree['launcher-activity'][0]
        except IndexError as f:
            self.lastError = 'can\'t get launcher activity from the file'
            return constant.UNKNOWN



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
    parse_args()
    dic = {}
    dic['apk_path'] = detectedApk
    # print(dic)
    if 'Linux' in platform.system():
        dic["aapt_path"] = "./tools/aapt-linux"
    if 'Darwin' in platform.system():
        dic["aapt_path"] = "./tools/aapt-mac"
    if 'Windows' in platform.system():
        dic["aapt_path"] = "tools\\aapt.exe"
    apk_info = DumpApkInfo(dic)
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


if __name__ == "__main__":
    # parse_args()
    main()
    '''
    dic = {}
    dic['apk_path'] = '/Users/simp1er/Android/analysis_of_apk/360/360VulScanner/com.qihoo360.leakscan_7（360加壳）.apk'
    dic['aapt_path'] = "./tools/aapt-mac"
    apk_info = DumpApkInfo(dic)
    apk_info.getLabelName()
    print(apk_info.label)
    '''
