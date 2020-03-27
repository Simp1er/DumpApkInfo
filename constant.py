SO_FEATURE = {'梆梆企业版': r'libDexHelper\S*.so',
              '梆梆': r'libsecexe\S*.so|libSecShell\S*.so|libsecmain\S*.so',
              '360加固': r'libjiagu\S*.so|libprotectClass\S*.so',
              '通付盾加固': r'libegis\S*.so|libegisboot\S*.so|libegismain\S*.so|libNSaferOnly\S*.so',
              '网秦加固': r'libnqshield\S*.so',
              '腾讯加固': r'libtxRes\S*.so|libshell\S*.so|^libtup.so$|mix\S*.dex|libtosprotection.\S*.so',
              '爱加密加固': r'ijiami\S*.dat|ijiami.ajm|libexec\S*.so',
              '娜迦加固': r'lib\wdog.so|libchaosvmp\S*.so',
              '阿里聚安全': r'libmobisec\w*.so|libaliutils\S*.so|aliprotect.dat|libsgmain.so|libsgsecuritybody.so',
              '百度加固': r'libbaiduprotect\S*.so',
              '网易易盾': r'libnesec.so|data.db|clazz.jar',
              'APKProtect': r'libAPKProtect\S*.so',
              '几维安全': r'libkwscmm.so|libkwscr.so|libkwslinker.so',
              '顶象科技': r'libx3g.so',
              '盛大': r'libapssec.so',
              '瑞星': r'librsprotect.so'}

APPLICATION_FEATURE = {
    '梆梆加固': r'com.secneo.apkwrapper|com.secneo.guard.ApplicationWrapper|com.secshell.secData.ApplicationWrapper',
    '360加固': r'com.stub.StubApp',
    '通付盾加固': r'com.payegis.ProxyApplication',
    '网秦加固': r'com.nqshield.NqApplication',
    '腾讯加固': r'com.tencent.StubShell.TxAppEntry',
    '爱加密加固': r'com.ijiami.residconfusion.ConfusionApplication|com.shell.SuperApplication|s.h.e.l.l.S',
    '娜迦加固': r'com.edog.AppWrapper|com.chaosvmp.AppWrapper',
    '阿里聚安全': r'com.ali.mobisecenhance.StubApplication',
    '百度加固': r'com.baidu.protect.StubApplication',
    '网易易盾': r'com.netease.nis.wrapper.MyApplication'}

NOWRAPPER = "NOT packed"

SENSTIVE_PERMISSIONS = {
    'READ_CALL_LOG': '读取通话记录',
    'WRITE_CALL_LOG': '编辑通话记录',
    'PROCESS_OUTGOING_CALLS': '修改或查看拨号',
    'READ_CONTACTS': '读取通讯录',
    'WRITE_CONTACTS': '编辑通讯录',
    'GET_ACCOUNTS': '获取应用账户',
    'RECORD_AUDIO': '录音',
    'READ_PHONE_STATE': '读取电话状态（获取设备IMSI、IMEI号）',
    'READ_PHONE_NUMBERS': '读取本机电话号码',
    'CALL_PHONE': '拨打电话',
    'ANSWER_PHONE_CALLS': '接听电话',
    'ADD_VOICEMAIL': '添加语音邮件',
    'USE_SIP': '使用网络电话',
    'SEND_SMS': '发送短信',
    'RECEIVE_SMS': '接收短信',
    'READ_SMS': '读取短信',
    'RECEIVE_WAP_PUSH': '接收WAP推送',
    'RECEIVE_MMS': '接收彩信',
    'READ_EXTERNAL_STORAGE': '读取多媒体文件',
    'CAMERA': '使用相机拍照',
    'WRITE_EXTERNAL_STORAGE': '截图与录屏'
}
