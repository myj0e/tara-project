import threat_process.utils_mongo as udbm
import json

commit1='''
graph TD
    root[攻破应用程序]
    auth[获得未授权访问]
    root --> auth
    auth1["伪装成后台工作进程获取Worker Config配置"]
    auth --> auth1
    auth2[伪装成合法用户或进程访问数据库]
    auth --> auth2
    auth3["伪装成Web应用获取Web Application Config配置"]
    auth --> auth3
    auth4[伪装成合法应用向消息队列发送恶意消息]
    auth --> auth4
    auth5[CSRF攻击伪造合法用户请求]
    auth --> auth5
    auth6[伪造浏览器身份]
    auth --> auth6
    auth7[伪造请求来源]
    auth --> auth7
    tamper[数据篡改]
    root --> tamper
    tamper1["恶意修改Worker Config配置信息"]
    tamper --> tamper1
    tamper2[通过注入攻击修改数据库内容]
    tamper --> tamper2
    tamper3[篡改Web应用配置]
    tamper --> tamper3
    tamper4[篡改消息队列中的消息内容]
    tamper --> tamper4
    tamper5[注入攻击修改应用逻辑]
    tamper --> tamper5
    tamper6[修改浏览器发出的请求]
    tamper --> tamper6
    tamper7[篡改Web应用到消息队列的消息]
    tamper --> tamper7
    tamper8[篡改消息队列到后台工作进程的消息]
    tamper --> tamper8
    tamper9[篡改返回到浏览器的内容]
    tamper --> tamper9
    tamper10[修改请求参数]
    tamper --> tamper10
    disclose[信息泄露]
    root --> disclose
    disclose1["获取Worker Config中的敏感配置信息"]
    disclose --> disclose1
    disclose2[获取数据库中的未加密敏感数据]
    disclose --> disclose2
    disclose3["获取Web Application Config中的配置信息"]
    disclose --> disclose3
    disclose4["获取未加密的Put Message传输数据"]
    disclose --> disclose4
    disclose5[获取未加密的Message传输数据]
    disclose --> disclose5
    disclose6["通过Web Response泄露敏感数据"]
    disclose --> disclose6
    dos[拒绝服务]
    root --> dos
    dos1[向消息队列发送大量垃圾消息]
    dos --> dos1
    dos2[利用应用漏洞发起DDoS攻击]
    dos --> dos2
    elevate[权限提升]
    root --> elevate
    elevate1[利用后台工作进程的权限漏洞获取更高权限]
    elevate --> elevate1
    elevate2[利用应用漏洞提升权限]
    elevate --> elevate2
    repudiation[抵赖]
    root --> repudiation
    repudiation1[利用数据库日志记录不充分进行抵赖]
    repudiation --> repudiation1'''
udbm.putAttackTreeMd("123", commit1)
res=udbm.getAttackTreeMd("123")

print(json.loads(json.dumps(res))==json.loads(json.dumps(commit1)))


