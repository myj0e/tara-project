
JSON='''
{
  "items": [
    {
      "component": "Web Application",
      "threat_type": "Spoofing",
      "scenario": "攻击者伪装成合法用户通过未认证访问敏感数据",
      "mitigations": ["实施多因素认证", "严格的会话管理", "定期轮换凭证"]
    },
    {
      "component": "Web Application",
      "threat_type": "Tampering",
      "scenario": "攻击者篡改Web应用程序发送到数据库的查询",
      "mitigations": ["使用参数化查询和存储过程", "部署WAF防护"]
    },
    {
      "component": "Web Application",
      "threat_type": "Information Disclosure",
      "scenario": "配置错误导致敏感数据泄露",
      "mitigations": ["禁用详细错误消息", "生产环境关闭调试模式", "实施数据脱敏"]
    },
    {
      "component": "Web Application",
      "threat_type": "Denial of Service",
      "scenario": "恶意请求导致服务不可用",
      "mitigations": ["部署速率限制和DDoS防护", "实现自动扩展能力"]
    },
    {
      "component": "Database",
      "threat_type": "Tampering",
      "scenario": "SQL注入攻击修改数据库数据",
      "mitigations": ["定期进行补丁管理", "最小权限原则", "实施输入验证"]
    },
    {
      "component": "Database",
      "threat_type": "Information Disclosure",
      "scenario": "访问控制不当导致数据泄露",
      "mitigations": ["实施基于角色的访问控制", "数据加密", "审计敏感数据访问"]
    },
    {
      "component": "Database",
      "threat_type": "Elevation of Privilege",
      "scenario": "利用漏洞获取管理员权限",
      "mitigations": ["定期漏洞扫描", "特权账户管理", "实施最小特权原则"]
    },
    {
      "component": "Web Application Config",
      "threat_type": "Information Disclosure",
      "scenario": "配置文件包含敏感凭证被泄露",
      "mitigations": ["凭证与配置分离", "使用密钥管理系统", "配置访问控制"]
    },
    {
      "component": "Web Application Config",
      "threat_type": "Tampering",
      "scenario": "攻击者修改配置文件改变应用行为",
      "mitigations": ["实施配置变更管理", "文件完整性监控", "只读权限设置"]
    },
    {
      "component": "Message Queue",
      "threat_type": "Tampering",
      "scenario": "篡改消息队列插入恶意指令",
      "mitigations": ["消息签名验证", "实施端到端加密", "消息有效性检查"]
    },
    {
      "component": "Message Queue",
      "threat_type": "Denial of Service",
      "scenario": "垃圾消息导致队列溢出",
      "mitigations": ["消息速率限制", "队列容量监控", "优先级消息处理"]
    },
    {
      "component": "Web Request",
      "threat_type": "Spoofing",
      "scenario": "伪造Web请求冒充合法用户",
      "mitigations": ["实施CSRF防护令牌", "请求签名", "行为分析验证"]
    },
    {
      "component": "Web Request",
      "threat_type": "Tampering",
      "scenario": "篡改Web请求参数传输",
      "mitigations": ["使用HTTPS加密", "数据完整性校验", "API参数验证"]
    },
    {
      "component": "Web Response",
      "threat_type": "Information Disclosure",
      "scenario": "响应数据被中间人截获",
      "mitigations": ["实施TLS 1.2+加密", "敏感数据脱敏", "禁止缓存敏感响应"]
    },
    {
      "component": "Web Response",
      "threat_type": "Tampering",
      "scenario": "篡改响应内容插入恶意代码",
      "mitigations": ["实施内容安全策略(CSP)", "响应完整性检查", "安全头设置"]
    }
  ],
  "summary": [
    "增强认证与访问控制：在所有关键系统中实施多因素认证，严格遵循最小权限原则，对敏感操作实施审批流程",
    "强化数据保护机制：对传输中和存储的敏感数据进行强加密处理，实施数据脱敏策略，定期审计数据访问记录",
    "完善输入输出验证：对所有输入数据实施严格验证，采用参数化查询防御注入攻击，响应内容实施完整性保护",
    "部署分层防御措施：在网络边界、应用层和数据库层面部署互补的安全控制措施，如WAF、SIEM和文件完整性监控"
  ]
}
'''
import threat_process.utils_db as udb
import json
print("start")
udb.putMitigationJSON2db("1234",json.loads(JSON))
res=udb.getMitigationJSON2db("1234")
# print(res)
#udb.exportMitigationToExcel("1234","/Users/mazihan/Desktop/icbc/tara-project/threatBackend/data/mitigation.xlsx")
res1=udb.get_mitigations_page_with_count()
print(res1)