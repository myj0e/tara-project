import threat_process.utils_db as udb
import json
'''
运行结果：
{'nodes': [{'name': 'user', 'type': 'External Entity', 'stride': [{'Threat Type': 'Spoofing', 'Scenario': '攻击者可能伪装成合法用户，利用未认证的系统访问敏感数据', 'Potential Impact': '未授权访问敏感数据，导致信息泄露'}, {'Threat Type': 'Tampering', 'Scenario': '恶意用户可能篡改发送到IAM的请求数据', 'Potential Impact': '数据完整性受损，可能导致未授权的系统操作'}, {'Threat Type': 'Repudiation', 'Scenario': '用户可能否认执行过的操作，系统中缺乏日志记录', 'Potential Impact': '难以追踪和审计用户行为'}]}, {'name': 'IAM', 'type': 'Process', 'stride': [{'Threat Type': 'Information Disclosure', 'Scenario': 'IAM系统可能存在漏洞导致认证信息泄露', 'Potential Impact': '敏感认证信息暴露给攻击者'}, {'Threat Type': 'Denial of Service', 'Scenario': '攻击者可能发送大量请求导致IAM系统不可用', 'Potential Impact': '系统服务中断，影响合法用户访问'}, {'Threat Type': 'Elevation of Privilege', 'Scenario': 'IAM系统可能存在权限配置错误', 'Potential Impact': '攻击者获得未授权的高级系统权限'}]}, {'name': 'Database', 'type': 'Data Store', 'stride': [{'Threat Type': 'Tampering', 'Scenario': '数据库存储的数据可能被未授权修改', 'Potential Impact': '篡改关键数据导致业务决策错误'}, {'Threat Type': 'Information Disclosure', 'Scenario': '数据库可能配置不当导致数据暴露', 'Potential Impact': 'Top Secret等级数据泄露'}, {'Threat Type': 'Denial of Service', 'Scenario': '攻击者可能发送复杂查询导致数据库资源耗尽', 'Potential Impact': '数据库服务不可用'}]}, {'name': 'user-IAM', 'type': 'Data Flow', 'stride': [{'Threat Type': 'Spoofing', 'Scenario': '未加密的通信可能被中间人攻击假冒用户身份', 'Potential Impact': '未授权访问敏感系统'}, {'Threat Type': 'Information Disclosure', 'Scenario': '明文传输敏感信息可能被窃听', 'Potential Impact': '关键数据在传输过程中泄露'}]}, {'name': 'IAM-Database', 'type': 'Data Flow', 'stride': [{'Threat Type': 'Tampering', 'Scenario': '数据库查询可能被篡改执行恶意操作', 'Potential Impact': '数据库内容被非法修改'}, {'Threat Type': 'Repudiation', 'Scenario': '缺乏适当日志记录数据库操作', 'Potential Impact': '无法追踪异常数据库活动'}]}], 'improvement_suggestions': ['请提供IAM系统的具体实现细节(如是否使用OAuth/SAML等)，以便分析认证流程中的更多威胁', '需要了解数据库的具体类型和位置(如云数据库/本地部署)，以评估更精确的存储安全威胁', '请描述敏感数据的加解密措施(传输中和存储中)，以便分析数据保护强度', '建议提供系统架构图中各组件的宿主环境信息(如容器/虚拟机/物理服务器)', '需要了解是否存在API网关或其他边界防护措施，以评估系统入口安全', '请补充系统关键组件间的通信协议细节(如HTTP/gRPC)，以分析协议层安全']}
True
'''

hash_id="1234"
commit=\
{
    "nodes": [
        {
            "name": "user",
            "type": "External Entity",
            "stride": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "\u653b\u51fb\u8005\u53ef\u80fd\u4f2a\u88c5\u6210\u5408\u6cd5\u7528\u6237\uff0c\u5229\u7528\u672a\u8ba4\u8bc1\u7684\u7cfb\u7edf\u8bbf\u95ee\u654f\u611f\u6570\u636e",
                    "Potential Impact": "\u672a\u6388\u6743\u8bbf\u95ee\u654f\u611f\u6570\u636e\uff0c\u5bfc\u81f4\u4fe1\u606f\u6cc4\u9732"
                },
                {
                    "Threat Type": "Tampering",
                    "Scenario": "\u6076\u610f\u7528\u6237\u53ef\u80fd\u7be1\u6539\u53d1\u9001\u5230IAM\u7684\u8bf7\u6c42\u6570\u636e",
                    "Potential Impact": "\u6570\u636e\u5b8c\u6574\u6027\u53d7\u635f\uff0c\u53ef\u80fd\u5bfc\u81f4\u672a\u6388\u6743\u7684\u7cfb\u7edf\u64cd\u4f5c"
                },
                {
                    "Threat Type": "Repudiation",
                    "Scenario": "\u7528\u6237\u53ef\u80fd\u5426\u8ba4\u6267\u884c\u8fc7\u7684\u64cd\u4f5c\uff0c\u7cfb\u7edf\u4e2d\u7f3a\u4e4f\u65e5\u5fd7\u8bb0\u5f55",
                    "Potential Impact": "\u96be\u4ee5\u8ffd\u8e2a\u548c\u5ba1\u8ba1\u7528\u6237\u884c\u4e3a"
                }
            ]
        },
        {
            "name": "IAM",
            "type": "Process",
            "stride": [
                {
                    "Threat Type": "Information Disclosure",
                    "Scenario": "IAM\u7cfb\u7edf\u53ef\u80fd\u5b58\u5728\u6f0f\u6d1e\u5bfc\u81f4\u8ba4\u8bc1\u4fe1\u606f\u6cc4\u9732",
                    "Potential Impact": "\u654f\u611f\u8ba4\u8bc1\u4fe1\u606f\u66b4\u9732\u7ed9\u653b\u51fb\u8005"
                },
                {
                    "Threat Type": "Denial of Service",
                    "Scenario": "\u653b\u51fb\u8005\u53ef\u80fd\u53d1\u9001\u5927\u91cf\u8bf7\u6c42\u5bfc\u81f4IAM\u7cfb\u7edf\u4e0d\u53ef\u7528",
                    "Potential Impact": "\u7cfb\u7edf\u670d\u52a1\u4e2d\u65ad\uff0c\u5f71\u54cd\u5408\u6cd5\u7528\u6237\u8bbf\u95ee"
                },
                {
                    "Threat Type": "Elevation of Privilege",
                    "Scenario": "IAM\u7cfb\u7edf\u53ef\u80fd\u5b58\u5728\u6743\u9650\u914d\u7f6e\u9519\u8bef",
                    "Potential Impact": "\u653b\u51fb\u8005\u83b7\u5f97\u672a\u6388\u6743\u7684\u9ad8\u7ea7\u7cfb\u7edf\u6743\u9650"
                }
            ]
        },
        {
            "name": "Database",
            "type": "Data Store",
            "stride": [
                {
                    "Threat Type": "Tampering",
                    "Scenario": "\u6570\u636e\u5e93\u5b58\u50a8\u7684\u6570\u636e\u53ef\u80fd\u88ab\u672a\u6388\u6743\u4fee\u6539",
                    "Potential Impact": "\u7be1\u6539\u5173\u952e\u6570\u636e\u5bfc\u81f4\u4e1a\u52a1\u51b3\u7b56\u9519\u8bef"
                },
                {
                    "Threat Type": "Information Disclosure",
                    "Scenario": "\u6570\u636e\u5e93\u53ef\u80fd\u914d\u7f6e\u4e0d\u5f53\u5bfc\u81f4\u6570\u636e\u66b4\u9732",
                    "Potential Impact": "Top Secret\u7b49\u7ea7\u6570\u636e\u6cc4\u9732"
                },
                {
                    "Threat Type": "Denial of Service",
                    "Scenario": "\u653b\u51fb\u8005\u53ef\u80fd\u53d1\u9001\u590d\u6742\u67e5\u8be2\u5bfc\u81f4\u6570\u636e\u5e93\u8d44\u6e90\u8017\u5c3d",
                    "Potential Impact": "\u6570\u636e\u5e93\u670d\u52a1\u4e0d\u53ef\u7528"
                }
            ]
        },
        {
            "name": "user-IAM",
            "type": "Data Flow",
            "stride": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "\u672a\u52a0\u5bc6\u7684\u901a\u4fe1\u53ef\u80fd\u88ab\u4e2d\u95f4\u4eba\u653b\u51fb\u5047\u5192\u7528\u6237\u8eab\u4efd",
                    "Potential Impact": "\u672a\u6388\u6743\u8bbf\u95ee\u654f\u611f\u7cfb\u7edf"
                },
                {
                    "Threat Type": "Information Disclosure",
                    "Scenario": "\u660e\u6587\u4f20\u8f93\u654f\u611f\u4fe1\u606f\u53ef\u80fd\u88ab\u7a83\u542c",
                    "Potential Impact": "\u5173\u952e\u6570\u636e\u5728\u4f20\u8f93\u8fc7\u7a0b\u4e2d\u6cc4\u9732"
                }
            ]
        },
        {
            "name": "IAM-Database",
            "type": "Data Flow",
            "stride": [
                {
                    "Threat Type": "Tampering",
                    "Scenario": "\u6570\u636e\u5e93\u67e5\u8be2\u53ef\u80fd\u88ab\u7be1\u6539\u6267\u884c\u6076\u610f\u64cd\u4f5c",
                    "Potential Impact": "\u6570\u636e\u5e93\u5185\u5bb9\u88ab\u975e\u6cd5\u4fee\u6539"
                },
                {
                    "Threat Type": "Repudiation",
                    "Scenario": "\u7f3a\u4e4f\u9002\u5f53\u65e5\u5fd7\u8bb0\u5f55\u6570\u636e\u5e93\u64cd\u4f5c",
                    "Potential Impact": "\u65e0\u6cd5\u8ffd\u8e2a\u5f02\u5e38\u6570\u636e\u5e93\u6d3b\u52a8"
                }
            ]
        }
    ],
    "improvement_suggestions": [
        "\u8bf7\u63d0\u4f9bIAM\u7cfb\u7edf\u7684\u5177\u4f53\u5b9e\u73b0\u7ec6\u8282(\u5982\u662f\u5426\u4f7f\u7528OAuth/SAML\u7b49)\uff0c\u4ee5\u4fbf\u5206\u6790\u8ba4\u8bc1\u6d41\u7a0b\u4e2d\u7684\u66f4\u591a\u5a01\u80c1",
        "\u9700\u8981\u4e86\u89e3\u6570\u636e\u5e93\u7684\u5177\u4f53\u7c7b\u578b\u548c\u4f4d\u7f6e(\u5982\u4e91\u6570\u636e\u5e93/\u672c\u5730\u90e8\u7f72)\uff0c\u4ee5\u8bc4\u4f30\u66f4\u7cbe\u786e\u7684\u5b58\u50a8\u5b89\u5168\u5a01\u80c1",
        "\u8bf7\u63cf\u8ff0\u654f\u611f\u6570\u636e\u7684\u52a0\u89e3\u5bc6\u63aa\u65bd(\u4f20\u8f93\u4e2d\u548c\u5b58\u50a8\u4e2d)\uff0c\u4ee5\u4fbf\u5206\u6790\u6570\u636e\u4fdd\u62a4\u5f3a\u5ea6",
        "\u5efa\u8bae\u63d0\u4f9b\u7cfb\u7edf\u67b6\u6784\u56fe\u4e2d\u5404\u7ec4\u4ef6\u7684\u5bbf\u4e3b\u73af\u5883\u4fe1\u606f(\u5982\u5bb9\u5668/\u865a\u62df\u673a/\u7269\u7406\u670d\u52a1\u5668)",
        "\u9700\u8981\u4e86\u89e3\u662f\u5426\u5b58\u5728API\u7f51\u5173\u6216\u5176\u4ed6\u8fb9\u754c\u9632\u62a4\u63aa\u65bd\uff0c\u4ee5\u8bc4\u4f30\u7cfb\u7edf\u5165\u53e3\u5b89\u5168",
        "\u8bf7\u8865\u5145\u7cfb\u7edf\u5173\u952e\u7ec4\u4ef6\u95f4\u7684\u901a\u4fe1\u534f\u8bae\u7ec6\u8282(\u5982HTTP/gRPC)\uff0c\u4ee5\u5206\u6790\u534f\u8bae\u5c42\u5b89\u5168"
    ]
}
udb.putThreatModleJSON2db(hash_id,commit)
commit_json = udb.getThreatModleJSON(hash_id)
print(commit_json)
print(json.loads(json.dumps(commit_json))==json.loads(json.dumps(commit)))