import threat_process.utils_db as udb
import json
'''
运行结果：
dread_json 写入成功 hash_id=1234
{'nodes': [{'name': 'user', 'type': 'External Entity', 'stride': {'S': {'description': '恶意用户伪装成合法用户访问系统，因为当前系统没有身份验证机制', 'Scenario': '系统无法识别真实用户身份，导致未经授权的访问和操作', 'dread': {'D': 8, 'R': 9, 'E': 8, 'A': 9, 'D2': 7}}, 'T': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'R': {'description': '用户执行操作后否定自己的行为', 'Scenario': '因为没有身份验证和日志记录，无法追踪用户操作，导致责任不明确', 'dread': {'D': 7, 'R': 8, 'E': 7, 'A': 8, 'D2': 6}}, 'I': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}}}, {'name': 'IAM', 'type': 'Process', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'T': {'description': '攻击者篡改IAM处理的数据流，如修改用户权限或访问控制规则', 'Scenario': '非法获取高权限或敏感数据访问权', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'I': {'description': 'IAM处理过程中泄露敏感信息，如日志中记录明文密码或密钥', 'Scenario': '敏感数据被未授权方获取', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}}, 'D': {'description': '攻击者通过大量请求使IAM服务超载', 'Scenario': '合法用户无法访问系统资源', 'dread': {'D': 7, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}}, 'E': {'description': '攻击者利用IAM漏洞获取更高权限', 'Scenario': '系统权限被恶意提升，造成更大范围破坏', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}}}}, {'name': 'Database', 'type': 'Data Store', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'T': {'description': '攻击者直接修改数据库中的敏感数据', 'Scenario': '数据完整性受损，可能导致决策错误', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'I': {'description': '数据库未加密或配置不当导致数据泄露', 'Scenario': '绝密信息外泄，造成严重安全事件', 'dread': {'D': 10, 'R': 7, 'E': 6, 'A': 9, 'D2': 6}}, 'D': {'description': '攻击者执行大量复杂查询耗尽数据库资源', 'Scenario': '数据库服务不可用，影响整个系统', 'dread': {'D': 8, 'R': 8, 'E': 7, 'A': 9, 'D2': 7}}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}}}, {'name': 'user-IAM', 'type': 'Data Flow', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'T': {'description': '中间人攻击篡改user和IAM之间传输的数据', 'Scenario': '传输数据被恶意修改', 'dread': {'D': 8, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'I': {'description': '数据未加密传输导致信息泄露', 'Scenario': '敏感信息被截获', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 6}}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}}}, {'name': 'IAM-Database', 'type': 'Data Flow', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'T': {'description': '数据库查询或命令被篡改', 'Scenario': '数据库执行了恶意操作', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'I': {'description': '查询结果中包含过多信息导致数据泄露', 'Scenario': '过度的信息暴露给IAM', 'dread': {'D': 8, 'R': 6, 'E': 5, 'A': 8, 'D2': 5}}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}}}}]}
True
'''

hash_id="1234"
commit=\
{
    "nodes": [
        {
            "name": "user",
            "type": "External Entity",
            "stride": {
                "S": {
                    "description": "\u6076\u610f\u7528\u6237\u4f2a\u88c5\u6210\u5408\u6cd5\u7528\u6237\u8bbf\u95ee\u7cfb\u7edf\uff0c\u56e0\u4e3a\u5f53\u524d\u7cfb\u7edf\u6ca1\u6709\u8eab\u4efd\u9a8c\u8bc1\u673a\u5236",
                    "Scenario": "\u7cfb\u7edf\u65e0\u6cd5\u8bc6\u522b\u771f\u5b9e\u7528\u6237\u8eab\u4efd\uff0c\u5bfc\u81f4\u672a\u7ecf\u6388\u6743\u7684\u8bbf\u95ee\u548c\u64cd\u4f5c",
                    "dread": {
                        "D": 8,
                        "R": 9,
                        "E": 8,
                        "A": 9,
                        "D2": 7
                    }
                },
                "T": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "R": {
                    "description": "\u7528\u6237\u6267\u884c\u64cd\u4f5c\u540e\u5426\u5b9a\u81ea\u5df1\u7684\u884c\u4e3a",
                    "Scenario": "\u56e0\u4e3a\u6ca1\u6709\u8eab\u4efd\u9a8c\u8bc1\u548c\u65e5\u5fd7\u8bb0\u5f55\uff0c\u65e0\u6cd5\u8ffd\u8e2a\u7528\u6237\u64cd\u4f5c\uff0c\u5bfc\u81f4\u8d23\u4efb\u4e0d\u660e\u786e",
                    "dread": {
                        "D": 7,
                        "R": 8,
                        "E": 7,
                        "A": 8,
                        "D2": 6
                    }
                },
                "I": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "D": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "E": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                }
            }
        },
        {
            "name": "IAM",
            "type": "Process",
            "stride": {
                "S": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "T": {
                    "description": "\u653b\u51fb\u8005\u7be1\u6539IAM\u5904\u7406\u7684\u6570\u636e\u6d41\uff0c\u5982\u4fee\u6539\u7528\u6237\u6743\u9650\u6216\u8bbf\u95ee\u63a7\u5236\u89c4\u5219",
                    "Scenario": "\u975e\u6cd5\u83b7\u53d6\u9ad8\u6743\u9650\u6216\u654f\u611f\u6570\u636e\u8bbf\u95ee\u6743",
                    "dread": {
                        "D": 9,
                        "R": 8,
                        "E": 7,
                        "A": 9,
                        "D2": 6
                    }
                },
                "R": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "I": {
                    "description": "IAM\u5904\u7406\u8fc7\u7a0b\u4e2d\u6cc4\u9732\u654f\u611f\u4fe1\u606f\uff0c\u5982\u65e5\u5fd7\u4e2d\u8bb0\u5f55\u660e\u6587\u5bc6\u7801\u6216\u5bc6\u94a5",
                    "Scenario": "\u654f\u611f\u6570\u636e\u88ab\u672a\u6388\u6743\u65b9\u83b7\u53d6",
                    "dread": {
                        "D": 9,
                        "R": 7,
                        "E": 6,
                        "A": 9,
                        "D2": 5
                    }
                },
                "D": {
                    "description": "\u653b\u51fb\u8005\u901a\u8fc7\u5927\u91cf\u8bf7\u6c42\u4f7fIAM\u670d\u52a1\u8d85\u8f7d",
                    "Scenario": "\u5408\u6cd5\u7528\u6237\u65e0\u6cd5\u8bbf\u95ee\u7cfb\u7edf\u8d44\u6e90",
                    "dread": {
                        "D": 7,
                        "R": 8,
                        "E": 7,
                        "A": 9,
                        "D2": 6
                    }
                },
                "E": {
                    "description": "\u653b\u51fb\u8005\u5229\u7528IAM\u6f0f\u6d1e\u83b7\u53d6\u66f4\u9ad8\u6743\u9650",
                    "Scenario": "\u7cfb\u7edf\u6743\u9650\u88ab\u6076\u610f\u63d0\u5347\uff0c\u9020\u6210\u66f4\u5927\u8303\u56f4\u7834\u574f",
                    "dread": {
                        "D": 9,
                        "R": 8,
                        "E": 7,
                        "A": 9,
                        "D2": 6
                    }
                }
            }
        },
        {
            "name": "Database",
            "type": "Data Store",
            "stride": {
                "S": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "T": {
                    "description": "\u653b\u51fb\u8005\u76f4\u63a5\u4fee\u6539\u6570\u636e\u5e93\u4e2d\u7684\u654f\u611f\u6570\u636e",
                    "Scenario": "\u6570\u636e\u5b8c\u6574\u6027\u53d7\u635f\uff0c\u53ef\u80fd\u5bfc\u81f4\u51b3\u7b56\u9519\u8bef",
                    "dread": {
                        "D": 9,
                        "R": 8,
                        "E": 7,
                        "A": 9,
                        "D2": 6
                    }
                },
                "R": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "I": {
                    "description": "\u6570\u636e\u5e93\u672a\u52a0\u5bc6\u6216\u914d\u7f6e\u4e0d\u5f53\u5bfc\u81f4\u6570\u636e\u6cc4\u9732",
                    "Scenario": "\u7edd\u5bc6\u4fe1\u606f\u5916\u6cc4\uff0c\u9020\u6210\u4e25\u91cd\u5b89\u5168\u4e8b\u4ef6",
                    "dread": {
                        "D": 10,
                        "R": 7,
                        "E": 6,
                        "A": 9,
                        "D2": 6
                    }
                },
                "D": {
                    "description": "\u653b\u51fb\u8005\u6267\u884c\u5927\u91cf\u590d\u6742\u67e5\u8be2\u8017\u5c3d\u6570\u636e\u5e93\u8d44\u6e90",
                    "Scenario": "\u6570\u636e\u5e93\u670d\u52a1\u4e0d\u53ef\u7528\uff0c\u5f71\u54cd\u6574\u4e2a\u7cfb\u7edf",
                    "dread": {
                        "D": 8,
                        "R": 8,
                        "E": 7,
                        "A": 9,
                        "D2": 7
                    }
                },
                "E": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                }
            }
        },
        {
            "name": "user-IAM",
            "type": "Data Flow",
            "stride": {
                "S": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "T": {
                    "description": "\u4e2d\u95f4\u4eba\u653b\u51fb\u7be1\u6539user\u548cIAM\u4e4b\u95f4\u4f20\u8f93\u7684\u6570\u636e",
                    "Scenario": "\u4f20\u8f93\u6570\u636e\u88ab\u6076\u610f\u4fee\u6539",
                    "dread": {
                        "D": 8,
                        "R": 7,
                        "E": 6,
                        "A": 9,
                        "D2": 5
                    }
                },
                "R": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "I": {
                    "description": "\u6570\u636e\u672a\u52a0\u5bc6\u4f20\u8f93\u5bfc\u81f4\u4fe1\u606f\u6cc4\u9732",
                    "Scenario": "\u654f\u611f\u4fe1\u606f\u88ab\u622a\u83b7",
                    "dread": {
                        "D": 9,
                        "R": 7,
                        "E": 6,
                        "A": 9,
                        "D2": 6
                    }
                },
                "D": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "E": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                }
            }
        },
        {
            "name": "IAM-Database",
            "type": "Data Flow",
            "stride": {
                "S": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "T": {
                    "description": "\u6570\u636e\u5e93\u67e5\u8be2\u6216\u547d\u4ee4\u88ab\u7be1\u6539",
                    "Scenario": "\u6570\u636e\u5e93\u6267\u884c\u4e86\u6076\u610f\u64cd\u4f5c",
                    "dread": {
                        "D": 9,
                        "R": 7,
                        "E": 6,
                        "A": 9,
                        "D2": 5
                    }
                },
                "R": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "I": {
                    "description": "\u67e5\u8be2\u7ed3\u679c\u4e2d\u5305\u542b\u8fc7\u591a\u4fe1\u606f\u5bfc\u81f4\u6570\u636e\u6cc4\u9732",
                    "Scenario": "\u8fc7\u5ea6\u7684\u4fe1\u606f\u66b4\u9732\u7ed9IAM",
                    "dread": {
                        "D": 8,
                        "R": 6,
                        "E": 5,
                        "A": 8,
                        "D2": 5
                    }
                },
                "D": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                },
                "E": {
                    "description": "None",
                    "Scenario": "None",
                    "dread": {
                        "D": 0,
                        "R": 0,
                        "E": 0,
                        "A": 0,
                        "D2": 0
                    }
                }
            }
        }
    ]
}
udb.putDreadJSON2db(hash_id,commit)
commit_json = udb.get_dread_json(hash_id)
print(commit_json)
print(json.loads(json.dumps(commit_json))==json.loads(json.dumps(commit)))
