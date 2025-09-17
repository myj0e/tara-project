import threat_process.utils_db as udb
import json
'''
运行结果：
Commit JSON 写入成功，hash_id=1234
{'nodes': [{'name': 'user', 'type': 'External Entity', 'stride': {'S': {'description': '恶意用户伪装成合法用户访问系统，因为当前系统没有身份验证机制', 'Scenario': '系统无法识别真实用户身份，导致未经授权的访问和操作', 'dread': {'D': 1, 'R': 1, 'E': 1, 'A': 1, 'D2': 1}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}, 'T': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}, 'R': {'description': '用户执行操作后否定自己的行为', 'Scenario': '因为没有身份验证和日志记录，无法追踪用户操作，导致责任不明确', 'dread': {'D': 7, 'R': 8, 'E': 7, 'A': 8, 'D2': 6}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}, 'I': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': '我们需要改进一下，D应该xxx，R应该xxx，......'}}}, {'name': 'IAM', 'type': 'Process', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'T': {'description': '攻击者篡改IAM处理的数据流，如修改用户权限或访问控制规则', 'Scenario': '非法获取高权限或敏感数据访问权', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}, 'commit': ''}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'I': {'description': 'IAM处理过程中泄露敏感信息，如日志中记录明文密码或密钥', 'Scenario': '敏感数据被未授权方获取', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}, 'commit': ''}, 'D': {'description': '攻击者通过大量请求使IAM服务超载', 'Scenario': '合法用户无法访问系统资源', 'dread': {'D': 7, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}, 'commit': ''}, 'E': {'description': '攻击者利用IAM漏洞获取更高权限', 'Scenario': '系统权限被恶意提升，造成更大范围破坏', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}, 'commit': ''}}}, {'name': 'Database', 'type': 'Data Store', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'T': {'description': '攻击者直接修改数据库中的敏感数据', 'Scenario': '数据完整性受损，可能导致决策错误', 'dread': {'D': 9, 'R': 8, 'E': 7, 'A': 9, 'D2': 6}, 'commit': ''}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'I': {'description': '数据库未加密或配置不当导致数据泄露', 'Scenario': '绝密信息外泄，造成严重安全事件', 'dread': {'D': 10, 'R': 7, 'E': 6, 'A': 9, 'D2': 6}, 'commit': ''}, 'D': {'description': '攻击者执行大量复杂查询耗尽数据库资源', 'Scenario': '数据库服务不可用，影响整个系统', 'dread': {'D': 8, 'R': 8, 'E': 7, 'A': 9, 'D2': 7}, 'commit': ''}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}}}, {'name': 'user-IAM', 'type': 'Data Flow', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'T': {'description': '中间人攻击篡改user和IAM之间传输的数据', 'Scenario': '传输数据被恶意修改', 'dread': {'D': 8, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}, 'commit': ''}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'I': {'description': '数据未加密传输导致信息泄露', 'Scenario': '敏感信息被截获', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 6}, 'commit': ''}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}}}, {'name': 'IAM-Database', 'type': 'Data Flow', 'stride': {'S': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'T': {'description': '数据库查询或命令被篡改', 'Scenario': '数据库执行了恶意操作', 'dread': {'D': 9, 'R': 7, 'E': 6, 'A': 9, 'D2': 5}, 'commit': ''}, 'R': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'I': {'description': '查询结果中包含过多信息导致数据泄露', 'Scenario': '过度的信息暴露给IAM', 'dread': {'D': 8, 'R': 6, 'E': 5, 'A': 8, 'D2': 5}, 'commit': ''}, 'D': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}, 'E': {'description': 'None', 'Scenario': 'None', 'dread': {'D': 0, 'R': 0, 'E': 0, 'A': 0, 'D2': 0}, 'commit': ''}}}]}
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
          "description": "恶意用户伪装成合法用户访问系统，因为当前系统没有身份验证机制",
          "Scenario": "系统无法识别真实用户身份，导致未经授权的访问和操作",
          "dread": {
            "D": 1,
            "R": 1,
            "E": 1,
            "A": 1,
            "D2": 1
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
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
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
        },
        "R": {
          "description": "用户执行操作后否定自己的行为",
          "Scenario": "因为没有身份验证和日志记录，无法追踪用户操作，导致责任不明确",
          "dread": {
            "D": 7,
            "R": 8,
            "E": 7,
            "A": 8,
            "D2": 6
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
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
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
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
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
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
          },
          "commit": "我们需要改进一下，D应该xxx，R应该xxx，......"
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
          },
          "commit": ""
        },
        "T": {
          "description": "攻击者篡改IAM处理的数据流，如修改用户权限或访问控制规则",
          "Scenario": "非法获取高权限或敏感数据访问权",
          "dread": {
            "D": 9,
            "R": 8,
            "E": 7,
            "A": 9,
            "D2": 6
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "I": {
          "description": "IAM处理过程中泄露敏感信息，如日志中记录明文密码或密钥",
          "Scenario": "敏感数据被未授权方获取",
          "dread": {
            "D": 9,
            "R": 7,
            "E": 6,
            "A": 9,
            "D2": 5
          },
          "commit": ""
        },
        "D": {
          "description": "攻击者通过大量请求使IAM服务超载",
          "Scenario": "合法用户无法访问系统资源",
          "dread": {
            "D": 7,
            "R": 8,
            "E": 7,
            "A": 9,
            "D2": 6
          },
          "commit": ""
        },
        "E": {
          "description": "攻击者利用IAM漏洞获取更高权限",
          "Scenario": "系统权限被恶意提升，造成更大范围破坏",
          "dread": {
            "D": 9,
            "R": 8,
            "E": 7,
            "A": 9,
            "D2": 6
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "T": {
          "description": "攻击者直接修改数据库中的敏感数据",
          "Scenario": "数据完整性受损，可能导致决策错误",
          "dread": {
            "D": 9,
            "R": 8,
            "E": 7,
            "A": 9,
            "D2": 6
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "I": {
          "description": "数据库未加密或配置不当导致数据泄露",
          "Scenario": "绝密信息外泄，造成严重安全事件",
          "dread": {
            "D": 10,
            "R": 7,
            "E": 6,
            "A": 9,
            "D2": 6
          },
          "commit": ""
        },
        "D": {
          "description": "攻击者执行大量复杂查询耗尽数据库资源",
          "Scenario": "数据库服务不可用，影响整个系统",
          "dread": {
            "D": 8,
            "R": 8,
            "E": 7,
            "A": 9,
            "D2": 7
          },
          "commit": ""
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
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "T": {
          "description": "中间人攻击篡改user和IAM之间传输的数据",
          "Scenario": "传输数据被恶意修改",
          "dread": {
            "D": 8,
            "R": 7,
            "E": 6,
            "A": 9,
            "D2": 5
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "I": {
          "description": "数据未加密传输导致信息泄露",
          "Scenario": "敏感信息被截获",
          "dread": {
            "D": 9,
            "R": 7,
            "E": 6,
            "A": 9,
            "D2": 6
          },
          "commit": ""
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
          },
          "commit": ""
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
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "T": {
          "description": "数据库查询或命令被篡改",
          "Scenario": "数据库执行了恶意操作",
          "dread": {
            "D": 9,
            "R": 7,
            "E": 6,
            "A": 9,
            "D2": 5
          },
          "commit": ""
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
          },
          "commit": ""
        },
        "I": {
          "description": "查询结果中包含过多信息导致数据泄露",
          "Scenario": "过度的信息暴露给IAM",
          "dread": {
            "D": 8,
            "R": 6,
            "E": 5,
            "A": 8,
            "D2": 5
          },
          "commit": ""
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
          },
          "commit": ""
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
          },
          "commit": ""
        }
      }
    }
  ]
}
udb.putCommitJSON2db(hash_id,commit)
commit_json = udb.getCommitJSON(hash_id)
print(commit_json)
print(json.loads(json.dumps(commit_json))==json.loads(json.dumps(commit)))
