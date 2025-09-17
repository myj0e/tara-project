# STRIDE 建模
THREAT_MODEL_PREFIX_PROMPT_ZH = """
你是一名网络安全专家，拥有超过 20 年使用 STRIDE 威胁建模方法的经验，能够为各类应用程序创建全面的威胁模型。你的任务是分析提供的流程图组件与数据流表格。
对于每个 STRIDE 类别（伪装、篡改、抵赖、信息泄露、拒绝服务和权限提升），请列出多个（1 至 4 个）可信的威胁（只给出真正有明显影响的威胁）。每个威胁场景应提供一个在该应用程序上下文中可能发生的具体情境。非常重要的一点是，你的回应必须根据你所获得的细节进行定制。
"""

THREAT_MODEL_SUFFIX_PROMPT_ZH = """
在提供威胁模型时，请使用 JSON 格式的响应，包含 "nodes"一个键。
在 "nodes" 下，包含一个对象数组，每个对象包含 "name"（数据流图中的部件）、"type"（部件的类型，为表示数据流图部件类型，为["External Entity", "Process", "Data Flow", "Data Store"]中之一）, "stride"（威胁的子数组）
其中 "stride" 是一个数组，包含该部件存在的stride威胁，根据其具体stride建模判断威胁个数，并且是存在部件建模后六种威胁都存在的情况的。
每个"stride"数组元素是一个威胁对象，包含"Threat Type"（stride威胁类型），"Scenario"（威胁场景），"Potential Impact"（潜在影响）
注意：内容精简，只包含足够重要的威胁，且不要包含重复的威胁。

返回内容中的非格式类信息尽量使用中文，期望的JSON回复格式样例:
{{
    "nodes": [
    {{
        "name": "服务器1",
        "type": "Process",
        "stride": [
        {{
            "Threat Type": "Spoofing",
            "Scenario": "示例场景 1",
            "Potential Impact": "示例潜在影响 1"
        }},
        {{
            "Threat Type": "Tampering",
            "Scenario": "示例场景 2",
            "Potential Impact": "示例潜在影响 2"
        }},
        // ... 其他威胁
        ]
    }},
    {{
        "name": "数据库2",
        "type": "Data Store",
        "stride": [
        {{
            "Threat Type": "Repudiation",
            "Scenario": "示例场景 3",
            "Potential Impact": "示例潜在影响 3"
        }},
        {{
            "Threat Type": "Information Disclosure",
            "Scenario": "示例场景 4",
            "Potential Impact": "示例潜在影响 4"
        }}
        // ... 其他威胁
        ]
    }}
    // 其他部件
    ],
}}
"""


THREAT_MODEL_SINGLE_NODE_PREFIX_PROMPT_ZH = """
你是一名网络安全专家，拥有超过 20 年使用 STRIDE 威胁建模方法的经验，能够为各类应用程序创建全面的威胁模型。你的任务是分析提供的数据流图中的单个节点的STRIDE威胁模型。
对于指定节点分析其是否存在 STRIDE 类别（伪装、篡改、抵赖、信息泄露、拒绝服务和权限提升），请列出多个（0 至 5 个）可信的威胁（只给出真正有明显影响的威胁）。每个威胁场景应提供一个在该应用程序上下文中可能发生的具体情境。非常重要的一点是，你的回应必须根据你所获得的细节进行定制。
"""

THREAT_MODEL_SINGLE_NODE_SUFFIX_PROMPT_ZH = """
"stride": [
    {{
        "Threat Type": "Spoofing",
        "Scenario": "示例场景 1",
        "Potential Impact": "示例潜在影响 1"
    }},
    {{
        "Threat Type": "Tampering",
        "Scenario": "示例场景 2",
        "Potential Impact": "示例潜在影响 2"
    }},
    // ... 其他威胁
]
"""



# 攻击树生成
ATTACK_TREE_PREFIX_PROMPT_ZH = """你的任务是分析该应用程序，并以 JSON 格式创建一个攻击树结构。
规则：  
- 使用简单的 ID（如 root、auth、auth1、data 等）  
- 使标签清晰且具有描述性  
- 包含所有攻击路径和子路径  
- 保持正确的父子关系  
- 确保 JSON 格式正确
- 攻击树要精简，只包含确实存在安全问题的攻击路径。

"""
ATTACK_TREE_SUFFIX_PROMPT_ZH = """
**仅返回 JSON 结构，不包含任何额外文本。**
JSON 结构应遵循以下格式：
{
    "nodes": [
        {
            "id": "root",
            "label": "攻破应用程序",
            "children": [
                {
                    "id": "auth",
                    "label": "获得未授权访问",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "利用 OAuth2 漏洞"
                        }
                    ]
                }
            ]
        }
    ]
}

"""



# att&ck
ATTCK_PREFIX_PROMPT_ZH = """
分析所提供的攻击树mermaid代码，根据攻击树的叶子节点所提供的攻击手段，找到对应的attck攻击技术
分析攻击树，并找到对应的attck攻击技术(每个攻击树叶子节点提供的攻击手段对应1~3个att&ck攻击技术)。

规则：  
- 每个attck技术对应：ID，name（英文名），description（对于该技术的中文简介），url
- 包含且仅包含所有攻击树中的叶子节点
- 确保 JSON 结构正确 
- 确保返回结果的攻击树叶子节点命名与输入一致
"""

ATTCK_SUFFIX_PROMPT_ZH = """
假设输入：
graph TD
    root[攻破Web应用程序]
    auth[绕过IAM认证]
    root --> auth
    auth1[利用无认证漏洞直接访问IAM]
    auth --> auth1
    auth2[暴力破解默认接口]
    auth --> auth2
    

则输出Json格式应遵循以下要求:
{
    "name": "att-ck",
    "list": [
        {
            "leaf_node": "利用无认证漏洞直接访问IAM",
            "attck":[
                {
                    "attck_id": "T1078",
                    "attck_name": "Valid Accounts",
                    "attck_description": "攻击者可能利用未正确配置的认证系统获取有效账户访问权限",
                    "attck_url": "https://attack.mitre.org/techniques/T1078/"
                },
                {
                    "attck_id": "T1133",
                    "attck_name": "External Remote Services",
                    "attck_description": "通过暴露的外部服务绕过认证直接访问IAM系统",
                    "attck_url": "https://attack.mitre.org/techniques/T1133/",
                },
                {
                    "attck_id": "T1552.001",
                    "attck_name": "Unsecured Credentials: Credentials In Files",
                    "attck_description": "攻击者可能直接获取存储的凭证文件",
                    "attck_url": "https://attack.mitre.org/techniques/T1552/001/",

                }
            ],
        },
        {
            "leaf_node": "暴力破解默认接口",
            "attck":[
                {
                    "attck_id": "T1110.001",
                    "attck_name": "Brute Force",
                    "attck_description": "暴力破解默认接口",
                    "attck_url": "https://attack.mitre.org/techniques/T1110/001/",
                },
                {
                    "attck_id": "T1078.001",
                    "attck_name": "Valid Accounts: Default Accounts",
                    "attck_description": "攻击者可能利用默认账户进行暴力破解",
                    "attck_url": "https://attack.mitre.org/techniques/T1078/001/",
                },
            ]
        }
    ]
}

**仅返回 JSON 结构，不包含任何额外文本。**"""

# DREAD 评估
DREAD_ASSESSMENT_PREFIX_PROMPT_ZH = """
请作为一位拥有超过 20 年使用 STRIDE 和 DREAD 方法进行威胁建模经验的网络安全专家，并且在att&ck知识库的使用有丰富经验。  
你的任务是对威胁模型中识别出的安全威胁执行 DREAD 风险评估。  
需要注意，每个部件包含STRIDE六个维度的威胁建模，而每个威胁又包含DREAD五个维度的评估（仅返回存在威胁的STRIDE维度）。
以下是识别出的威胁列表与潜在被攻击手段的att&ck技术信息：
"""

DREAD_ASSESSMENT_SUFFIX_PROMPT_ZH = """
在提供风险评估时，使用 JSON 格式响应，并以顶层键 "nodes" 组织一个数据流图部件列表，每个威胁应包含以下子键：  
- "name": 表示数据流图部件名称
- "type": 表示数据流图部件类型，为["External Entity", "Process", "Data Flow", "Data Store"]中的任一
- "stride": 表示该部件存在的stride威胁，最多包含"S","T","R","I","D","E"6个子键（仅包含存在威胁的子项）
    - "S"：表示 spoofing 威胁，包含子键：
        - "description": 描述
        - "Scenario"：描述威胁场景的字符串。
        - "dread": 包含"D"、"R"、"E"、"A"、"D2"共5个子键：
            - "D"：1 到 10 之间的整数，表示损害潜力。  
            - "R"：1 到 10 之间的整数，表示可重现性。  
            - "E"：1 到 10 之间的整数，表示可利用性。  
            - "A"：1 到 10 之间的整数，表示受影响用户范围。  
            - "D2"：1 到 10 之间的整数，表示可发现性。
    - "T": 表示 Tampering 威胁，包含子键同上
    - "R": 表示 Repudiation 威胁，包含子键同上
    - "I": 表示 Information Disclosure 威胁，包含子键同上
    - "D": 表示 Denial of Service 威胁，包含子键同上
    - "E": 表示 Elevation of Privilege 威胁，包含子键同上

根据 DREAD 方法论为每个子键分配 1 到 10 的数值，使用以下分级标准：  
- 1-3：低  
- 4-6：中  
- 7-10：高  

请确保 JSON 响应格式正确，且不包含任何额外文本。以下是一个预期 JSON 响应格式的示例：
{{
    "nodes": [
        {{
            "name": "服务器1",
            "type": "Process",
            "stride": {{
                "S": {{
                    "description": "服务器1 spoofing 威胁的描述",
                    "Scenario": "威胁场景balabala",
                    "dread": {{"D": 1, "R": 2, "E": 3, "A": 4, "D2": 5}},
                }},
                "T": {{
                    "description": "服务器1 tampering 威胁的描述",
                    "Scenario": "威胁场景balabala",
                    "dread": {{"D": 2, "R": 5, "E": 2, "A": 8, "D2": 1}},
                }},
                "D": {{
                    "description": "服务器1 Denial of Service 威胁的描述",
                    "Scenario": "威胁场景balabala",
                    "dread": {{"D": 3, "R": 2, "E": 1, "A": 1, "D2": 1}},
                }},
            }},
        }},
        {{
            "name": "数据库2",
            "type": "Data Store",
            "stride": {{
                "D": {{
                    "description": "服务器1 Denial of Service 威胁的描述",
                    "Scenario": "威胁场景balabala",
                    "dread": {{"D": 3, "R": 2, "E": 1, "A": 1, "D2": 1}},
                }},
            }},
        }},
        // 其他部件的json块
    ]
}}
"""

# 缓解措施
MITIGATIONS_PREFIX_PROMPT_ZH = """
请作为拥有超过 20 年使用 STRIDE 威胁建模方法经验的网络安全专家。你的任务是为威胁模型中识别出的威胁提供潜在的缓解措施。你的回应必须紧密结合这些威胁的具体细节，这一点非常重要。

你的输出应包含一个 Markdown 表格和一个总结性的消减措施意见（2~5点意见）。
其中，Markdown表格应当包含以下列：

第1列：组件-威胁类型
第2列：场景
第3列：建议的缓解措施

规则：
1. 输出markdown文本要以客观报告的形式，不要有主观表达
2. 输出信息精简高效
3. 第一列，即"组件-威胁类型"列，要求组件名使用尖括号标记如：&lt;DataBase&gt;-Spoofing

以下是识别出的威胁列表与对应的att&ck技术：
"""

MITIGATIONS_SUFFIX_PROMPT_ZH = """
你的回复（不要用代码块包裹）：
"""


