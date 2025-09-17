import re
from threat_process.utils import debug, create_reasoning_system_prompt, extract_mermaid_code
import json
from openai import OpenAI
from config import app_attrs
from prompt import ATTCK_PREFIX_PROMPT_ZH, ATTCK_SUFFIX_PROMPT_ZH


def convert_json_to_markdown_attck(attck_data):
    l = attck_data["list"]
    ret  = "| 攻击 | att&ck | 名称 | 描述 |\n"
    ret += "| ---- | ------ | ---- | --- |\n"

    for i in l:
        ret += f"| {i['leaf_node']} | [{i['attck_id']}]({i['attck_url']}) | {i["attck_name"]} | {i['attck_description']} |\n"
    return ret

def merge_attck_into_attack_tree(attack_tree_json, attck_json):
    """
    将 ATT&CK 技术信息作为子节点添加到攻击树的任意节点（含中间节点/叶子）
    """

    # 递归提取 "所有" 节点标签（不只叶子）
    def extract_all_labels(node):
        labels = [node["label"]]
        for ch in node.get("children", []) or []:
            labels.extend(extract_all_labels(ch))
        return labels

    # 收集整个树的所有标签
    all_labels = []
    for node in attack_tree_json["nodes"]:
        all_labels.extend(extract_all_labels(node))

    # 校验：attck_json 里的映射目标必须在树中“存在”（不限叶子）
    attck_targets = [item["leaf_node"] for item in attck_json["list"]]
    invalid_nodes = set(attck_targets) - set(all_labels)
    if invalid_nodes:
        raise ValueError(f"ATT&CK JSON 中有在攻击树中找不到的节点: {invalid_nodes}")

    # 将 ATT&CK 列表预索引：label -> list of techniques
    attck_map = {}
    for item in attck_json["list"]:
        attck_map.setdefault(item["leaf_node"], []).extend(item.get("attck", []))

    mermaid_lines = ["graph TD"]

    def process_node(node, parent_id=None):
        node_id = node.get("id", node["label"].replace(" ", "_"))
        mermaid_lines.append(f'    {node_id}[{node["label"]}]')
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')

        # 无论是否叶子，只要 label 命中，就挂 ATT&CK 技术子节点
        if node["label"] in attck_map:
            for i, tech in enumerate(attck_map[node["label"]], 1):
                tid = f'{node_id}_attck_{i}'
                mermaid_lines.append(f'    {tid}[{tech["attck_id"]}: {tech["attck_name"]}]')
                mermaid_lines.append(f'    {node_id} --> {tid}')

        # 继续递归原有子节点
        for ch in node.get("children", []) or []:
            process_node(ch, node_id)

    for node in attack_tree_json["nodes"]:
        process_node(node)
    ret = "\n".join(mermaid_lines)
    # 为节点名添加双引号，避免解析错误
    ret = ret.replace("[", '["')
    ret = ret.replace("]", '"]')
    return ret

def create_json_attck_prompt_zh(app_input):
    return ATTCK_PREFIX_PROMPT_ZH+f"\nattack tree mermaid:\n{app_input}\n"+ATTCK_SUFFIX_PROMPT_ZH

def clean_json_response(response_text):
    """
    从响应文本中提取并清理JSON内容
    
    该函数尝试从包含````json````格式或``````````格式的文本中提取纯JSON内容，
    如果没有找到代码块则返回去除首尾空白的原始文本
    
    参数:
        response_text (str): 包含JSON内容的原始响应文本，可能包含````json````或``````````标记
    
    返回:
        str: 提取的纯JSON字符串或清理后的原始文本
    """
    
    # 移除````json````格式的JSON代码块
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # 如果没有找到````json````代码块，则尝试查找任何``````````内容
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # 如果没有找到任何``````````代码块，则返回去除首尾空白的原始文本
    return response_text.strip()


# Function to get attck markdown  from the GPT response.
def get_attck_markdown_siliconflow(base_url, api_key, model_name, prompt):
    client = OpenAI(
        base_url=base_url,
        api_key=api_key)

    # For models that support JSON output format
    if model_name in []:
        system_prompt = create_reasoning_system_prompt(
            task_description="分析所提供的攻击树mermaid代码，根据攻击树的叶子节点所提供的攻击手段，找到对应的attck攻击技术",
            approach_description="""分析攻击树，并找到对应的attck攻击技术。

规则：  
- 每个attck技术对应：ID，描述，url
- 包含所有叶子节点
- 确保 JSON 结构正确  

示例格式：
{
    "name": "att-ck",
    "list": [
        {
            "leaf_node": "域控制器身份验证",
            "attck_id": "T1556.002",
            "attck_name": "Password Filter DLL",
            "attck_description": "凭证伪造：伪造数字证书",
            "attck_url": "https://attack.mitre.org/techniques/T1556/002/",
        },
        {
            "leaf_node": "直接访问内部组件",
            "attck_id": "T1133",
            "attck_name": "External Remote Services",
            "attck_description": "外部远程服务访问，通常手段有。。。",
            "attck_url": "https://attack.mitre.org/techniques/T1133/",
        },
        {
            "leaf_node": "左侧进程注入攻击",
            "attck_id": "T1055",
            "attck_name": "Process Injection",
            "attck_description": "进程注入，进程注入的实现方式。。。。",
            "attck_url": "https://attack.mitre.org/techniques/T1055/",
        },
        
    ]
}

**仅返回 JSON 结构，不包含任何额外文本。**"""
        )
        
        response = client.chat.completions.create(
            model=model_name,
            response_format=create_attck_schema(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_completion_tokens=4000
        )
    else:
        # For other models, try to get JSON output without format parameter
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                #{"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000
        )

    # Try to parse JSON response
    try:
        # Clean the response text first
        cleaned_response = clean_json_response(response.choices[0].message.content)
        attck_data = json.loads(cleaned_response)
        return attck_data
        #return convert_json_to_markdown_attck(attck_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        print("attck info json parsing failed")
        return None



def create_attck_schema():
    return {
    "name": "att-ck",
    "list": [
        {
            "leaf_node": "域控制器身份验证",
            "attck_id": "T1556.002",
            "attck_name": "Password Filter DLL",
            "attck_description": "凭证伪造：伪造数字证书",
            "attck_url": "https://attack.mitre.org/techniques/T1556/002/",
        },
        {
            "leaf_node": "直接访问内部组件",
            "attck_id": "T1133",
            "attck_name": "External Remote Services",
            "attck_description": "外部远程服务访问，通常手段有。。。",
            "attck_url": "https://attack.mitre.org/techniques/T1133/",
        },
        {
            "leaf_node": "左侧进程注入攻击",
            "attck_id": "T1055",
            "attck_name": "Process Injection",
            "attck_description": "进程注入，进程注入的实现方式。。。。",
            "attck_url": "https://attack.mitre.org/techniques/T1055/",
        },
    ]
}

