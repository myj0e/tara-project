import re
from threat_process.utils import debug, create_reasoning_system_prompt, extract_mermaid_code
import json
from openai import OpenAI
from config import app_attrs
from prompt import ATTACK_TREE_PREFIX_PROMPT_ZH, ATTACK_TREE_SUFFIX_PROMPT_ZH

def create_attack_tree_prompt_zh(appAttr:app_attrs, app_input, stride_model):
    prompt = f"""
应用程序类型：{appAttr.app_type}  
认证方式：{appAttr.authentication}  
是否面向互联网：{appAttr.internet_facing}  
敏感数据：{appAttr.sensitive_data}  
应用程序描述：{app_input}
应用程序STRIDE威胁建模：{stride_model}
"""
    return ATTACK_TREE_PREFIX_PROMPT_ZH+prompt+ATTACK_TREE_SUFFIX_PROMPT_ZH

def convert_tree_to_mermaid(tree_data):
    """
    将结构化树数据转换为 Mermaid 语法。

    参数：  
        tree_data (dict)：包含树结构的字典  

    返回：  
        str：Mermaid 图表示例代码
    """
    mermaid_lines = ["graph TD"]
    
    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]
        
        # Add quotes if label contains spaces or parentheses
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'
        
        # Add the node definition
        mermaid_lines.append(f'    {node_id}[{node_label}]')
        
        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')
        
        # Process children
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)
    
    # Process the root node(s)
    for root_node in tree_data["nodes"]:
        process_node(root_node)
    
    # Join lines with newlines
    return "\n".join(mermaid_lines)


def clean_json_response(response_text):
    """
    Clean JSON response by removing any markdown code block markers and finding the JSON content.
    
    Args:
        response_text (str): The raw response text that might contain JSON
        
    Returns:
        str: Cleaned JSON string
    """
    # Remove markdown JSON code block if present
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no code blocks, return the original text
    return response_text.strip()


# Function to get attack tree from the GPT response.
def get_attack_tree_siliconflow(base_url, api_key, model_name, prompt):
    client = OpenAI(
        base_url=base_url,
        api_key=api_key)

    # For models that support JSON output format
    if model_name in []:
        system_prompt = create_reasoning_system_prompt(
            task_description="通过分析潜在攻击路径，创建一个结构化的攻击树。",
            approach_description="""分析应用程序，并创建一个展示潜在攻击路径的攻击树。

规则：  
- 使用简单的字母数字 ID（如 A1、A2、B1 等）  
- 使标签清晰且具有描述性  
- 包含所有攻击路径和子路径  
- 保持正确的父子关系  
- 确保 JSON 结构正确  

示例格式：
{
    "nodes": [
        {
            "id": "A1",
            "label": "攻破应用程序",
            "children": [
                {
                    "id": "B1",
                    "label": "利用身份验证漏洞",
                    "children": [
                        {
                            "id": "C1",
                            "label": "暴力破解凭证",
                            "children": []
                        }
                    ]
                }
            ]
        }
    ]
}

**仅返回 JSON 结构，不包含任何额外文本。**"""
        )
        
        response = client.chat.completions.create(
            model=model_name,
            response_format=create_attack_tree_schema(),
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
        tree_data = json.loads(cleaned_response)
        return tree_data
        #return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        print("attack tree json parsing failed")
        return None
        #return extract_mermaid_code(response.choices[0].message.content)



def create_attack_tree_schema():
    """
    Creates a JSON schema for attack tree structure.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "$ref": "#/$defs/node"
                        }
                    }
                },
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node"
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal"
                            },
                            "children": {
                                "type": "array",
                                "items": {
                                    "$ref": "#/$defs/node"
                                }
                            }
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False
            },
            "strict": True
        }
    }

