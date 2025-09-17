import json

from openai import OpenAI
from prompt import (
    THREAT_MODEL_PREFIX_PROMPT_ZH, 
    THREAT_MODEL_SUFFIX_PROMPT_ZH
)
from config import app_attrs
from threat_process.utils import debug, create_reasoning_system_prompt


def description_to_stride_threats_Json(
        base_url:str, api_key:str, model_name:str, 
        description: str, appAttr:app_attrs):
    prompt = create_threat_model_prompt_zh(appAttr=appAttr ,app_input=description)
    try:
        description = get_threat_model_SiliconFlow(base_url, api_key, model_name, prompt)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return description

# Function to convert JSON to Markdown for display.    
def stride_json_to_markdown(components):
    markdown_output = "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Component | Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-----------|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for element in components:
        for i in element["stride"]:
            markdown_output += f"| {element['name']} | {i["Threat Type"]} | {i['Scenario']} | {i['Potential Impact']} |\n"

    
    return markdown_output



# Function to create a prompt for generating a threat model
def create_threat_model_prompt_zh(appAttr:app_attrs, app_input):
    prompt = THREAT_MODEL_PREFIX_PROMPT_ZH+f"""
应用程序类型：{appAttr.app_type}  
认证方式：{appAttr.authentication}  
是否面向互联网：{appAttr.internet_facing}  
敏感数据：{appAttr.sensitive_data}  
代码摘要、README 内容及应用程序描述：  
{app_input}
"""+THREAT_MODEL_SUFFIX_PROMPT_ZH
    return prompt

def create_image_analysis_prompt_zh():
    prompt = """
作为高级解决方案架构师，你的任务是向安全架构师解释以下架构图以支持系统的威胁建模。

为了完成此任务，你必须：

分析图表
向安全架构师解释系统架构。你的解释应涵盖关键组件、它们之间的交互以及使用的所有技术。
提供对图表的直接解释，采用清晰、结构化的格式，适合专业讨论。

重要说明：

解释时不要在前面或后面添加任何词语。例如，不要以“图像显示...”或“图表显示...”开头，直接开始解释关键组件和其他相关细节。
不要推断或猜测图表中未明确显示的信息。仅提供可以直接从图表中确定的信息。
    """
    return prompt

def get_image_analysis_siliconflow(base_url, api_key, model_name, prompt, base64_image):
    client = OpenAI(
        base_url=base_url,
        api_key=api_key)

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": prompt
                },
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}
                }
            ]
        }
    ]
    
    # If using o4-mini, use the structured system prompt approach
    if model_name in []:
        system_prompt = create_reasoning_system_prompt(
            task_description="分析提供的架构图，并向安全架构师解释。",
            approach_description="""1. 仔细检查图表  
2. 确定所有组件及其关系  
3. 记录显示的任何技术、协议或安全措施  
4. 创建清晰、结构化的解释，包含以下部分：  
   - 总体架构：系统的简要概述  
   - 关键组件：列出并解释每个主要组件  
   - 数据流：信息如何在系统中流动  
   - 使用的技术：识别技术、框架或平台  
   - 安全考虑：记录任何可见的安全措施"""
        )
        # Insert system message at the beginning
        messages.insert(0, {"role": "system", "content": system_prompt})
        
        # Create completion with max_completion_tokens for reasoning models
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_completion_tokens=4000
            )
            return {
                "choices": [
                    {"message": {"content": response.choices[0].message.content}}
                ]
            }
        except Exception as e:
            return None
    else:
        # For standard models (gpt-4, etc.)
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_tokens=4000
            )
            return {
                "choices": [
                    {"message": {"content": response.choices[0].message.content}}
                ]
            }
        except Exception as e:
            return None

def get_threat_model_SiliconFlow(sf_base_url, sf_api_key, sf_model, prompt):
    client = OpenAI(base_url=sf_base_url, api_key=sf_api_key)

    response = client.chat.completions.create(
        model=sf_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "你是一个旨在输出 JSON 格式的有帮助的助手。"},
            {"role": "user", "content": prompt}
        ],
        stream=False
    )
    response_content = json.loads(response.choices[0].message.content)
    return response_content
