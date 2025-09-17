import json

from openai import OpenAI
from prompt import (
    DREAD_ASSESSMENT_PREFIX_PROMPT_ZH, 
    DREAD_ASSESSMENT_SUFFIX_PROMPT_ZH
)
from threat_process.utils import debug, create_reasoning_system_prompt

def dread_json_to_markdown(dread_assessment):
    # Create a clean Markdown table with proper spacing
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|\n"
    
    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])
        
        # If there are no threats, add a message row
        if not threats:
            markdown_output += "| No threats found | Please generate a threat model first | - | - | - | - | - | - |\n"
            return markdown_output
            
        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                # Get values with defaults
                threat_type = threat.get('Threat Type', 'N/A')
                scenario = threat.get('Scenario', 'N/A')
                damage_potential = threat.get('Damage Potential', 0)
                reproducibility = threat.get('Reproducibility', 0)
                exploitability = threat.get('Exploitability', 0)
                affected_users = threat.get('Affected Users', 0)
                discoverability = threat.get('Discoverability', 0)
                
                # Calculate the Risk Score
                risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5
                
                # Escape any pipe characters in text fields to prevent table formatting issues
                threat_type = str(threat_type).replace('|', '\\|')
                scenario = str(scenario).replace('|', '\\|')
                
                # Ensure scenario text doesn't break table formatting by limiting length and removing newlines
                if len(scenario) > 100:
                    scenario = scenario[:97] + "..."
                scenario = scenario.replace('\n', ' ').replace('\r', '')
                
                # Add the row to the table with proper formatting
                markdown_output += f"| {threat_type} | {scenario} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                # Skip non-dictionary entries and log a warning
                markdown_output += "| Invalid threat | Threat data is not in the correct format | - | - | - | - | - | - |\n"
    except Exception as e:
        # Add a note about the error and a placeholder row
        markdown_output += "| Error | An error occurred while processing the DREAD assessment | - | - | - | - | - | - |\n"
    
    # Add a blank line after the table for better rendering
    markdown_output += "\n"
    return markdown_output

# Function to create a prompt to generate mitigating controls
def create_dread_assessment_prompt_zh(threats, attck_info):
    return DREAD_ASSESSMENT_PREFIX_PROMPT_ZH+f"系统威胁模型：{threats}\n系统攻击树与对应att&ck技术{attck_info}\n"+DREAD_ASSESSMENT_SUFFIX_PROMPT_ZH

def clean_json_response(response_text):
    import re
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

def get_dread_assessment_siliconflow(base_url, api_key, model_name, prompt):
    #print("生成dread评估结果")
    client = OpenAI(
        base_url=base_url,
        api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in []:
        system_prompt = create_reasoning_system_prompt(
            task_description="对已识别的安全威胁执行 DREAD 风险评估。",
            approach_description="""
1. 对于提供的威胁模型中的每个威胁：  
   - 详细分析威胁类型和场景  
   - 评估损害潜力（1-10）：  
     * 考虑直接和间接损害  
     * 评估财务、声誉和运营影响  
   - 评估可重现性（1-10）：  
     * 评估攻击可被重现的可靠性  
     * 考虑所需的条件和资源  
   - 评估可利用性（1-10）：  
     * 分析技术复杂度  
     * 考虑所需技能和工具  
   - 评估受影响用户（1-10）：  
     * 确定影响范围  
     * 考虑直接和间接用户  
   - 评估可发现性（1-10）：  
     * 评估漏洞被发现的难易程度  
     * 考虑可见性和检测方法  
2. 以 JSON 格式输出，包含一个名为 "Risk Assessment" 的数组，内容包括：  
   - 威胁类型  
   - 场景  
   - 每个 DREAD 类别的数值评分（1-10）"""
        )
    else:
        system_prompt = "你是一个旨在输出 JSON 格式的有帮助的助手。"

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        # Handle error silently
        print("get dread assessment json parsing failed")
        dread_assessment = {}

    #print("dread assessment:", dread_assessment)
    return dread_assessment
