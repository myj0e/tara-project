from openai import OpenAI
import re, json

from threat_process.utils import debug, create_reasoning_system_prompt

from prompt import *

def create_mitigations_prompt_zh(threats, attck_info):
    prompt = MITIGATIONS_PREFIX_PROMPT_ZH+f"{threats}\n{attck_info}"+MITIGATIONS_SUFFIX_PROMPT_ZH
    return prompt

# Function to get mitigations from the GPT response.
def get_mitigations_siliconflow(base_url, api_key, model_name, prompt):
    client = OpenAI(
        base_url=base_url,
        api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in []:
        system_prompt = create_reasoning_system_prompt(
            task_description="使用 STRIDE 方法论为已识别的威胁生成有效的安全缓解措施。",
            approach_description="""1. 分析提供的威胁模型中的每个威胁  
2. 对于每个威胁：  
   - 理解威胁类型和场景  
   - 考虑潜在影响  
   - 识别适当的安控措施和缓解措施  
   - 确保缓解措施具体且可操作  
3. 以 Markdown 表格格式输出，包含以下列：  
   - 威胁类型  
   - 场景  
   - 建议的缓解措施  
4. 确保缓解措施遵循安全最佳实践和行业标准"""
        )
    else:
        system_prompt = "你是一个提供威胁缓解策略的助手，以 Markdown 格式输出。"

    response = client.chat.completions.create(
        model = model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations
#==========================JSON=====================================
# 要求模型只输出 JSON
JSON_SYSTEM_PROMPT = """
你是安全缓解措施助手。仅输出一个 JSON 代码块（```json ... ```），必须符合：
{
  "items": [
    {
      "component": "Actor | GUI | Wallet | Browser | Exchange Web Site | Exchange Backend | Exchange API | MongoDB | Blockchain Integration | Trading Bot | ...",
      "threat_type": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege | ...",
      "scenario": "string",
      "mitigations": ["string", "string", "..."]
    }
  ],
  "summary": ["string", "string", "..."]
}
不要输出解释、前后缀或任何非 JSON 内容；如无法满足，也要输出空数组字段的 JSON。
"""

def _extract_json_block(text: str) -> dict:
    """优先抓 ```json … ``` 代码块；没有就回退到全文第一段 {...}。"""
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.S | re.I)
    if m:
        return json.loads(m.group(1))
    m2 = re.search(r"\{.*\}", text, re.S)
    if not m2:
        raise ValueError("模型未返回可解析的 JSON。原始内容片段：%s" % text[:200])
    return json.loads(m2.group(0))

def get_mitigations_json_siliconflow(base_url: str, api_key: str, model_name: str,
                                     prompt: str, temperature: float = 0.2) -> dict:
    """
    调用大模型并返回“规范 JSON”（dict）。
    保持你的 OpenAI SDK 用法，只是把 system prompt 换成 JSON 约束，并解析为 dict 返回。
    """
    client = OpenAI(base_url=base_url, api_key=api_key)

    # 网关/模型支持 JSON 强制模式，可解注下一行（不支持就去掉）：
    # response_format = {"type": "json_object"}
    # 否则仅靠 system prompt + 解析器兜底。

    resp = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": JSON_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=temperature,
        # response_format=response_format,
    )
    raw = resp.choices[0].message.content
    data = _extract_json_block(raw)

    # 宽容补全必备字段，保证 CRUD 侧稳定
    data.setdefault("items", [])
    data.setdefault("summary", [])

    return data

