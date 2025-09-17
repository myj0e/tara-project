import re
import json
import os
import hashlib
from functools import wraps
import time


def extract_deepseek_reasoning(response_text):
    """
    Extract reasoning and final output from DeepSeek R1 model response.
    The reasoning is contained within <think></think> tags.
    
    Args:
        response_text (str): The raw response text from the model
        
    Returns:
        tuple: (reasoning, final_output)
            - reasoning: The extracted reasoning text, or None if no reasoning found
            - final_output: The remaining text after removing the reasoning
    """
    # Look for content within <think></think> tags
    think_pattern = r'<think>(.*?)</think>'
    think_match = re.search(think_pattern, response_text, re.DOTALL)
    
    if think_match:
        reasoning = think_match.group(1).strip()
        # Remove the think tags and their content to get the final output
        final_output = re.sub(think_pattern, '', response_text, flags=re.DOTALL).strip()
        return reasoning, final_output
    else:
        # If no think tags found, return None for reasoning and the original text as final output
        return None, response_text

def extract_mermaid_code(text):
    """
    Extract the Mermaid diagram code from text that may contain additional content.
    Looks for code between ```mermaid, ``` or just ``` tags, and extracts the graph content.
    Also cleans and validates the Mermaid syntax.
    
    Args:
        text (str): The text containing the Mermaid code
        
    Returns:
        str: The cleaned Mermaid code, or the original text if no code block is found
    """
    # Try to find code block with explicit mermaid tag
    mermaid_pattern = r'```mermaid\s*(graph[\s\S]*?)```'
    match = re.search(mermaid_pattern, text, re.MULTILINE)
    
    if not match:
        # Try to find any code block containing graph definition
        code_pattern = r'```\s*(graph[\s\S]*?)```'
        match = re.search(code_pattern, text, re.MULTILINE)
    
    if match:
        # Extract just the graph content
        code = match.group(1).strip()
    else:
        # If no code block found but text contains graph definition, use as is
        code = text.strip()
    
    # Only proceed if we have a graph definition
    if not code.startswith('graph '):
        if 'graph ' in code:
            # Find the start of the graph definition
            code = code[code.find('graph '):]
        else:
            return text

    # Clean up common issues in Mermaid syntax
    code = clean_mermaid_syntax(code)
    
    return code

def clean_mermaid_syntax(code):
    """
    Clean up common issues in Mermaid syntax.
    
    Args:
        code (str): The Mermaid code to clean
        
    Returns:
        str: The cleaned Mermaid code
    """
    # Ensure proper spacing around arrows
    code = re.sub(r'(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)', r'\1 \2 \3', code)
    
    # Fix missing brackets around node labels
    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in '[](){}'):
            return f'{node_id}[{node_id}]'
        return node_id
    code = re.sub(r'(?:^|\s)(\w+)(?:\s|$)', fix_node_brackets, code)
    
    # Ensure node IDs with spaces are properly quoted
    def quote_node_labels(match):
        label = match.group(1)
        if ' ' in label and not label.startswith('"'):
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', quote_node_labels, code)
    
    # Fix parentheses in node labels
    def fix_parentheses(match):
        label = match.group(1)
        if '(' in label or ')' in label:
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', fix_parentheses, code)
    
    # Ensure proper line endings
    code = code.replace('\r\n', '\n').strip()
    
    return code


def create_reasoning_system_prompt(task_description, approach_description):
    """
    Creates a system prompt formatted for OpenAI's reasoning models (o1, o3, o3-mini, o4-mini).
    
    Args:
        task_description (str): Description of what the model needs to do
        approach_description (str): Step-by-step approach the model should follow
        
    Returns:
        str: Formatted system prompt
    """
    return f"""Task: {task_description}

Approach:
{approach_description}""" 

# 创建文件夹，若存在什么都不做
def create_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return folder_path

# 向文件中写入list内容
def write_list_to_file(path, filename, list_data):
    file_path = os.path.join(path, filename)
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in list_data:
            file.write(item + '\n')

# 从文件中读取list内容，若文件不存在创建空文件
def read_list_from_file(path, filename):
    file_path = os.path.join(path, filename)
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as file:
            pass
    with open(file_path, 'r', encoding='utf-8') as file:
        return [line.strip() for line in file]

# 向路径path目录中，创建json文件，json内容（content）为dict格式
def write_json_file(path, filename_withoutsuffix, content):
    json_file_path = os.path.join(path, filename_withoutsuffix + ".json")
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(content, json_file, indent=4)

# 从路径path目录中，读取json文件，并返回json内容（dict格式）
def read_json_file(path, filename_withoutsuffix):
    json_file_path = os.path.join(path, filename_withoutsuffix + ".json")
    with open(json_file_path, 'r', encoding='utf-8') as json_file:
        return json.load(json_file)

# 向路径path中写入md文件
def write_md_file(path, filename_withoutsuffix, content):
    md_file_path = os.path.join(path, filename_withoutsuffix + ".md")
    with open(md_file_path, 'w', encoding='utf-8') as md_file:
        md_file.write(content)
# 从路径path中，读取md文件，并返回md内容（str格式）
def read_md_file(path, filename_withoutsuffix):
    md_file_path = os.path.join(path, filename_withoutsuffix + ".md")
    with open(md_file_path, 'r', encoding='utf-8') as md_file:
        return md_file.read()

# dict to hash，保证相同内容的dict，hash值相同，同时允许传入字典嵌套字典，列表，元组
def dict_to_hash(input_dict):
    # 将字典转换为JSON字符串，并确保排序
    sorted_json_str = json.dumps(input_dict, sort_keys=True)
    # 使用SHA-256算法生成哈希值
    hash_object = hashlib.sha256(sorted_json_str.encode())
    # 获取十六进制表示的哈希值，并去除符号
    hex_dig = hash_object.hexdigest()
    return hex_dig


def timer_decorator(func):
    """装饰器：打印函数名及其执行时间"""
    @wraps(func)  # 保留原函数的元信息
    def wrapper(*args, **kwargs):
        # 打印函数名称
        print(f"函数 {func.__name__} 开始执行...")
        
        # 记录开始时间
        start_time = time.perf_counter()
        
        # 执行原函数并获取返回值
        result = func(*args, **kwargs)
        
        # 计算执行时间
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        # 打印执行时间
        print(f"函数 {func.__name__} 执行完成，耗时: {execution_time:.6f} 秒")
        
        # 返回原函数的返回值
        return result
    return wrapper

def debug(message, end = '\n'):
    if 1:
        print(message, end=end, flush=True)
    else:
        pass