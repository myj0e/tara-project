"""
基于LangGraph的Agent和Function Calling演示

这个文件展示了如何使用LangGraph创建一个可以调用自定义函数的Agent。
"""

from typing import Annotated, Literal, TypedDict
from typing_extensions import NotRequired
import operator
from pydantic import BaseModel, Field
import requests
import math
from datetime import datetime, timezone
from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage, AIMessage
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
import shlex
import os
import subprocess

# 配置模型连接信息
SYSTEM_PROMPT="""
你是一个网络安攻防智能助手,你需要根据前后文已有信息和用户提供的目标考虑你当前应当做什么，使用什么工具。
规则：
1. 当用户给出一个任务，如检测目标漏洞时，自主使用工具无需询问用户“是否要使用xxx进行”
2. 工具使用后请根据结果判断是否达到用户任务目的，若没有自主进行后续步骤与工具调用，无需询问用户
助手的工作思路示例：
用户：请帮我扫描 主机A（IP: 192.168.1.1）的漏洞
助手的执行流程：调用ping检测存活-发现ping不通-继续以nmap禁用ping的方式扫描-找到开放端口-使用fscan扫描对应的端口-获得扫描结果-返回用户
（这个过程中非必要不询问用户，尽可能自主调用工具）
以下是提供给你的工具（有且仅有这些工具）：
"""
# 定义允许执行的命令及其功能描述（核心配置：限制Agent只能使用这些命令）
ALLOWED_COMMANDS: dict[str, str] = {
    "sqlmap": "sql漏洞扫描工具，专门用于检测数据库的SQL注入漏洞。",
    "ifconfig": "网络配置工具，用于查看和设置网络接口的配置信息。",
    "fscan": "内网综合扫描工具，支持一键自动化和全方位的漏洞扫描（示例：fscan -h 127.0.0.1）。",
    "nmap": "网络扫描工具，用于扫描网络中的主机和端口。",
    "curl": "网络工具，用于从指定的URL下载数据（注意：特殊符号需URL编码）。",
    "echo": "系统工具，用于打印环境变量或文本（示例：echo $PATH）。",
    "uname": "系统工具，用于获取系统信息（示例：uname -a）。",
}

def setup_tool_paths(tool_dir):
    """从环境变量获取工具路径并添加到系统PATH"""
    
    if tool_dir and os.path.isdir(tool_dir):
        # 将工具目录添加到PATH（兼容Windows和类Unix系统）
        path_sep = ";" if os.name == "nt" else ":"
        os.environ["PATH"] = f"{tool_dir}{path_sep}{os.environ['PATH']}"
        return True
    return False

def commandLog(func):
    """命令执行日志"""
    def wrapper(*args, **kwargs):
        command = args[0] if args else ""
        # 打印命令开关
        log_cmd_sw = True
        # 打印输出开关
        log_out_sw = True
        if log_cmd_sw:
            if(type(command)==str):
                print(f"执行命令: {command}")
            elif(type(command)==list):
                print(f"执行命令: {" ".join(command)}")
        result = func(*args, **kwargs)
        if log_out_sw:
            print(f"命令输出: {result}")
        return result
    return wrapper

subprocess.run = commandLog(subprocess.run)


@tool
def execute_command(command: str) -> str:
    """
    执行指定的系统命令（仅支持预定义的安全命令）。
    
    支持的命令及功能：
    {% for cmd, desc in ALLOWED_COMMANDS.items() %}
    - {{ cmd }}: {{ desc }}
    {% endfor %}
    
    Args:
        command (str): 要执行的完整命令（例如"nmap -p 80 127.0.0.1"）
    
    Returns:
        str: 命令执行结果或错误信息
    """
    try:
        # 提取命令名称（第一个空格前的部分）
        cmd_name = command.split()[0].lower()
        
        # 验证命令是否在允许的列表中
        if cmd_name not in ALLOWED_COMMANDS:
            return f"错误：不支持的命令 '{cmd_name}'。支持的命令：{list(ALLOWED_COMMANDS.keys())}"
        
        
        # 统一执行命令（根据命令特性调整参数，这里统一使用shell=True以便解析完整命令）
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True  # 命令执行失败时抛出CalledProcessError
        )
        
        # 返回处理后的结果
        return result.stdout.strip()
    
    except IndexError:
        return "错误：无效的命令格式（命令不能为空）"
    except subprocess.CalledProcessError as e:
        return f"命令执行失败：{e.stderr.strip() or '未知错误'}"
    except Exception as e:
        return f"执行出错：{str(e)}"


# 定义图的节点状态
class State(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]



class WebSecAgent:
    """
    Web安全代理类，封装了所有与AI代理相关的功能
    """
    
    def __init__(self, base_url: str = None, model_name: str = None, api_key: str = None, tool_dir: str = None):
        """
        初始化WebSecAgent实例
        
        Args:
            base_url (str): LLM API的基础URL
            model_name (str): 使用的模型名称
            api_key (str): API密钥
        """
        # 设置默认值
        self.base_url = base_url
        self.model_name = model_name
        self.api_key = api_key
        self.tool_dir = tool_dir

        if self.tool_dir:
            setup_tool_paths(self.tool_dir)
        
        # 验证必要参数
        if not self.api_key:
            raise ValueError("API密钥不能为空")
        
        # 初始化工具
        self.tools = [execute_command]
        self.tools_by_name = {tool.name: tool for tool in self.tools}
        
        # 初始化工具节点
        self.tool_node = self.BasicToolNode(self.tools)
        
        # 初始化大语言模型
        self.llm = ChatOpenAI(
            model_name=self.model_name,
            temperature=0,
            openai_api_base=self.base_url,
            openai_api_key=self.api_key
        )
        
        # 绑定工具到模型
        self.llm_with_tools = self.llm.bind_tools(self.tools)
        
        # 创建图
        self._create_graph()
    
    def _create_graph(self):
        """
        创建代理图结构
        """
        # 创建图
        graph = StateGraph(State)

        # 添加节点
        graph.add_node("chatbot", self._chatbot)
        graph.add_node("tools", self.tool_node)

        # 添加边
        graph.add_conditional_edges(
            "chatbot",
            self._route_message,
            {
                "tools": "tools",
                "__end__": END,
            },
        )
        graph.add_edge("tools", "chatbot")
        graph.set_entry_point("chatbot")

        # 编译图
        self.app = graph.compile()
    
    def _chatbot(self, state: State):
        """
        聊天机器人节点函数
        """
        # 创建提示模板
        prompt = ChatPromptTemplate.from_messages([
            ("system", f"{SYSTEM_PROMPT}{[f"{k}:{ALLOWED_COMMANDS[k]}\n" for k in ALLOWED_COMMANDS]}"),
            MessagesPlaceholder(variable_name="messages"),
        ])
        
        # 创建聊天链
        chain = prompt | self.llm_with_tools
        response = chain.invoke(state)
        return {"messages": [response]}

    def _route_message(self, state: State) -> Literal["tools", "__end__"]:
        """
        根据最后一条消息决定是否调用工具
        """
        last_message = state["messages"][-1]
        if last_message.tool_calls:
            return "tools"
        return "__end__"
    
    # 自定义工具节点实现，替代 ToolNode
    class BasicToolNode:
        """一个执行工具请求的节点"""
        
        def __init__(self, tools: list) -> None:
            self.tools_by_name = {tool.name: tool for tool in tools}
        
        def __call__(self, inputs: dict):
            if messages := inputs.get("messages", []):
                message = messages[-1]
            else:
                raise ValueError("No messages found in input")
                
            outputs = []
            for tool_call in message.tool_calls:
                tool_result = self.tools_by_name[tool_call["name"]].invoke(tool_call["args"])
                outputs.append(
                    ToolMessage(
                        content=tool_result,
                        name=tool_call["name"],
                        tool_call_id=tool_call["id"],
                    )
                )
            return {"messages": outputs}
    
    def chat(self, messages: list):
        """
        与代理进行单次对话
        
        Args:
            messages (list): 消息历史列表
            
        Yields:
            str: 流式返回的响应内容
        """
        assistant_message_content = ""
        
        # 使用stream方法进行真正的流式输出，使用messages模式直接获取LLM的token流
        for chunk in self.app.stream({"messages": messages}, stream_mode="messages"):
            # chunk is a tuple of (message, metadata)
            message, metadata = chunk
            if message.content and metadata.get("langgraph_node") == "chatbot":
                yield message.content
                assistant_message_content += message.content
        
        # 返回完整的消息内容
        yield {"full_content": assistant_message_content}
    
    def run(self):
        """
        运行Agent进行交互
        """
        print("基于LangGraph的Function Calling Agent演示")
        print("=" * 50)
        print("输入 '退出' 或 'quit' 结束对话")
        print("=" * 50)
        
        # 初始化消息历史
        messages = []
        
        while True:
            user_input = input("\n你: ").strip()
            if user_input.lower() in ['退出', 'quit', 'exit']:
                print("Agent: 再见！")
                break
                
            if not user_input:
                continue
                
            try:
                # 添加用户消息到历史
                messages.append(HumanMessage(content=user_input))
                
                # 流式处理消息
                print("Agent: ", end="", flush=True)
                assistant_message_content = ""
                
                # 使用流式方法获取响应
                for content in self.chat(messages):
                    if isinstance(content, dict) and "full_content" in content:
                        # 这是完整的消息内容
                        assistant_message_content = content["full_content"]
                    else:
                        # 这是流式的部分内容
                        print(content, end="", flush=True)
                
                # 添加完整消息到历史记录
                messages.append(AIMessage(content=assistant_message_content))
                print()  # 换行
                
            except Exception as e:
                print(f"\n发生错误: {str(e)}")
