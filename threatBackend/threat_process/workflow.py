import json
import logging

from threat_process.threat_model import (
    get_threat_model_SiliconFlow,
    create_threat_model_prompt_zh,
    stride_json_to_markdown
)
from threat_process.attack_tree import (
    create_attack_tree_prompt_zh,
    get_attack_tree_siliconflow,
    convert_tree_to_mermaid
)
from threat_process.mitigations import (
    get_mitigations_siliconflow,
    create_mitigations_prompt_zh
)
from threat_process.dread import (
    get_dread_assessment_siliconflow,
    create_dread_assessment_prompt_zh
)
from threat_process.utils import (
    write_json_file,
    read_json_file,
    write_md_file,
    read_md_file
)
from threat_process.attck import(
    get_attck_markdown_siliconflow,
    create_json_attck_prompt_zh,
    merge_attck_into_attack_tree
)

from config import *
from threat_process.utils import debug, timer_decorator
import os
import time
import threat_process.utils_db as udb
from langchain_core.runnables import RunnablePassthrough
from typing import Tuple, Union

class State:
    def __init__(self,dfd_id:str, base_url:str, api_key:str, model_name:str, app_attr:app_attrs):
        self.app_attr = app_attr
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model_name
        self.dfd_id = dfd_id
        self.description = ""
        self.stride_json = {}
        self.attack_tree_json = {}
        self.attck_json = {}
        self.dread_json = {}

@timer_decorator
def stride_model_generate(state:State)->State:
    if os.path.exists(os.path.join(THREAT_MODEL_FOLDER, state.dfd_id+".json")):
        try:
            stride_json = read_json_file(THREAT_MODEL_FOLDER, state.dfd_id)
        except Exception as e:
            print(e)
    elif state.description:
        threat_model_prompt = create_threat_model_prompt_zh(state.app_attr, state.description)
        stride_json = get_threat_model_SiliconFlow(state.base_url, state.api_key, state.model_name,threat_model_prompt)
        write_json_file(THREAT_MODEL_FOLDER, state.dfd_id, stride_json)
    else:
        raise Exception("No description provided")
    state.stride_json = stride_json
    return state

@timer_decorator
def attack_tree_generate(state: State)->State:
    # 生成攻击树
    if os.path.exists(os.path.join(ATTACK_TREE_FOLDER, state.dfd_id+".json")):
        try:
            attack_tree_json = read_json_file(ATTACK_TREE_FOLDER, state.dfd_id)
        except Exception as e:
            print(e)
    elif state.stride_json:
        stride_md = stride_json_to_markdown(state.stride_json["nodes"])
        attack_tree_prompt = create_attack_tree_prompt_zh(appAttr=state.app_attr, app_input=state.description, stride_model=stride_md)
        attack_tree_json = get_attack_tree_siliconflow(state.base_url, state.api_key, state.model_name,attack_tree_prompt)
        write_json_file(ATTACK_TREE_FOLDER, state.dfd_id, attack_tree_json)
    else:
        raise Exception("No attack tree generated")
    state.attack_tree_json = attack_tree_json
    return state

@timer_decorator
def attck_generate(state: State)->State:
    # 检查attck信息
    if os.path.exists(os.path.join(ATTCK_FOLDER, state.dfd_id+".json")):
        try:
            attck_json = read_json_file(ATTCK_FOLDER, state.dfd_id)
        except:
            raise Exception("attck json file error")

    elif state.attack_tree_json:
        attack_tree_mermaid = convert_tree_to_mermaid(state.attack_tree_json)
        attck_prompt = create_json_attck_prompt_zh(attack_tree_mermaid)
        attck_json = get_attck_markdown_siliconflow(state.base_url, state.api_key, state.model_name, attck_prompt)
        write_json_file(ATTCK_FOLDER, state.dfd_id, attck_json)
    else:
        raise Exception("No attack tree generated")
    state.attck_json = attck_json
    return state

@timer_decorator
def attack_tree_attck_merge(state: State)->State:
    if os.path.exists(os.path.join(ATTCK_FOLDER, state.dfd_id+".md")):
        attck_mermaid = read_md_file(ATTCK_FOLDER, state.dfd_id)
    elif state.attck_json and state.attack_tree_json:
        attack_tree_attck_mermaid = merge_attck_into_attack_tree(state.attack_tree_json, state.attck_json)
        write_md_file(ATTCK_FOLDER, state.dfd_id, attack_tree_attck_mermaid)
    else:
        raise Exception("No attack tree or ATT&CK JSON provided")
    return state

@timer_decorator
def dread_generate(state: State)->State:
    # 准备攻击树信息
    if os.path.exists(os.path.join(ATTCK_FOLDER, state.dfd_id, ".md")):
        attack_tree_attck_mermaid = read_md_file(ATTCK_FOLDER, state.dfd_id)
    else:
        attack_tree_attck_mermaid = merge_attck_into_attack_tree(state.attack_tree_json, state.attck_json)
    # 检查生成dread json文件
    if os.path.exists(os.path.join(DREAD_FOLDER, state.dfd_id+".json")):
        dread_json = read_json_file(DREAD_FOLDER, state.dfd_id)
    elif attack_tree_attck_merge and state.stride_json:
        stride_md = stride_json_to_markdown(state.stride_json["nodes"])
        dread_json_prompt = create_dread_assessment_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
        dread_json = get_dread_assessment_siliconflow(state.base_url, state.api_key, state.model_name,dread_json_prompt)
        try:
            for i in dread_json["nodes"]:
                for j in ["S","T","R","I","D","E"]:
                    if j not in i["stride"]:
                        i["stride"][j] = {"description":"None", "Scenario": "None","dread": {"D": 0, "R": 0, "E": 0, "A": 0, "D2": 0}}
        except Exception as e:
            print(f"Error:{e}")
            print(f"{dread_json}")
        write_json_file(DREAD_FOLDER, state.dfd_id, dread_json)
    else:
        raise ValueError("Invalid input")
    state.dread_json = dread_json
    return state

@timer_decorator
def mitigation_generate(state: State) -> State:
    # 检查生成mitigations md文件
    if os.path.exists(os.path.join(COMMIT_FOLDER, state.dfd_id+".json")):
        commit_json = read_json_file(COMMIT_FOLDER, state.dfd_id)
    else:
        return None
    if os.path.exists(os.path.join(MITIGATION_FOLDER, state.dfd_id+".md")):
        mitigations_md = read_md_file(MITIGATION_FOLDER, state.dfd_id)
    elif commit_json and state.stride_json and state.attack_tree_json and state.attck_json:
        attack_tree_attck_mermaid = merge_attck_into_attack_tree(state.attack_tree_json, state.attck_json)
        stride_md = stride_json_to_markdown(state.stride_json["nodes"])
        mitigations_prompt = create_mitigations_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
        mitigations_md = get_mitigations_siliconflow(state.base_url, state.api_key, state.model_name, mitigations_prompt)
        write_md_file(MITIGATION_FOLDER, state.dfd_id, mitigations_md)

chain = (
    RunnablePassthrough()|
    stride_model_generate|
    attack_tree_generate|
    attck_generate|
    attack_tree_attck_merge|
    dread_generate|
    mitigation_generate
)

def workflow(base_url, api_key, model_name, dfd_id):
    app_attr = app_attrs()
    state = State(dfd_id, base_url, api_key, model_name, app_attr)
    state.description = read_md_file(DESCRIPTION_FOLDER, state.dfd_id)
    chain.invoke(state)
