# createSuggestion.py

import logging
import os
import json
from config import DREAD_FOLDER, COMMIT_FOLDER
import threat_process.utils_db as udb

def initialize_commit_file(dfd_id):
    """
    读取 LLM 原始结构，在内存中添加空 commit 字段，并存入 COMMIT_FOLDER 中。
    原始 dread 文件保持不变。
    """
    #dread_path = os.path.join(DREAD_FOLDER, f"{dfd_id}.json")
    commit_path = os.path.join(COMMIT_FOLDER, f"{dfd_id}.json")

    # if not os.path.exists(dread_path):
    #     raise FileNotFoundError(f"LLM 原始文件不存在：{dread_path}")

    # with open(dread_path, 'r', encoding='utf-8') as f:
    #     llm_data = json.load(f)
    llm_data=udb.getDreadJSON(dfd_id)

    commit_data = {"nodes": []}
    # 遍历 LLM 原始数据，添加空的 commit 字段
    for node in llm_data.get("nodes", []):
        new_node = {
            "name": node["name"],
            "type": node["type"],
            "stride": {}
        }
        for threat_type, threat in node.get("stride", {}).items():
            new_node["stride"][threat_type] = {
                "description": threat.get("description", ""),
                "Scenario": threat.get("Scenario", ""),
                "dread": threat.get("dread", {}),
                "commit": ""  # 添加空字段
            }
        commit_data["nodes"].append(new_node)

    os.makedirs(COMMIT_FOLDER, exist_ok=True)
    with open(commit_path, "w", encoding="utf-8") as f:
        json.dump(commit_data, f, indent=2, ensure_ascii=False)

    print(f"初始化用户提交文件成功：{commit_path}")

def merge_commit_with_dread(dfd_id):
    """
    合并用户提交的 commit 信息进 LLM 原始结构，保留原始描述，更新 dread，并添加 commit 字段。
    保存到 COMMIT_FOLDER/dfd_id.json 中。
    """
    dread_path = os.path.join(DREAD_FOLDER, f"{dfd_id}.json")
    logging.info("dread_path: %s", dread_path)
    commit_path = os.path.join(COMMIT_FOLDER, f"{dfd_id}.json")
    logging.info("commit_path: %s", commit_path)

    #==========初始==========
    if not os.path.exists(dread_path):
        raise FileNotFoundError(f"LLM 原始建议文件不存在：{dread_path}")
    if not os.path.exists(commit_path):
        raise FileNotFoundError(f"人工提交建议文件不存在：{commit_path}")

    with open(dread_path, 'r', encoding='utf-8') as f:
        llm_data = json.load(f)
    with open(commit_path, 'r', encoding='utf-8') as f:
        user_data = json.load(f)
    #=======================

    # 列表转字典
    llm_node_map = {node["name"]: node for node in llm_data.get("nodes", [])}
    user_node_map = {node["name"]: node for node in user_data.get("nodes", [])}

    # 遍历 用户提交的 节点
    for node_name, user_node in user_node_map.items():
        if node_name not in llm_node_map:
            continue

        llm_stride = llm_node_map[node_name]["stride"]
        user_stride = user_node.get("stride", {})

        for threat_type, user_threat in user_stride.items():
            if "commit" in user_threat and user_threat["commit"] and user_threat["commit"].strip():
                llm_stride[threat_type]["dread"] = user_threat["dread"]
                llm_stride[threat_type]["commit"] = user_threat["commit"]

    # 保存合并后的新结构
    os.makedirs(COMMIT_FOLDER, exist_ok=True)
    with open(commit_path, "w", encoding="utf-8") as f:
        json.dump({"nodes": list(llm_node_map.values())}, f, indent=2, ensure_ascii=False)

    print(f"合并人工建议成功，保存至：{commit_path}")


