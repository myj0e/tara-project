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
    create_mitigations_prompt_zh, get_mitigations_json_siliconflow
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
from threat_process.attck import (
    get_attck_markdown_siliconflow,
    create_json_attck_prompt_zh,
    merge_attck_into_attack_tree
)

from config import *
from threat_process.utils import debug
import os
import time
import threat_process.utils_db as udb
import threat_process.utils_mongo as udbm


def description_to_stride_threats_Json(
        base_url: str, api_key: str, model_name: str,
        description: str, appAttr: app_attrs):
    prompt = create_threat_model_prompt_zh(appAttr=appAttr, app_input=description)
    try:
        description = get_threat_model_SiliconFlow(base_url, api_key, model_name, prompt)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return description


# 获取到dfd_id后检查未生成文件
# def workflowDB(base_url, api_key, model_name, dfd_id):
#     appAttr = app_attrs()
#     # 检查生成描述md文件
#     if not os.path.exists(os.path.join(DESCRIPTION_FOLDER, dfd_id + ".md")):
#         # 获取描述md文件
#         print("Unexpected error: No description")
#         return None
#
#     description_md = read_md_file(DESCRIPTION_FOLDER, dfd_id)
def workflowDB(base_url, api_key, model_name, dfd_id):
    appAttr = app_attrs()
    # 检查生成描述md文件
    #if not os.path.exists(os.path.join(DESCRIPTION_FOLDER, dfd_id + ".md")):
    print("进入workflow了")
    if not udbm.findDescriptionsMd(dfd_id):
        # 获取描述md文件
        print("Unexpected error: No description 没有description的md文件")
        return None
    print("寻找description")
    description_md = udbm.getDescriptionsMd(dfd_id)
    #description_md = read_md_file(DESCRIPTION_FOLDER, dfd_id)

    # debug信息

    debug("workflow:")
    start_time = time.time()
    # 检查生成stride json
    print("查询stride json......")
    #exist = udb.findThreatModelsJSONbyHashID(dfd_id) if DB_PERSISTENCE else os.path.exists(
        #os.path.join(THREAT_MODEL_FOLDER, dfd_id + ".json"))
    # if not exist:
    #     # 创建提示词
    #     threat_model_prompt = create_threat_model_prompt_zh(appAttr, description_md)
    #     stride_json = get_threat_model_SiliconFlow(base_url, api_key, model_name, threat_model_prompt)
    #     if DB_PERSISTENCE:
    #
    #         udb.putThreatModleJSON2db(dfd_id, stride_json)
    #     else:
    #         write_json_file(THREAT_MODEL_FOLDER, dfd_id, stride_json)
    # else:
    #     if DB_PERSISTENCE:
    #         stride_json = udb.getThreatModleJSON(dfd_id)
    #     else:
    #         stride_json = read_json_file(THREAT_MODEL_FOLDER, dfd_id)
    if not udb.findThreatModelsJSONbyHashID(dfd_id):
        print("threatModel不存在，然后创建提示词，并写入")
        threat_model_prompt = create_threat_model_prompt_zh(appAttr=appAttr, app_input=description_md)
        print("生成提示词完毕")
        stride_json = get_threat_model_SiliconFlow(base_url, api_key, model_name, threat_model_prompt)
        print("stride_JSON:")
        print(stride_json)
        print("尝试将 STRIDE 装填入MySQL")
        udb.putThreatModleJSON2db(dfd_id, stride_json)

    else:
        stride_json = udb.getThreatModleJSON(dfd_id)

    debug(f"#stridejson<{int(time.time() - start_time)}s>")

    stride_md = stride_json_to_markdown(stride_json["nodes"])

    # 生成攻击树
    start_time = time.time()
    # if not os.path.exists(os.path.join(ATTACK_TREE_FOLDER, dfd_id + ".md")):
    #     attack_tree_prompt = create_attack_tree_prompt_zh(appAttr=appAttr, app_input=description_md,
    #                                                       stride_model=stride_md)e
    #     attack_tree_json = get_attack_tree_siliconflow(base_url, api_key, model_name, attack_tree_prompt)
    #     write_json_file(ATTACK_TREE_FOLDER, dfd_id, attack_tree_json)
    # else:
    #     attack_tree_json = read_json_file(ATTACK_TREE_FOLDER, dfd_id)
    # debug(f"#attacktree<{int(time.time() - start_time)}s>")
    # attack_tree_mermaid = convert_tree_to_mermaid(attack_tree_json)
    # if not udb.findAttackTreeJSONbyHashID(dfd_id):
    if not udbm.findAttackTreeJSON(dfd_id):
        print("Mongo中未生成过攻击树，开始攻击树生成")
        attck_tree_prompt = create_attack_tree_prompt_zh(appAttr=appAttr, app_input=description_md,
                                                        stride_model=stride_md)
        attack_tree_json = get_attack_tree_siliconflow(base_url, api_key, model_name, attck_tree_prompt)
        # udb.putAttackTreeJSON2db(dfd_id, attack_tree_json)
        udbm.putAttackTreeJSON(dfd_id,attack_tree_json)
    else:
        # attack_tree_json = udb.getAttackTreeJSON(dfd_id)
        print("Mongo中查找到攻击树")
        attack_tree_json = udbm.getAttackTreeJSON(dfd_id)
    debug(f"#attacktree<{int(time.time() - start_time)}s>")
    attack_tree_mermaid = convert_tree_to_mermaid(attack_tree_json)

    # 检查attck信息
    start_time = time.time()
    # if not os.path.exists(os.path.join(ATTCK_FOLDER, dfd_id + ".md")):
    #     attck_prompt = create_json_attck_prompt_zh(attack_tree_mermaid)
    #     attck_json = get_attck_markdown_siliconflow(base_url, api_key, model_name, attck_prompt)
    #     write_json_file(ATTCK_FOLDER, dfd_id, attck_json)
    # else:
    #     attck_json = read_json_file(ATTCK_FOLDER, dfd_id)
    # if not udb.findAttckJSONbyHashID(dfd_id):

    # if not udbm.findAttackJSON(dfd_id):
    if not udbm.findAttckMapJSON(dfd_id):
        attck_prompt = create_json_attck_prompt_zh(attack_tree_mermaid)
        attck_json = get_attck_markdown_siliconflow(base_url, api_key, model_name, attck_prompt)
        print("这个是attack_json")
        print(attck_json)

        if attck_json is not None:
            udbm.putAttckMapJSON(dfd_id,attck_json)
            # udb.putAttckJSON2db(dfd_id, attck_json)
        else:
            print("att&ck获取失败")
            return
    else:
        attck_json=udbm.getAttckMapJSON(dfd_id)
        # attck_json = udb.getAttckJSON(dfd_id)

    end_time = time.time()
    debug(f"#att&ck<{int(end_time - start_time)}s>")

    # if not os.path.exists(os.path.join(ATTCK_FOLDER, dfd_id + ".md")):
    #     attack_tree_attck_mermaid = merge_attck_into_attack_tree(attack_tree_json, attck_json)
    #     write_md_file(ATTCK_FOLDER, dfd_id, attack_tree_attck_mermaid)
    # else:
    #     attack_tree_attck_mermaid = read_md_file(ATTCK_FOLDER, dfd_id)
    # if not udb.findAttckMdbyHashID(dfd_id):
    if not udbm.findAttackMd(dfd_id):
        print("Mongo中未生成过攻击树+attck，开始合并")
        attack_tree_attck_mermaid = merge_attck_into_attack_tree(attack_tree_json, attck_json)
        print("准备将AttackTreeMd写入Mongo")
        udbm.putAttackTreeMd(dfd_id, attack_tree_attck_mermaid)
        print("写入完毕")
    else:
        attack_tree_attck_mermaid = udbm.getAttackTreeMd(dfd_id)


    # 检查生成dread json文件
    start_time = time.time()
    # exist = udb.findDreadJSONbyHashID(dfd_id) if DB_PERSISTENCE else os.path.exists(
    #     os.path.join(DREAD_FOLDER, dfd_id + ".json"))
    # if not exist:
    #     dread_json_prompt = create_dread_assessment_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
    #     dread_json = get_dread_assessment_siliconflow(base_url, api_key, model_name, dread_json_prompt)
    #     try:
    #         for i in dread_json["nodes"]:
    #             for j in ["S", "T", "R", "I", "D", "E"]:
    #                 if j not in i["stride"]:
    #                     i["stride"][j] = {"description": "None", "Scenario": "None",
    #                                       "dread": {"D": 0, "R": 0, "E": 0, "A": 0, "D2": 0}}
    #     except Exception as e:
    #         print(f"Error:{e}")
    #         print(f"{dread_json}")
    #
    #     if DB_PERSISTENCE:
    #         udb.putDreadJSON2db(dfd_id, dread_json)
    #     else:
    #         write_json_file(DREAD_FOLDER, dfd_id, dread_json)
    # else:
    #     if DB_PERSISTENCE:
    #         dread_json = udb.getDreadJSON(dfd_id)
    #     else:
    #         dread_json = read_json_file(DREAD_FOLDER, dfd_id)
    print("dread操作")
    if not udb.findDreadJSONbyHashID(dfd_id):
        dread_json_prompt = create_dread_assessment_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
        print("dread_json_prompt:"+dread_json_prompt)
        dread_json = get_dread_assessment_siliconflow(base_url, api_key, model_name, dread_json_prompt)
        print("dread_json:", dread_json)
        try:
            for i in dread_json["nodes"]:
                for j in ["S", "T", "R", "I", "D", "E"]:
                    if j not in i["stride"]:
                        i["stride"][j] = {"description": "None", "Scenario": "None",
                                          "dread": {"D": 0, "R": 0, "E": 0, "A": 0, "D2": 0}}
        except Exception as e:
            print(f"Error:{e}")
            print(f"{dread_json}")
        print("准备将DreadJson写入Mongo")
        udb.putDreadJSON2db(dfd_id, dread_json)
        print("写入完毕")
    else:
        dread_json = udb.getDreadJSON(dfd_id)

    debug(f"#dreadjson<{int(time.time() - start_time)}s>")

    # 检查生成mitigations md文件
    start_time = time.time()
    # exist = udb.findCommitJSONbyHashID(dfd_id) if DB_PERSISTENCE else os.path.exists(
    #     os.path.join(COMMIT_FOLDER, dfd_id + ".json"))
    # # if os.path.exists(os.path.join(COMMIT_FOLDER, dfd_id+".json")) and (not os.path.exists(os.path.join(MITIGATION_FOLDER, dfd_id+".md"))):
    # if exist and (not os.path.exists(os.path.join(MITIGATION_FOLDER, dfd_id + ".md"))):
    #     mitigations_prompt = create_mitigations_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
    #     mitigations_md = get_mitigations_siliconflow(base_url, api_key, model_name, mitigations_prompt)
    #     write_md_file(MITIGATION_FOLDER, dfd_id, mitigations_md)
    if not udb.findMitigationsMdbyHashID(dfd_id):
        mitigations_prompt = create_mitigations_prompt_zh(stride_md, attck_info=attack_tree_attck_mermaid)
        mitigations_md = get_mitigations_siliconflow(base_url, api_key, model_name, mitigations_prompt)
        mitigations_json = get_mitigations_json_siliconflow(base_url, api_key, model_name, mitigations_prompt)

        #udb.put
        udbm.putMitigationsMd(dfd_id, mitigations_md)
        udb.putMitigationJSON2db(dfd_id,mitigations_json)

    debug(f"#mitigations<{int(time.time() - start_time)}s>")

    start_time = time.time()
    # if os.path.exists(os.path.join(COMMIT_FOLDER, dfd_id + ".json")) and (
    # if udb.findCommitJSONbyHashID(dfd_id) and (
    # not os.path.exists(os.path.join(REPORT_FOLDER, dfd_id + ".md"))):
    #     '''
    #     对dread的字段先进行改进，添加一个空白的commit字段，将这个之后的Json保存至COMMIT_FOLDER处；具体实现在initialize_commit_file
    #     然后合并用户提交的commit信息进LLM原始结构，保留原始描述 + scenario，更新dread，并添加commit字段。
    #     '''
    #     from threat_process.createSuggestion import merge_commit_with_dread, initialize_commit_file
    #     from threat_process.report_generator import generate_report
    #
    #     #dread_Json
    #     dread_path = os.path.join(DREAD_FOLDER, f"{dfd_id}.json")
    #     logging.info("dread_path: %s", dread_path)
    #     #扩容commit字段的Json
    #     commit_path = os.path.join(COMMIT_FOLDER, f"{dfd_id}.json")
    #     logging.info("commit_path: %s", commit_path)
    #     #报告md文件路径
    #     report_path = os.path.join(REPORT_FOLDER, f"{dfd_id}.md")
    #     logging.info("report_path: %s", report_path)
    #
    #     #给dread_json中添加commit字段
    #     # if not os.path.exists(commit_path):
    #     #     initialize_commit_file(dfd_id)
    #
    #     # 读 LLM 原始建议
    #     if not os.path.exists(dread_path):
    #         debug(f"缺少原始 dread 文件：{dread_path}")
    #         return
    #
    #     # 合并人工建议进原始结构，保存回 COMMIT_FOLDER/dfd_id.json
    #     merge_commit_with_dread(dfd_id)
    #
    #     # 读取合并结果，生成 markdown 报告
    #     with open(commit_path, "r", encoding="utf-8") as f:
    #         merged_data = json.load(f)
    #     generate_report(dfd_id, merged_data)
    #
    #     debug(f"报告生成完成：{report_path}")
    end_time = time.time()
    debug(f"#report<{int(end_time - start_time)}s>")