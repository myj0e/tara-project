from flask import (
    Flask, 
    request, 
    Response, 
    jsonify, 
    abort, 
    send_file, 
    stream_with_context
)

import tempfile, os, sys
from langchain_core.messages import AIMessage, HumanMessage
from WebSecAgent.agent import WebSecAgent
from flask_cors import CORS
import os
import uuid
from queue import Queue
from threading import Thread, Event
import json
from config import *
from threat_process.core import core
from threat_process.utils import (
    debug,
    write_json_file,
    write_md_file,
    write_list_to_file,
    read_json_file,
    read_md_file,
    read_list_from_file,
    create_folder,
    dict_to_hash,
    
)
from threat_process.workflow import (
    app_attrs
)
from threat_process.threat_model import (
    description_to_stride_threats_Json
)
from threat_process import utils_db as udb
from threat_process import utils_mongo as udbm




class app_data:
    def __init__(self,description):
        self.description = description
        self.threat_model = ""
        self.Improvement_suggestions = ""
        self.attck_tree = ""
        self.mitigations = ""
        self.DREAD = ""
        self.test_cases = ""

    def set_threat_model(self, threat_model):
        self.threat_model = threat_model
    def get_threat_model(self):
        return self.threat_model
    

    def set_Improvement_suggestions(self, Improvement_suggestions):
        self.Improvement_suggestions = Improvement_suggestions
    def get_Improvement_suggestions(self):
        return self.Improvement_suggestions
    
    def set_attack_tree(self, attack_tree):
        self.attack_tree = attack_tree
    def set_mitigations(self, mitigations):
        self.mitigations = mitigations
    def set_DREAD(self, DREAD):
        self.DREAD = DREAD
    def set_tests(self, tests):
        self.tests = tests
    


def create_dfd_description(data: dict) -> str | None:
    """
    根据 DFD JSON 生成 Markdown 描述。
    兼容两种结构：
      1) 扁平：{"title","description","nodes","edges"}
      2) 分层：{"summary":{"title","description"},"detail":{"nodes","edges"}}
    返回 Markdown 字符串；若校验失败返回 None。
    """
    if not isinstance(data, dict):
        return None

    # ---- 取标题与描述（优先根层，其次 summary）----
    title = (data.get('title') or data.get('summary', {}).get('title') or '').strip()
    desc  = (data.get('description') or data.get('summary', {}).get('description') or '').strip()

    # ---- 取 nodes / edges（优先根层，其次 detail）----
    nodes = data.get('nodes')
    edges = data.get('edges')
    if nodes is None or edges is None:
        detail = data.get('detail', {}) if isinstance(data.get('detail'), dict) else {}
        nodes = nodes if nodes is not None else detail.get('nodes', [])
        edges = edges if edges is not None else detail.get('edges', [])

    if not isinstance(nodes, list) or not isinstance(edges, list):
        return None

    # 工具：不改入参，统一清洗
    def norm_text(x) -> str:
        return (x or '').replace('\n', ' ').strip()

    # -------- 规范化 nodes --------
    nodes_id_dict: dict[str, str] = {}
    nodes_list: list[dict] = []
    seen_names: set[str] = set()

    try:
        for n in nodes:
            n = n or {}
            nid   = n.get('id', '')
            nname = norm_text(n.get('name', ''))
            ntype = norm_text(n.get('type', ''))
            ndesc = norm_text(n.get('description', ''))

            # 关键字段校验
            if not nid or not nname:
                try: debug("Invalid node (missing id/name): " + str(n))
                except NameError: pass
                return None

            if nname in seen_names:
                try: debug("Duplicate node name: " + nname)
                except NameError: pass
                return None

            seen_names.add(nname)
            nodes_id_dict[nid] = nname
            nodes_list.append({
                'name': nname,
                'type': ntype,
                'description': ndesc,
            })
    except Exception as e:
        try: debug(f"[create_dfd_description] nodes normalize error: {e}")
        except NameError: pass
        return None

    # -------- 规范化 edges --------
    edges_list: list[dict] = []
    try:
        for e in edges:
            e = e or {}
            ename = norm_text(e.get('name', '')) or 'Unnamed Flow'
            edesc = norm_text(e.get('description', ''))
            src   = e.get('source', '')
            tgt   = e.get('target', '')

            if not src or not tgt:
                try: debug("Invalid edge (missing source/target): " + str(e))
                except NameError: pass
                return None
            if src not in nodes_id_dict or tgt not in nodes_id_dict:
                try: debug("Invalid edge (source/target not in nodes): " + str(e))
                except NameError: pass
                return None

            edges_list.append({
                'name': ename,
                'description': edesc,
                'source': nodes_id_dict[src],
                'target': nodes_id_dict[tgt],
            })
    except Exception as e:
        try: debug(f"[create_dfd_description] edges normalize error: {e}")
        except NameError: pass
        return None

    # -------- 生成 Markdown（含标题与描述）--------
    parts = []

    if title:  # 一级标题
        parts.append(f"# {title}")
    if desc:   # 段落描述
        parts.append(desc)

    # 概览行（举例：总数统计，非必需）
    parts.append(f"*共 {len(nodes_list)} 个关键部件，{len(edges_list)} 条关键连接。*\n")

    # 节点表
    lines = []
    lines.append("### 关键部件")
    lines.append("| 序号 | 名称 | 类型 | 描述 |")
    lines.append("|------|------|------|------|")
    for i, node in enumerate(nodes_list):
        lines.append(
            f"|{i}|{node['name']}|{node['type']}|{node['description']}|"
        )
    parts.append("\n".join(lines))

    # 边表
    lines = []
    lines.append("\n### 关键连接")
    lines.append("| 序号 | 名称 | 描述 | 源 | 目的 |")
    lines.append("|------|------|------|----|------|")
    for i, edge in enumerate(edges_list):
        lines.append(
            f"|{i}|{edge['name']}|{edge['description']}|{edge['source']}|{edge['target']}|"
        )
    parts.append("\n".join(lines))

    return "\n\n".join(parts)





# init部分
app = Flask(__name__)
CORS(app)
que = Queue()
try:
    myagent = WebSecAgent(
        base_url=SILICONFLOW_BASE_URL,
        api_key=SILICONFLOW_API_KEY,
        model_name=SILICONFLOW_MODEL,
        )
except Exception as e:
    print(f"启动代理时发生错误: {str(e)}")

create_folder(DESCRIPTION_FOLDER)
create_folder(THREAT_MODEL_FOLDER)
create_folder(ATTACK_TREE_FOLDER)
create_folder(ATTCK_FOLDER)
create_folder(MITIGATION_FOLDER)
create_folder(DREAD_FOLDER)
create_folder(COMMIT_FOLDER)
create_folder(REPORT_FOLDER)
create_folder(AGENT_SESSION_FOLDER)

# 创建线程core, 并传入参数que
stop_event = Event()
try:
    core_thread = Thread(target=core, args=(que, stop_event,SILICONFLOW_BASE_URL, SILICONFLOW_API_KEY, SILICONFLOW_MODEL))
    core_thread.daemon = True
    core_thread.start()
except KeyboardInterrupt:
    stop_event.set()
    core_thread.join(timeout=2.0)



@app.route("/threat_model", methods=["POST"])
def get_threat_model():
    appAttr = app_attrs()

    # 1) 解析 JSON（强制按 JSON）
    try:
        data = request.get_json(force=True, silent=False)
    except Exception as e:
        print(f"[/threat_model] invalid json: {e}")
        return "Bad Request: invalid JSON", 400

    # 2) 关键打点：看结构长啥样
    # try:
    #     print("[/threat_model] keys:", list(data.keys()))
    #     print("[/threat_model] title:", repr(data.get("title")))
    #     print("[/threat_model] nodes:", len(data.get("nodes") or []))
    #     print("[/threat_model] edges:", len(data.get("edges") or []))
    # except Exception:
    #     pass

    # 3) 规范化：把 title/description 放入 dfd_json，并稳健提取 nodes/edges
    dfd_json = {"title": "", "description": "", "nodes": [], "edges": []}
    try:
        dfd_json["title"] = (data.get("title") or "").strip()
        dfd_json["description"] = (data.get("description") or "").strip()

        # 节点
        for i in data.get("nodes", []) or []:
            dfd_json["nodes"].append({
                "id": i.get("id", ""),
                "name": i.get("name", ""),
                "type": i.get("type", ""),
                "description": i.get("description", "") or "",
                "hasOpenThreats": bool(i.get("hasOpenThreats", False)),
                "threats": [
                    {
                        "title":      (t or {}).get("title", "") or "",
                        "severity":   (t or {}).get("severity", "") or "",
                        "type":       (t or {}).get("type", "") or "",
                        "mitigation": (t or {}).get("mitigation", "") or "",
                        "status":     (t or {}).get("status", "") or "",
                    }
                    for t in (i.get("threats") or [])
                ]
            })

        # 边
        for i in data.get("edges", []) or []:
            dfd_json["edges"].append({
                "id": i.get("id", ""),
                "name": i.get("name", "") or "Unnamed Flow",
                "description": i.get("description", "") or "",
                "source": i.get("source", "") or "",
                "target": i.get("target", "") or "",
                "isEncrypted": bool(i.get("isEncrypted", False)),
                "isPublicNetwork": bool(i.get("isPublicNetwork", False)),
                "hasOpenThreats": bool(i.get("hasOpenThreats", False)),
                "protocol": i.get("protocol", "") or "",
                "threats": [
                    {
                        "title":      (t or {}).get("title", "") or "",
                        "severity":   (t or {}).get("severity", "") or "",
                        "type":       (t or {}).get("type", "") or "",
                        "mitigation": (t or {}).get("mitigation", "") or "",
                        "status":     (t or {}).get("status", "") or "",
                    }
                    for t in (i.get("threats") or [])
                ]
            })
    except Exception as e:
        print(f"Error in get_threat_model normalize: {e}")
        return "Bad Request", 400

    # 4) 基于规范化后的 dfd_json 生成描述（示例：仅 nodes/edges 参与也没问题）
    description = create_dfd_description(dfd_json)
    #print("description is :", description)
    if description is None:
        return "Bad Request: description generate fail", 400


    # 5) 计算哈希（现在包含 title/description，更稳定）
    dfd_id = dict_to_hash(dfd_json)
    #print("dfd_id is :", dfd_id)
    # 6) 写库（如果需要可加 try/except）
    if DB_PERSISTENCE:
        print(dfd_id + " 初始JSON 试图 存入mysql")
        udb.putDFDJSON2db(dfd_id, dfd_json)
        print(dfd_id+"试图将descriptionMD存入MongoDB")
        udbm.putDescriptionsMd(dfd_id, description)
    else:
        dfd_id_list = read_list_from_file('./', DFD_ID_FILE)
        
        if dfd_id not in dfd_id_list:
            dfd_id_list.append(dfd_id)
            write_list_to_file('./',DFD_ID_FILE, dfd_id_list)
            write_md_file(DESCRIPTION_FOLDER, dfd_id, description)

    # 7) 入队
    que.put({"id": dfd_id})

    return {"id": dfd_id}, 200



@app.route('/DREAD', methods=['GET'])
def get_dread_assessment():
    # 获取GET请求入参"id"
    id = request.args.get("id")
    if DB_PERSISTENCE:
        if id != None:
            pass
            #print("DREAD 前端传来的ID是："+id)
        else:
            print("DREAD 前端没有传入ID")
            return "id is required", 400
        ret=udb.getDreadJSON(id)
    else:
        dfd_id_list = read_list_from_file('./', DFD_ID_FILE)
        if(id not in dfd_id_list):
            print("DREAD中 id 不在 DFD_ID_FILE 中")
            return "id not found",404
        
        #检查路径中是否有目标文件，若不存在返回正在处理
        if not os.path.exists(os.path.join(DREAD_FOLDER, id+".json")):
            return "processing", 202
        ret = read_json_file(DREAD_FOLDER, id)
        
    if ret is None:
        return "DFD JSON is NONE ",400
    #将json文件内容读取为dict
        
    return ret,200

@app.route('/commits', methods=['POST'])
def get_commits():

    data = request.get_json()
    if DB_PERSISTENCE:
        if ("id" not in data) or ("nodes" not in data):
            return "error", 400
        udb.putCommitJSON2db(data["id"], {"nodes": data.get("nodes", [])})
    else:
        dfd_id_list = read_list_from_file('./', DFD_ID_FILE)
        if data["id"] not in dfd_id_list:
            print(f"{data["id"]}\n##\n{dfd_id_list}")
            return "Data Flow Diagram Not Found", 404
        write_json_file(COMMIT_FOLDER, data["id"], {"nodes":data["nodes"]})

    que.put({"id":data["id"]})
    return {"status": "success","message": "建议处理成功"}


@app.route('/mitigations/<id>', methods=['GET'])
def get_report(id):
    if DB_PERSISTENCE:
        if not udbm.findMitigationsMd(id):
            return "Data Flow Diagram Not Found", 404
        ret= udbm.getMitigationsMd(id)
    else:
        dfd_id_list = read_list_from_file('./', DFD_ID_FILE)
        if id not in dfd_id_list:
            return "Data Flow Diagram Not Found", 404
        if id is None:
            return "id is required", 400
        if (id+".md") not in os.listdir(MITIGATION_FOLDER):
            return "processing", 202
        ret = read_md_file(MITIGATION_FOLDER, id)
    return ret,200
@app.route('/get-attack-tree/<id>',methods=['GET'])
def get_attack_tree(id):
    if DB_PERSISTENCE:
        if not udbm.findAttackTreeMd(id):
            return Response("Attack Tree Not Found", status=404)
        else:
            content = udbm.getAttackTreeMd(id)
    else:
        path = os.path.join(ATTCK_FOLDER, id +".md")
        if not os.path.exists(path):
            return Response("Attack Tree Not Found", status=404)
        else:
            content = read_md_file(ATTCK_FOLDER, id)
    return Response(content, mimetype='text/plain')

@app.route('/mitigationstable',methods=['GET'])
def show_mitigations_table():
    page = request.args.get('page', default=1, type=int)
    page_size = request.args.get('page_size', default=5, type=int)
    result = udb.get_mitigations_page_with_count(page=page, page_size=page_size) if DB_PERSISTENCE else 0
    return jsonify(result)

@app.route('/mitigationsexport/<int:id>', methods=['GET'])
def mitigation_export(id):
    print(f"走到了打印接口，ID={id}")

    tmp_path = None
    try:
        # 在系统临时目录创建一个临时文件名
        fd, tmp_path = tempfile.mkstemp(suffix='.xlsx', prefix=f'mitigation_{id}_')
        os.close(fd)  # 只要路径，先关掉描述符

        # 把 Excel 写到这个临时路径
        udb.exportMitigationToExcel(id, tmp_path)

        # 作为附件返回
        return send_file(
            tmp_path,
            as_attachment=True,
            download_name=f"mitigation_{id}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            max_age=0
        )
    except Exception as e:
        print("导出失败：", e)
        abort(500, description=f"生成 Excel 失败: {e}")
    finally:
        # 成功失败都尝试清理临时文件
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


messages = []
@app.route('/agent', methods=['GET'])
def agent():
    global messages
    #session_list = read_list_from_file(AGENT_SESSION_FOLDER, AGENT_SESSION_FILE)
    
    # 生成随机hash值作为id
    id = uuid.uuid4().hex
    #while id in session_list:
    #    id = uuid.uuid4().hex
    #session_list.append(id)
    messages=[]
    #write_list_to_file(AGENT_SESSION_FOLDER, AGENT_SESSION_FILE, session_list)

    return id, 200



@app.route('/agent/<id>', methods=['POST'])
def agent_post(id):
    data = request.get_json()
    if "message" not in data:
        print("message not found")
        return "error", 400
    
    # 添加用户消息到messages
    user_message = HumanMessage(data["message"])
    messages.append(user_message)

    # 收集AI响应 - 非流式生成响应，收集完整响应
    ai_response = ""
    try:
        print("# 获取AI响应：", end="")
        print(messages)
        for event in myagent.chat(messages):
            # 检查event类型并正确处理
            if isinstance(event, dict):
                # 如果event是字典，提取其中的文本内容
                # 常见的键可能是'content'或其他包含实际文本的键
                content = event.get('content', str(event))
            else:
                # 如果event是字符串或其他类型，直接转换为字符串
                content = str(event)
            
            # 累积响应内容
            if content and len(content) > 0 and content[0] != '{':
                ai_response += content
                print(content, end='', flush=True)
            else:
                # 处理包含完整内容的JSON响应
                try:
                    # 将content中的单引号替换为可被json解析的双引号
                    content = content.replace("'", '"')
                    content_json = json.loads(content)
                    if "full_content" in content_json:
                        ai_response = content_json["full_content"]
                except Exception as e:
                    print(f"Error parsing final content: {str(e)}")
                    
    except Exception as e:
        error_msg = f"Error during chat generation: {str(e)}"
        print(error_msg)
        return {"error": error_msg}, 500
    
    # 在响应完成后，将AI消息添加到messages并保存
    try:
        ai_message = AIMessage(ai_response)
        messages.append(ai_message)
    except Exception as e:
        print(f"Error saving messages: {str(e)}")
        return {"error": f"Error saving messages: {str(e)}"}, 500

    # 返回完整的响应
    return {"response": ai_response}, 200


# """
# @app.route('/agent/<id>', methods=['POST'])
# def agent_post(id):
#     #session_list = read_list_from_file(AGENT_SESSION_FOLDER, AGENT_SESSION_FILE)
#     #if(id not in session_list):
#     #    return "Session Not Found", 404
# 
#     data = request.get_json()
#     if "message" not in data:
#         print("message not found")
#         return "error", 400
#     
#     # 添加用户消息到messages
#     user_message = HumanMessage(data["message"])
#     messages.append(user_message)
# 
#     # 收集AI响应
#     ai_response = ""
#     def generate_response():
#         try:
#             # 非流式生成响应，收集完整响应
#             print("# 获取AI响应：",end="")
#             print(messages)
#             for event in myagent.chat(messages):
#                 # 检查event类型并正确处理
#                 if isinstance(event, dict):
#                     # 如果event是字典，提取其中的文本内容
#                     # 常见的键可能是'content'或其他包含实际文本的键
#                     content = event.get('content', str(event))
#                 else:
#                     # 如果event是字符串或其他类型，直接转换为字符串
#                     content = str(event)
#                 if content[0] != '{':
#                     print(content, end='',flush=True)
#                     # 使用标准SSE格式返回数据
#                     yield f'data: {content}\n\n'
#                     # 强制刷新stdout缓冲区，确保数据立即发送到客户端
#                     sys.stdout.flush()
#                 else:
#                     # 在响应完成后，将AI消息添加到messages并保存
#                     try:
#                         # 将content中的单引号替换为可被json解析的双引号
#                         content = content.replace("'", '"')
#                         #print("解析content"+content)
#                         content_json = json.loads(content)
#                         if("full_content" in content_json):
#                             ai_message = AIMessage(content_json["full_content"])
#                             messages.append(ai_message)
#                             data["messages"] = messages
#                             # 发送结束信号
#                             yield 'data: \n\n'
#                             # 强制刷新stdout缓冲区
#                             sys.stdout.flush()
#                         else:
#                             #print(f"解析错误{content}", end='',flush=True)
#                             yield 'data: {"error": "解析错误"}\n\n'
#                             # 强制刷新stdout缓冲区
#                             sys.stdout.flush()
#                     except Exception as e:
#                         print(f"Error saving messages: {str(e)}")
#                         yield f'data: {{"error": "Error saving messages: {str(e)}"}}\n\n'
#                         # 强制刷新stdout缓冲区
#                         sys.stdout.flush()
#         except Exception as e:
#             error_msg = f"Error during chat generation: {str(e)}"
#             print(error_msg)
#             yield f'data: {{"error": "{error_msg}"}}\n\n'
#             # 强制刷新stdout缓冲区
#             sys.stdout.flush()
#             return
# 
#     #print("响应结束:"+ai_response)
#     return Response(stream_with_context(generate_response()), mimetype='text/event-stream', headers={
#         'Cache-Control': 'no-cache',
#         'X-Accel-Buffering': 'no'  # 禁用Nginx缓冲
#     })
# """
# 
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)