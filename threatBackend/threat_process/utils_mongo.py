from datetime import datetime
from pymongo import UpdateOne
from pymongo import MongoClient
#================================配置================================
client = MongoClient("mongodb://admin:admin123@localhost:27017/")
db = client["threat_modeling"]
#====================================================================

def putAttackTreeMd(hash_id, attack_tree_md):
    try:
        collection = db["attack_tree_md"]
        doc = {
            "hash_id": hash_id,
            "content": attack_tree_md,
            "created_at": datetime.utcnow()
        }

        print(hash_id+" 攻击树插入成功")
        collection.insert_one(doc)
    except Exception as e:
        print(f"插入攻击树失败: {e}")
def getAttackTreeMd(hash_id):
    try:
        collection = db["attack_tree_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            return doc["content"]
        else:
            print(hash_id+" 攻击树未找到")
            return None
    except Exception as e:
        print(f"异常！获取攻击树失败: {hash_id}")
def findAttackTreeMd(hash_id):
    try:
        collection = db["attack_tree_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            print(hash_id+" 攻击树查找成功")
            return True
        else:
            print(hash_id+" 攻击树未找到")
            return False
    except Exception as e:
        print(f"异常！查找攻击树失败: {e}")
        return True



def putAttackMd(hash_id, attack_md):
    try:
        db = client["attack_md"]
        collection = db["users"]
        doc = {
            "hash_id": hash_id,
            "content": attack_md,
            "created_at": datetime.utcnow()
        }

        print(hash_id+" 攻击插入成功")
        collection.insert_one(doc)
    except Exception as e:
        print(f"异常！插入攻击失败: {e}")
def getAttackMd(hash_id):
    try:
        db = client["attack_md"]
        collection = db["users"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            return doc["content"]
        else:
            print(hash_id+" 攻击未找到get")
            return None
    except Exception as e:
        print(f"异常！获取攻击失败: {e}")
        return None
def findAttackMd(hash_id):
    try:
        collection = db["attack_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            print(hash_id+" 攻击查找成功")
            return True
        else:
            print(hash_id+" 攻击未找到find")
            return False
    except Exception as e:
        print(f"异常！查找攻击失败: {e}")
        return False


def putDescriptionsMd(hash_id, descriptions_md):
    try:
        collection = db["descriptions_md"]
        doc = {
            "hash_id": hash_id,
            "content": descriptions_md,
            "created_at": datetime.utcnow()
        }
        print(hash_id+" Descriptions插入成功")
        collection.insert_one(doc)
    except Exception as e:
        print(f"异常！插入Descriptions失败: {e}")
def getDescriptionsMd(hash_id):
    try:
        collection = db["descriptions_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            return doc["content"]
        else:
            print(hash_id+" Descriptions未找到")
            return None
    except Exception as e:
        print(f"异常！获取Descriptions失败: {e}")
        return None
def findDescriptionsMd(hash_id):
    try:
        collection = db["descriptions_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            print(hash_id+" Descriptions查找成功")
            return True
        else:
            print(hash_id+" Descriptions未找到")
            return False
    except Exception as e:
        print(f"异常！查找Descriptions失败: {e}")
        return False

def putMitigationsMd(hash_id, mitigations_md):
    try:
        collection = db["mitigations_md"]
        doc = {
            "hash_id": hash_id,
            "content": mitigations_md,
            "created_at": datetime.utcnow()
        }
        print(hash_id+" 缓解措施插入成功")
        collection.insert_one(doc)
    except Exception as e:
        print(f"异常！插入缓解措施失败: {e}")
def getMitigationsMd(hash_id):
    collection = db["mitigations_md"]
    doc = collection.find_one({"hash_id": hash_id})
    if doc:
        return doc["content"]
    else:
        print(hash_id+" 缓解措施未找到")
        return None
def findMitigationsMd(hash_id):
    try:
        collection = db["mitigations_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            print(hash_id+" 缓解措施查找成功")
            return True
        else:
            print(hash_id+" 缓解措施未找到")
            return False
    except Exception as e:
        print(f"异常！查找缓解措施失败: {e}")
        return False

def putReportsMd(hash_id, reports_md):
    collection = db["reports_md"]
    doc = {
        "hash_id": hash_id,
        "content": reports_md,
        "created_at": datetime.utcnow()
    }
    print(hash_id+" Reports插入成功")
    collection.insert_one(doc)
def getReportsMd(hash_id):
    collection = db["reports_md"]
    doc = collection.find_one({"hash_id": hash_id})
    if doc:
        return doc["content"]
    else:
        print(hash_id+" Reports报告未找到")
        return None
def findReportsMd(hash_id):
    try:
        collection = db["reports_md"]
        doc = collection.find_one({"hash_id": hash_id})
        if doc:
            print(hash_id+" Reports报告查找成功")
            return True
        else:
            print(hash_id+" Reports报告未找到")
            return False
    except Exception as e:
        print(f"异常！查找Reports报告失败: {e}")
        return False

#攻击树JSON放入Mongo
# from your_mongo_client import db
def ensure_attack_tree_indexes():
    """初始化索引（只需调用一次，或在启动时调用）。"""
    coll = db["attack_tree_nodes"]
    coll.create_index([("hash_id", 1), ("node_key", 1)], unique=True)
    coll.create_index([("hash_id", 1), ("parent_key", 1), ("sibling_order", 1)])
    coll.create_index([("hash_id", 1), ("ancestors", 1)])
    # 可选：按深度过滤时更快
    coll.create_index([("hash_id", 1), ("depth", 1)])
def putAttackTreeJSON(hash_id: str, tree_json: dict) -> bool:
    """
    幂等写入攻击树：
      - 将树展开为节点列表（包含 ancestors/parent_key/depth/sibling_order）
      - bulk upsert（不存在则插入、存在则更新）
      - 删除这次未出现的旧节点（保持幂等）
    返回 True/False 表示是否成功。
    """
    try:
        coll = db["attack_tree_nodes"]

        # 1) 展开树 → 扁平节点
        flat = []
        def walk(node: dict, parent_key: str | None, ancestors: list[str], order: int):
            node_key = (node.get("id") or "").strip()
            if not node_key:
                return
            label = (node.get("label") or "").strip()

            flat.append({
                "hash_id": hash_id,
                "node_key": node_key,
                "label": label,
                "parent_key": parent_key,
                "ancestors": ancestors[:],              # 从根到父
                "depth": len(ancestors),                # 根=0
                "sibling_order": order,                 # 同级顺序
                "root_key": ancestors[0] if ancestors else node_key,
            })

            for idx, child in enumerate(node.get("children") or []):
                walk(child, node_key, ancestors + [node_key], idx)

        roots = tree_json.get("nodes") or []
        if not roots:
            print(f"{hash_id} AttackTree为空，未写入")
            return False

        for r_idx, root in enumerate(roots):
            walk(root, None, [], r_idx)

        # 2) 批量 upsert
        now = datetime.utcnow()
        ops = [
            UpdateOne(
                {"hash_id": hash_id, "node_key": doc["node_key"]},
                {
                    "$set": {
                        "label": doc["label"],
                        "parent_key": doc["parent_key"],
                        "ancestors": doc["ancestors"],
                        "depth": doc["depth"],
                        "sibling_order": doc["sibling_order"],
                        "root_key": doc["root_key"],
                        "updated_at": now
                    },
                    "$setOnInsert": {"created_at": now}
                },
                upsert=True
            )
            for doc in flat
        ]
        if ops:
            coll.bulk_write(ops, ordered=False)

        # 3) 删除这次没有出现的旧节点（幂等清理）
        keep_keys = [d["node_key"] for d in flat]
        coll.delete_many({"hash_id": hash_id, "node_key": {"$nin": keep_keys}})

        print(f"{hash_id} AttackTree upsert成功（{len(flat)} 个节点）")
        return True

    except Exception as e:
        print(f"异常！插入AttackTree失败: {e}")
        return False
def getAttackTreeJSON(hash_id: str, root_key: str | None = None) -> dict:
    """
    读取攻击树并还原为前端的嵌套 JSON：
      - root_key=None：返回整棵树（可能是“森林”，nodes = [root1, root2, ...]）
      - root_key=某节点：仅返回该节点为根的子树
    """
    try:
        coll = db["attack_tree_nodes"]

        query = {"hash_id": hash_id}
        if root_key:
            query["$or"] = [{"node_key": root_key}, {"ancestors": root_key}]

        cur = coll.find(
            query,
            projection={"_id": 0, "hash_id": 0, "created_at": 0, "updated_at": 0}
        ).sort([("depth", 1), ("sibling_order", 1)])

        nodes = list(cur)
        if not nodes:
            print(f"{hash_id} AttackTree未找到")
            return {"nodes": []}

        # 组装嵌套结构
        by_key = {n["node_key"]: {"id": n["node_key"], "label": n.get("label", ""), "children": []} for n in nodes}
        roots = []

        for n in nodes:
            key = n["node_key"]
            parent = n.get("parent_key")
            if parent and parent in by_key:
                by_key[parent]["children"].append(by_key[key])
            else:
                roots.append(by_key[key])

        if root_key:
            # 若指定根，返回该子树
            root = by_key.get(root_key)
            return {"nodes": [root] if root else []}
        else:
            # 否则返回完整森林（支持多根的情况）
            return {"nodes": roots}

    except Exception as e:
        print(f"异常！获取AttackTree失败: {e}")
        return {"nodes": []}
def findAttackTreeJSON(hash_id: str) -> bool:
    """
    判断该 hash_id 的攻击树是否存在（至少有一个节点）。
    """
    try:
        coll = db["attack_tree_nodes"]
        exists = coll.find_one({"hash_id": hash_id}, {"_id": 1})
        if exists:
            print(f"{hash_id} AttackTree查找成功")
            return True
        else:
            print(f"{hash_id} AttackTree未找到")
            return False
    except Exception as e:
        print(f"异常！查找AttackTree失败: {e}")
        return False
#将AttckJSON放入
def ensure_attck_map_indexes():
    coll = db["attck_map_json"]
    # 一个 hash_id 对应一份 ATT&CK 映射
    coll.create_index([("hash_id", 1)], unique=True)
    # 按 name 或 leaf_node 查询更快
    coll.create_index([("name", 1)])
    coll.create_index([("list.leaf_node", 1)])
def putAttckMapJSON(hash_id: str, attck_json: dict) -> bool:
    """
    JSON 存入集合 attck_map_json（整包存一条文档）。
    """
    try:
        coll = db["attck_map_json"]
        now = datetime.utcnow()

        # 规范化 & 兜底
        doc = {
            "hash_id": hash_id,
            "name": (attck_json or {}).get("name", "") or "",
            "list": [
                {
                    "leaf_node": item.get("leaf_node", "") or "",
                    "attck": [
                        {
                            "attck_id": a.get("attck_id", "") or "",
                            "attck_name": a.get("attck_name", "") or "",
                            "attck_description": a.get("attck_description", "") or "",
                            "attck_url": a.get("attck_url", "") or ""
                        }
                        for a in (item.get("attck") or [])
                    ]
                }
                for item in ((attck_json or {}).get("list") or [])
            ],
            "updated_at": now
        }

        coll.update_one(
            {"hash_id": hash_id},
            {"$set": doc, "$setOnInsert": {"created_at": now}},
            upsert=True
        )
        print(f"{hash_id} ATT&CK 映射 upsert 成功")
        return True
    except Exception as e:
        print(f"异常！ATT&CK 映射写入失败: {e}")
        return False
def getAttckMapJSON(hash_id: str, leaf_node: str | None = None) -> dict:
    """
    leaf_node 为 None 时返回整份 JSON；
    否则只返回该 leaf_node 对应的那一项
    """
    try:
        coll = db["attck_map_json"]
        if leaf_node:
            doc = coll.find_one(
                {"hash_id": hash_id, "list.leaf_node": leaf_node},
                {"_id": 0, "hash_id": 0, "list": {"$elemMatch": {"leaf_node": leaf_node}}}
            )
            return doc or {"name": "", "list": []}
        else:
            doc = coll.find_one({"hash_id": hash_id}, {"_id": 0, "hash_id": 0})
            return doc or {"name": "", "list": []}
    except Exception as e:
        print(f"异常！ATT&CK 读取失败: {e}")
        return {"name": "", "list": []}
def findAttckMapJSON(hash_id: str) -> bool:
    try:
        coll = db["attck_map_json"]
        ok = coll.find_one({"hash_id": hash_id}, {"_id": 1})
        if ok:
            print(f"{hash_id} ATT&CK 查找成功")
            return True
        else:
            print(f"{hash_id} ATT&CK 未找到")
            return False
    except Exception as e:
        print(f"异常！ATT&CK 查找失败: {e}")
        return False

