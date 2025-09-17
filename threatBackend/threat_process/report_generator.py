import os
from config import REPORT_FOLDER

def generate_report(dfd_id, data):
    """
    将合并后的 threat 建议数据生成 markdown 格式的报告，保存到 REPORT_FOLDER/{dfd_id}.md
    """
    md_lines = [f"# 威胁建模建议报告：{dfd_id}", ""]

    for node in data.get("nodes", []):
        node_name = node.get("name", "未知节点")
        node_type = node.get("type", "未知类型")
        md_lines.append(f"## 节点：{node_name}（{node_type}）")

        stride = node.get("stride", {})
        for threat_type, threat in stride.items():
            md_lines.append(f"### 威胁类型：{threat_type}")

            # 描述与场景
            md_lines.append(f"- **描述（LLM 原始）**：{threat.get('description', '无')}")
            md_lines.append(f"- **场景分析**：{threat.get('Scenario', '无')}")

            # DREAD 打分
            md_lines.append(f"- **DREAD 打分：**")
            dread = threat.get("dread", {})
            for k in ["D", "R", "E", "A", "D2"]:
                v = dread.get(k, "无")
                md_lines.append(f"  - {k}：{v}")

            # 如果有人工 commit 修改，加入说明
            if "commit" in threat:
                md_lines.append(f"- **人工修改说明：**{threat['commit']}")

            md_lines.append("")  # 添加空行

        md_lines.append("")  # 每个节点结束后空行

    # 保存 markdown 文件
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    report_path = os.path.join(REPORT_FOLDER, f"{dfd_id}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"Markdown 报告已生成：{report_path}")

