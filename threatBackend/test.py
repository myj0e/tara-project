from threat_process.attck import merge_attck_into_attack_tree
from threat_process.attack_tree import convert_tree_to_mermaid
import pymysql
import os

def execute_sql_file(sql_file_path, root_password):
    """
    执行SQL文件来初始化数据库
    
    参数:
    sql_file_path: SQL文件的路径
    root_password: MySQL root用户的密码
    
    返回:
    bool: 执行成功返回True，否则返回False
    """
    # 检查SQL文件是否存在
    if not os.path.exists(sql_file_path):
        print(f"错误: SQL文件 {sql_file_path} 不存在")
        return False
    
    try:
        # 创建数据库连接配置（不指定具体数据库）
        db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': root_password,
            'charset': 'utf8mb4'
        }
        
        # 连接到MySQL服务器
        connection = pymysql.connect(**db_config)
        cursor = connection.cursor()
        
        # 读取并执行SQL文件
        with open(sql_file_path, 'r', encoding='utf-8') as file:
            sql_script = file.read()
        
        # 分割SQL语句（按分号分割）
        sql_commands = sql_script.split(';')
        
        # 执行每个SQL命令
        for command in sql_commands:
            command = command.strip()
            if command:  # 忽略空命令
                try:
                    cursor.execute(command)
                    print(f"成功执行: {command[:50]}...")
                except Exception as e:
                    print(f"执行SQL命令失败: {command[:50]}...")
                    print(f"错误信息: {e}")
                    raise e
        
        # 提交事务
        connection.commit()
        print("SQL文件执行完成，数据库初始化成功")
        return True
        
    except Exception as e:
        print(f"执行SQL文件时发生错误: {e}")
        return False
    
    finally:
        # 关闭数据库连接
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

# 示例调用
if __name__ == "__main__":
    # 调用函数执行SQL文件
    # 注意：请根据实际情况修改SQL文件路径和root密码
    execute_sql_file("/home/yzy/tara.sql", "123456")

attack_tree = {
    "nodes": [
        {
            "id": "root",
            "label": "攻破应用程序",
            "children": [
                {
                    "id": "auth",
                    "label": "获得未授权访问",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "利用Web应用配置漏洞",
                            "children": [
                                {
                                    "id": "auth1_1",
                                    "label": "读取Web应用配置"
                                }
                            ]
                        },
                        {
                            "id": "auth2",
                            "label": "利用Worker配置漏洞",
                            "children": [
                                {
                                    "id": "auth2_1",
                                    "label": "读取Worker配置"
                                }
                            ]
                        },
                        {
                            "id": "auth3",
                            "label": "利用数据库漏洞",
                            "children": [
                                {
                                    "id": "auth3_1",
                                    "label": "SQL注入攻击"
                                }
                            ]
                        }
                    ]
                },
                {
                    "id": "data",
                    "label": "窃取或篡改数据",
                    "children": [
                        {
                            "id": "data1",
                            "label": "攻击数据库",
                            "children": [
                                {
                                    "id": "data1_1",
                                    "label": "通过Web应用进行SQL注入"
                                },
                                {
                                    "id": "data1_2",
                                    "label": "通过Worker进行SQL注入"
                                }
                            ]
                        },
                        {
                            "id": "data2",
                            "label": "攻击消息队列",
                            "children": [
                                {
                                    "id": "data2_1",
                                    "label": "伪造或篡改消息"
                                }
                            ]
                        }
                    ]
                },
                {
                    "id": "process",
                    "label": "破坏进程",
                    "children": [
                        {
                            "id": "process1",
                            "label": "攻击Web应用进程",
                            "children": [
                                {
                                    "id": "process1_1",
                                    "label": "通过Web请求进行DoS攻击"
                                }
                            ]
                        },
                        {
                            "id": "process2",
                            "label": "攻击Worker进程",
                            "children": [
                                {
                                    "id": "process2_1",
                                    "label": "通过消息队列进行DoS攻击"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}

#print(convert_tree_to_mermaid(attack_tree))

attck = {
    "name": "att-ck",
    "list": [
        {
            "leaf_node": "读取Web应用配置",
            "attck": [
                {
                    "attck_id": "T1592",
                    "attck_name": "Gather Victim Host Information",
                    "attck_description": "攻击者通过读取Web应用配置获取目标主机信息",
                    "attck_url": "https://attack.mitre.org/techniques/T1592/"
                },
                {
                    "attck_id": "T1213",
                    "attck_name": "Data from Information Repositories",
                    "attck_description": "攻击者从信息存储库中获取Web应用配置数据",
                    "attck_url": "https://attack.mitre.org/techniques/T1213/"
                }
            ]
        },
        {
            "leaf_node": "读取Worker配置",
            "attck": [
                {
                    "attck_id": "T1592",
                    "attck_name": "Gather Victim Host Information",
                    "attck_description": "攻击者通过读取Worker配置获取目标主机信息",
                    "attck_url": "https://attack.mitre.org/techniques/T1592/"
                },
                {
                    "attck_id": "T1213",
                    "attck_name": "Data from Information Repositories",
                    "attck_description": "攻击者从信息存储库中获取Worker配置数据",
                    "attck_url": "https://attack.mitre.org/techniques/T1213/"
                }
            ]
        },
        {
            "leaf_node": "SQL注入攻击",
            "attck": [
                {
                    "attck_id": "T1190",
                    "attck_name": "Exploit Public-Facing Application",
                    "attck_description": "攻击者利用SQL注入漏洞攻击公开的应用程序",
                    "attck_url": "https://attack.mitre.org/techniques/T1190/"
                },
                {
                    "attck_id": "T1505",
                    "attck_name": "Server Software Component",
                    "attck_description": "攻击者通过SQL注入攻击服务器软件组件",
                    "attck_url": "https://attack.mitre.org/techniques/T1505/"
                }
            ]
        },
        {
            "leaf_node": "通过Web应用进行SQL注入",
            "attck": [
                {
                    "attck_id": "T1190",
                    "attck_name": "Exploit Public-Facing Application",
                    "attck_description": "攻击者通过Web应用进行SQL注入攻击",
                    "attck_url": "https://attack.mitre.org/techniques/T1190/"
                },
                {
                    "attck_id": "T1505",
                    "attck_name": "Server Software Component",
                    "attck_description": "攻击者通过Web应用进行SQL注入攻击服务器软件组件",
                    "attck_url": "https://attack.mitre.org/techniques/T1505/"
                }
            ]
        },
        {
            "leaf_node": "通过Worker进行SQL注入",
            "attck": [
                {
                    "attck_id": "T1190",
                    "attck_name": "Exploit Public-Facing Application",
                    "attck_description": "攻击者通过Worker进行SQL注入攻击",
                    "attck_url": "https://attack.mitre.org/techniques/T1190/"
                },
                {
                    "attck_id": "T1505",
                    "attck_name": "Server Software Component",
                    "attck_description": "攻击者通过Worker进行SQL注入攻击服务器软件组件",
                    "attck_url": "https://attack.mitre.org/techniques/T1505/"
                }
            ]
        },
        {
            "leaf_node": "伪造或篡改消息",
            "attck": [
                {
                    "attck_id": "T1553",
                    "attck_name": "Subvert Trust Controls",
                    "attck_description": "攻击者伪造或篡改消息以破坏信任控制",
                    "attck_url": "https://attack.mitre.org/techniques/T1553/"
                },
                {
                    "attck_id": "T1565",
                    "attck_name": "Data Manipulation",
                    "attck_description": "攻击者篡改消息队列中的数据",
                    "attck_url": "https://attack.mitre.org/techniques/T1565/"
                }
            ]
        },
        {
            "leaf_node": "通过Web请求进行DoS攻击",
            "attck": [
                {
                    "attck_id": "T1499",
                    "attck_name": "Endpoint Denial of Service",
                    "attck_description": "攻击者通过Web请求对Web应用进程进行DoS攻击",
                    "attck_url": "https://attack.mitre.org/techniques/T1499/"
                },
                {
                    "attck_id": "T1498",
                    "attck_name": "Network Denial of Service",
                    "attck_description": "攻击者通过大量Web请求导致网络拒绝服务",
                    "attck_url": "https://attack.mitre.org/techniques/T1498/"
                }
            ]
        },
        {
            "leaf_node": "通过消息队列进行DoS攻击",
            "attck": [
                {
                    "attck_id": "T1499",
                    "attck_name": "Endpoint Denial of Service",
                    "attck_description": "攻击者通过消息队列对Worker进程进行DoS攻击",
                    "attck_url": "https://attack.mitre.org/techniques/T1499/"
                },
                {
                    "attck_id": "T1498",
                    "attck_name": "Network Denial of Service",
                    "attck_description": "攻击者通过大量消息导致消息队列拒绝服务",
                    "attck_url": "https://attack.mitre.org/techniques/T1498/"
                }
            ]
        }
    ]
}

#print(merge_attck_into_attack_tree(attack_tree, attck))