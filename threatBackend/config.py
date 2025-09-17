# 宏部分
SILICONFLOW_BASE_URL="https://api.siliconflow.cn/v1"
SILICONFLOW_API_KEY="sk-mjhoskrqxbqokodcrydxkpqukelwwuvpvdjztidiqelfxomj"
SILICONFLOW_MODEL = "deepseek-ai/DeepSeek-V3"
DESCRIPTION_FOLDER = "./data/descriptions"
THREAT_MODEL_FOLDER = "./data/threat_models"
ATTACK_TREE_FOLDER = "./data/attack_trees"
MITIGATION_FOLDER = "./data/mitigations"
#给Json添加完commit后的路径
COMMIT_FOLDER = "./data/commits"
#LLM处理后的Json文件路径
DREAD_FOLDER = "./data/dreads"
TEST_CASE_FOLDER = "./data/test_cases"
DFD_ID_FILE = "./data/dfd_id.txt"
AGENT_SESSION_FOLDER = "./data/agent_sessions"
AGENT_SESSION_FILE = "session.txt"

REPORT_FOLDER = "./data/reports"
ATTCK_FOLDER = "./data/attck"

DB_PERSISTENCE = False

# 应用属性配置

app_types=[
    "Web 应用程序",
    "移动应用程序",
    "桌面应用程序",
    "云应用程序",
    "物联网(IoT)应用程序",
    "其他",
]


authentications = ["None", "SSO", "MFA", "OAUTH2", "Basic"]

internet_facing = ["Yes", "No"]

sensitive_data=[
    "Top Secret",
    "Secret",
    "Confidential",
    "Restricted",
    "Unclassified",
    "None",
]


class app_attrs:
    def __init__(self, app_type = app_types[0], 
                 authentication = authentications[0], 
                 internet_facing = internet_facing[0], 
                 sensitive_data = sensitive_data[0]):
        self.app_type = app_type
        self.authentication = authentication
        self.internet_facing = internet_facing
        self.sensitive_data = sensitive_data
