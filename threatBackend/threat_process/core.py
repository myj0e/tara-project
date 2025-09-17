import json
import time
from threading import Event
from threat_process.workflow import workflow
from threat_process.workflowDB import workflowDB

def core(que, stop_event:Event,base_url, api_key, model_name):
    """
    核心函数，从消息队列中读取JSON内容并打印
    """
    print(base_url)
    print(api_key)
    print(model_name)
    while not stop_event.is_set():
        try:
            # 从消息队列中获取数据
            if not que.empty():
                # 从队列中取出一条消息
                message = que.get()
                
                # 打印接收到的数据
                #print("Received message from queue:", message)
                
                # 如果消息是字符串形式的JSON，尝试解析
                if isinstance(message, str):
                    try:
                        data = json.loads(message)
                        #print("Parsed JSON data:", data)
                        dfd_id = data["id"]
                    except json.JSONDecodeError as e:
                        print("Failed to decode JSON:", e)
                else:
                    # 如果消息本身就是字典或其他对象，直接赋值
                    #print("Received object:", message)
                    dfd_id = message["id"]
                workflow(base_url, api_key, model_name, dfd_id)
                #workflowDB(base_url, api_key, model_name, dfd_id)
                    
            else:
                #print("No messages in queue, waiting...")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("Core function interrupted by user")
            break
        except Exception as e:
            print("Error in core function:", e)
            time.sleep(1)

if __name__ == "__main__":
    # 这里应该传入一个实际的队列对象进行测试
    pass