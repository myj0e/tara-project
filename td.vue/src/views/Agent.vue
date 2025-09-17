<template>
  <b-container fluid class="full-height p-0">
    <b-row class="h-100">
      <!-- 左侧边栏 -->
      <b-col cols="3" class="sidebar h-100 d-flex flex-column border-right">
        <div class="p-3">
          <b-button 
            variant="primary" 
            class="w-100 mb-3" 
            @click="newSession"
          >
            <font-awesome-icon icon="plus" class="mr-2"></font-awesome-icon>
            新对话
          </b-button>
        </div>
        
        <div class="conversation-list flex-grow-1 overflow-auto">
          <!-- 对话历史列表可以在这里添加 -->
        </div>
      </b-col>
      
      <!-- 主聊天区域 -->
      <b-col cols="9" class="chat-container d-flex flex-column h-100">
        <!-- 聊天内容区域 -->
        <div class="chat-messages flex-grow-1 overflow-auto p-3" ref="chatMessages">
          <div 
            v-for="(message, index) in messages" 
            :key="index"
            :class="['message', message.role === 'user' ? 'user-message' : 'agent-message']"
          >
            <div class="message-content">
              <div class="message-text" v-html="renderMarkdown(message.content)"></div>
              <div class="message-time">{{ formatTime(message.timestamp) }}</div>
            </div>
          </div>
          
          <!-- 打字机效果指示器 -->
          <div v-if="isTyping" class="message agent-message">
            <div class="message-content">
              <div class="typing-indicator">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- 输入区域 -->
        <div class="chat-input-area p-3 border-top mt-auto">
          <b-form @submit.prevent="sendMessage">
            <b-input-group>
              <b-form-textarea
                id="message-input"
                v-model="newMessage"
                :disabled="sending"
                placeholder="输入消息..."
                rows="3"
                max-rows="6"
                class="message-textarea"
                @keydown="handleKeydown"
              ></b-form-textarea>
              <b-input-group-append class="align-items-end">
                <b-button 
                  type="submit" 
                  variant="primary" 
                  :disabled="sending || !newMessage.trim()"
                  class="send-button ml-2"
                >
                  <b-spinner v-if="sending" small></b-spinner>
                  <font-awesome-icon 
                    v-else
                    icon="paper-plane" 
                    class="mr-1"
                  ></font-awesome-icon>
                  发送
                </b-button>
              </b-input-group-append>
            </b-input-group>
          </b-form>
        </div>
      </b-col>
    </b-row>
  </b-container>
</template>

<script>
import axios from 'axios';
import MarkdownIt from 'markdown-it';

export default {
  name: 'Agent',
  data() {
    return {
      sessionId: null,
      messages: [],
      newMessage: '',
      sending: false,
      md: null,
      isTyping: false,  // 添加打字机状态
      typingText: '',   // 当前正在打字的文本
      currentMessageIndex: -1,  // 当前打字的消息索引
      abortController: null  // 添加AbortController用于中断请求
    };
  },
  async mounted() {
    await this.newSession();
    // 初始化MarkdownIt实例
    this.md = new MarkdownIt({
      html: true,
      breaks: true,
      linkify: true
    });
  },
  methods: {
    clearInput() {
      // 清空输入框内容
      this.newMessage = '';
      
      // 如果输入框处于禁用状态，添加一个视觉反馈
      if (this.sending) {
        // 可以在这里添加一些视觉反馈，比如临时启用输入框或显示一个提示
        // 这里我们只是添加一个注释，说明可以扩展功能
      }
    },
    
    handleKeydown(event) {
      if (event.key === 'Enter') {
        if (event.shiftKey) {
          // Shift+Enter - 允许换行，使用默认行为
          return;
        } else {
          // 只按 Enter - 发送消息
          event.preventDefault();
          this.sendMessage();
          this.newMessage='';
        }
      }
    },
    
    async newSession() {
      try {
        // 如果有正在进行的发送操作，先中断它
        if (this.sending && this.abortController) {
          this.abortController.abort();
        }
        
        const response = await axios.get('/agent');
        this.sessionId = response.data;
        console.log("sessionId",this.sessionId);
        this.messages = [];
      } catch (error) {
        console.error('Failed to create new session:', error);
        this.$toast.error('创建新会话失败');
      }
    },
    
    // 实现打字机效果
    typeMessage(content, messageIndex) {
      return new Promise((resolve) => {
        let i = 0;
        this.currentMessageIndex = messageIndex;
        this.typingText = '';
        
        const type = () => {
          if (i < content.length) {
            this.typingText += content.charAt(i);
            i++;
            setTimeout(type, 20); // 每个字符20ms
          } else {
            resolve();
          }
        };
        
        type();
      });
    },
    
    async sendMessage() {
      if (!this.newMessage.trim() || this.sending) {
        return;
      }
      
      const userMessage = {
        role: 'user',
        content: this.newMessage.trim(),
        timestamp: new Date()
      };
     
      
      this.messages.push(userMessage);
      const messageToSend = this.newMessage.trim();
      this.sending = true;
      
      // 创建新的AbortController用于可能的中断操作
      this.abortController = new AbortController();

      // 滚动到底部
      this.$nextTick(() => {
        this.scrollToBottom();
      });
      
      try {
        // 使用axios发送POST请求并接收完整响应
        const response = await axios.post(`/agent/${this.sessionId}`, {
          message: messageToSend
        }, {
          signal: this.abortController.signal  // 将signal传递给axios
        });
        
        // 启动打字机效果
        this.isTyping = true;
        const agentContent = response.data.response || response.data;
        
        // 创建临时消息对象
        const agentMessage = {
          role: 'agent',
          content: '',
          timestamp: new Date()
        };
        this.messages.push(agentMessage);
        const messageIndex = this.messages.length - 1;
        
        // 逐字显示消息
        let i = 0;
        const type = () => {
          // 检查是否已被中断
          if (this.abortController.signal.aborted) {
            this.isTyping = false;
            return;
          }
          
          if (i < agentContent.length) {
            this.messages[messageIndex].content += agentContent.charAt(i);
            i++;
            this.$nextTick(() => {
              this.scrollToBottom();
            });
            if((agentContent.charAt(i)>'!' && agentContent.charAt(i)<'~')){
              setTimeout(type, 1);
            }
            else{
              setTimeout(type, 10);
            }
          } else {
            this.isTyping = false;
          }
        };
        
        type();
      } catch (error) {
        // 如果是由于中断导致的错误，则不显示错误消息
        if (error.name === 'AbortError' || this.abortController.signal.aborted) {
          console.log('Message sending was aborted');
          this.isTyping = false;
          return;
        }
        
        console.error('Failed to send message:', error);
        this.$toast.error('发送消息失败');
        // 添加错误消息到聊天记录
        this.messages.push({
          role: 'agent',
          content: '抱歉，发送消息时出现错误，请稍后重试。',
          timestamp: new Date()
        });
        this.isTyping = false;
        // 出错时也清空输入框
        this.newMessage = '';
      } finally {
        this.sending = false;
        this.clearInput();
        this.$nextTick(() => {
          this.scrollToBottom();
        });
      }
    },
    
    renderMarkdown(content) {
      if (!this.md) {
        return content;
      }
      return this.md.render(content);
    },
    
    scrollToBottom() {
      const container = this.$refs.chatMessages;
      if (container) {
        container.scrollTop = container.scrollHeight;
      }
    },
    
    formatTime(timestamp) {
      return timestamp.toLocaleTimeString('zh-CN', { 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    }
  }
};
</script>

<style scoped lang="scss">
.full-height {
  height: calc(100vh - 56px); // 减去navbar高度
}

.sidebar {
  background-color: #f8f9fa;
}

.chat-container {
  background-color: #ffffff;
  display: flex;
  flex-direction: column;
}

.chat-messages {
  background-color: #f0f2f5;
  flex: 1;
  overflow-y: auto;
}

.message {
  display: flex;
  margin-bottom: 1rem;
  
  &.user-message {
    justify-content: flex-end;
    
    .message-content {
      background-color: #0084ff;
      color: white;
      border-radius: 18px 4px 18px 18px;
    }
  }
  
  &.agent-message {
    justify-content: flex-start;
    
    .message-content {
      background-color: #ffffff;
      color: #333333;
      border-radius: 4px 18px 18px 18px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    }
  }
}

.message-content {
  max-width: 70%;
  padding: 0.75rem 1rem;
  
  .message-text {
    word-wrap: break-word;
    white-space: normal;
    line-height: 1.5;
  }
  
  /* Markdown内容样式 */
  ::v-deep h1,
  ::v-deep h2,
  ::v-deep h3,
  ::v-deep h4,
  ::v-deep h5,
  ::v-deep h6 {
    margin: 10px 0;
    font-weight: bold;
  }
  
  ::v-deep p {
    margin: 0 0 8px 0;
    line-height: inherit;
  }
  
  ::v-deep ul,
  ::v-deep ol {
    padding-left: 20px;
    margin: 8px 0;
  }
  
  ::v-deep li {
    margin: 4px 0;
  }
  
  ::v-deep code {
    background-color: rgba(0, 0, 0, 0.05);
    padding: 2px 4px;
    border-radius: 3px;
    font-family: monospace;
  }
  
  ::v-deep pre {
    background-color: rgba(0, 0, 0, 0.05);
    padding: 10px;
    border-radius: 5px;
    overflow-x: auto;
    margin: 0 0 8px 0;
  }
  
  ::v-deep pre code {
    background: none;
    padding: 0;
  }
  
  ::v-deep blockquote {
    border-left: 4px solid #ddd;
    padding-left: 10px;
    margin: 8px 0;
    color: #666;
  }
  
  ::v-deep a {
    color: #0066cc;
    text-decoration: underline;
  }
  
  ::v-deep strong {
    font-weight: bold;
  }
  
  ::v-deep em {
    font-style: italic;
  }

  .message-time {
    font-size: 0.75rem;
    text-align: right;
    margin-top: 0.25rem;
    opacity: 0.7;
  }
}

.chat-input-area {
  background-color: #ffffff;
  
  .message-textarea {
    resize: none;
  }
  
  .send-button {
    height: calc(100% - 1rem);
    align-self: flex-end;
    margin-bottom: 0.5rem;
  }
}

.conversation-list {
  // 对话历史列表样式
}

// 打字机效果指示器样式
.typing-indicator {
  display: flex;
  align-items: center;
  padding: 5px 0;
  
  span {
    height: 8px;
    width: 8px;
    background: #999;
    border-radius: 50%;
    margin: 0 2px;
    animation: typing 1s infinite;
    
    &:nth-child(2) {
      animation-delay: 0.2s;
    }
    
    &:nth-child(3) {
      animation-delay: 0.4s;
    }
  }
}

@keyframes typing {
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-5px);
  }
}
</style>