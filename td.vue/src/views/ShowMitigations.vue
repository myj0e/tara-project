<template>
    <b-container fluid class="full-height">
        <b-jumbotron id="show-mitigations-jumbotron" class="full-height" fluid>
            <b-row>
                <b-col md="12">
                    <h1 class="display-5 text-center">缓解措施</h1>
                </b-col>
            </b-row>


            <b-row>
                <b-col md="12">
                    <div>
                        <!-- 加载状态提示 -->
                        <div v-if="loading" class="text-center my-3">
                            <b-spinner variant="primary"></b-spinner>
                            <p>正在分析数据...</p>
                        </div>

                        <!-- 错误提示 -->
                        <div v-if="error" class="alert alert-danger my-3">
                            {{ error }}
                        </div>

                        <!-- 缓解措施内容 -->
                        <div v-if="!loading && !error" class="mitigations-content">
                            <!-- 查看报告按钮 -->
                            <b-row class="mb-3">
                                <b-col md="12">
                                    <b-button variant="primary" class="float-right" @click="$router.push('/local/threatmodel/report')">查看报告</b-button>
                                </b-col>
                            </b-row>
                            
                            <div v-html="mitigationsHtml"></div>
                        </div>
                    </div>
                </b-col>
            </b-row>
        </b-jumbotron>
    </b-container>
</template>

<style lang="scss" scoped>
.full-height {
    min-height: 100vh;
    height: 100%;
}

#show-mitigations-jumbotron {
    padding: 0;
    margin: 0;
}

.mitigations-content {
    padding: 20px;
    background-color: #f8f9fa;
    border-radius: 5px;
    min-height: 300px;
    font-size: 0.9rem; // 调整字体大小
    
    // 改进表格样式
    ::v-deep table {
        border-collapse: collapse;
        width: auto; // 改为自动宽度
        margin: 1rem auto; // 水平居中
        display: block; // 使margin: auto生效
        overflow-x: auto; // 防止表格溢出容器
        max-width: 100%;
    }
    
    ::v-deep table th,
    ::v-deep table td {
        border: 1px solid #ddd;
        padding: 12px 15px; // 增加内边距，使列更分散
        text-align: left;
    }
    
    ::v-deep table th {
        background-color: #e9ecef;
        font-weight: bold;
    }
    
    // 使用深度选择器确保样式能正确应用到动态渲染的表格
    ::v-deep table tbody tr:nth-child(odd) td {
        background-color: #ffffff; // 白色背景
    }
    
    ::v-deep table tbody tr:nth-child(even) td {
        background-color: #ffe5cc; // 浅橘色背景
    }
    
    ::v-deep table tr:hover td {
        background-color: #e2e6ea; // 悬停效果
    }
}

</style>

<script>
import axios from 'axios';
import MarkdownIt from 'markdown-it';

export default {
    name: 'ShowMitigations',
    components: {
        // 如果需要添加其他组件可以在这里引入
    },
    data() {
        return {
            mitigationsMd: '',
            mitigigationsHtml: '',
            loading: true,
            error: null
        };
    },
    mounted() {
        // 页面加载时获取缓解措施数据
        this.fetchMitigationsData();
    },
    methods: {
        async fetchMitigationsData() {
            this.loading = true;
            this.error = null;

            try {
                // 轮询获取缓解措施数据
                let dfdid = localStorage.getItem('dfdHashId')
                let path = `/mitigations/${encodeURIComponent(dfdid)}`;
                await this.pollForMitigationsData(path, 30, 5000);
            } catch (error) {
                console.error('获取缓解措施数据时出错:', error);
                this.error = `获取缓解措施失败: ${error.message || '未知错误'}`;
            } finally {
                this.loading = false;
            }
        },
        
        // 轮询方法
        async pollForMitigationsData(apiUrl, maxAttempts = 30, interval = 5000) {
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    const response = await axios.get(apiUrl);
                    
                    if (response.status === 200) {
                        // 成功获取数据
                        this.mitigationsMd = response.data;
                        // 将mitigationsMd数据保存到localStorage中
                        localStorage.setItem('mitigationsMd', JSON.stringify(this.mitigationsMd));
                        // 使用markdown-it库渲染markdown，配置breaks选项以识别<br>换行
                        const md = new MarkdownIt({
                            breaks: true, // 转换 \n 为 <br>
                            html: true   // 允许HTML标签
                        });
                        this.mitigationsHtml = md.render(this.mitigationsMd);
                        return; // 成功获取数据，退出轮询
                    } else if (response.status === 202) {
                        // 202 Accepted - 数据仍在处理中
                        console.log(`缓解措施数据仍在处理中，第 ${attempt} 次尝试...`);
                    } else {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                } catch (error) {
                    // 如果是最后一次尝试，抛出错误
                    if (attempt === maxAttempts) {
                        throw error;
                    }
                    console.log(`获取缓解措施数据失败，${interval/1000}秒后重试... (${attempt}/${maxAttempts})`);
                }

                // 等待指定时间后重试
                await new Promise(resolve => setTimeout(resolve, interval));
            }

            throw new Error('获取缓解措施数据超时，请稍后重试');
        },
    }
};
</script>