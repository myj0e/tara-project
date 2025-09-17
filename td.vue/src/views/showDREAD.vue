<template>
    <b-container fluid class="full-height">
        <b-jumbotron id="show-dread-jumbotron" class="full-height" fluid>
            <b-row>
                <b-col md="12">
                    <h1 class="display-5 text-center">STRIDE 威胁建模</h1>
                </b-col>
            </b-row>

            <!-- 查看攻击树按钮 -->
            <b-row class="mb-3" v-if="!loading && !error">
                <b-col md="12" class="d-flex justify-content-end">
                    <b-button variant="primary" class="mr-2" @click="showAttackTree">查看攻击树</b-button>
                    <b-button type="submit" variant="primary" @click="submitEvaluation">提交并查看措施</b-button>
                </b-col>
            </b-row>

            <!-- 上半部分：表格区域 -->
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

                        <!-- 威胁数据表格 -->
                        <div v-if="!loading && !error" class="table-container">
                            <b-table
                                :items="threatItems"
                                :fields="threatFields"
                                striped
                                hover
                                responsive
                                small
                                fixed
                                head-variant="light"
                                sticky-header="250px"
                                :style="{ maxHeight: '230px' }"
                                :sort-by="'totalScore'"
                                :sort-desc="true"
                            >
                                <!-- 风险等级徽章渲染 -->
                                <template #cell(riskLevel)="row">
                                    <b-badge :variant="row.item.riskVariant">
                                        {{ row.item.riskText }}
                                    </b-badge>
                                </template>

                                <template #cell(actions)="row">
                                    <b-button 
                                        size="sm" 
                                        variant="info" 
                                        @click="showThreatDetails(row.item)"
                                    >
                                        查看详情
                                    </b-button>
                                </template>
                            </b-table>
                        </div>
                    </div>
                </b-col>
            </b-row>

            <!-- 下半部分：雷达图和评价区域 -->
            <b-row class="mt-4">
                <b-col md="6">
                    <!-- 雷达图显示区域 -->
                    <div v-if="selectedThreat">
                        <h4 class="text-center">{{ selectedNode.name }} - {{ threatLabels[selectedThreatType] }}</h4>
                        <div class="chart-wrapper">
                            <canvas id="dreadRadarChart" width="500" height="500"></canvas>
                        </div>
                    </div>
                    <div v-else class="text-center text-muted">
                        请选择一个威胁查看详情
                    </div>
                </b-col>

                <b-col md="6">
                    <div v-if="selectedThreat">
                        <!-- DREAD评分编辑区域（竖排一行一个） -->
                        <div class="dread-edit-section mb-4">
                            <h5>编辑DREAD评分</h5>
                            <div class="dread-list">
                                <b-row
                                    v-for="(label, key) in dreadLabels"
                                    :key="key"
                                    class="align-items-center mb-2 no-gutters"
                                >
                                    <!-- 键名 -->
                                    <b-col cols="1" class="text-right pr-2">
                                        <label :for="`dread-${key}`" class="mb-0 font-weight-bold">{{ key }}:</label>
                                    </b-col>
                                    <!-- 滑杆 -->
                                    <b-col cols="6" class="px-2">
                                        <b-form-input
                                            :id="`dread-${key}`"
                                            type="range"
                                            min="0"
                                            max="10"
                                            step="1"
                                            size="sm"
                                            v-model.number="editedDread[key]"
                                            @input="updateChartOnEdit"
                                            class="dread-slider"
                                        ></b-form-input>
                                    </b-col>
                                    <!-- 分值 -->
                                    <b-col cols="1" class="text-center">
                                        {{ editedDread[key] }}
                                    </b-col>
                                    <!-- 说明 -->
                                    <b-col cols="4" class="text-muted pl-2">
                                        {{ label }}
                                    </b-col>
                                </b-row>
                            </div>
                        </div>

                        <!-- 评价输入区域 -->
                        <div class="evaluation-section">
                            <b-form-group label="修改理由与反馈">
                                <b-form-textarea
                                    v-model="evaluationText"
                                    :placeholder="selectedNode && selectedThreatType && selectedNode.stride && selectedNode.stride[selectedThreatType].commit ? selectedNode.stride[selectedThreatType].commit : '修改后，请提交您的修改理由与反馈...'"
                                    rows="4"
                                    max-rows="6"
                                    :disabled="!isDreadModified"
                                    :class="{ 'warning-shake': showEvaluationWarning }"
                                ></b-form-textarea>
                            </b-form-group>
                            <div class="mt-2">
                                <small class="text-muted">当前选中: {{ selectedNode.name }} - {{ threatLabels[selectedThreatType] }}</small>
                            </div>
                        </div>
                    </div>
                    <div v-else class="text-center text-muted">
                        请选择一个威胁以添加评价
                    </div>
                </b-col>
            </b-row>
        </b-jumbotron>
        
        <!-- 攻击树模态框 -->
        <b-modal
          id="attackTreeModal"
          v-model="showModal"
          size="xl"
          title="攻击树视图"
          hide-footer
          modal-class="attack-tree-modal"
        >
          <div
            class="attack-tree-wrapper"
            @wheel.capture.stop.prevent="zoom"
          >
            <div
              class="attack-tree-scroll"
              ref="scrollContainer"
              @mousedown="startDrag"
              @mousemove="onDrag"
              @mouseup="endDrag"
              @mouseleave="endDrag"
            >
              <!-- 渲染结果容器 -->
              <div
                class="attack-tree-content"
                ref="contentRef"
              ></div>
            </div>
          </div>
        </b-modal>
    </b-container>
</template>

<style lang="scss" scoped>
.full-height {
    min-height: 100vh;
    height: 100%;
}

.login-btn-icon {
    display: block;
}

.td-description {
    font-size: 20px;
    margin-right: 20px;
    margin-left: 170px;
}

.td-cupcake {
    margin: 10px auto;
    display: block;
    max-width: 200px;
}

#dreadRadarChart {
    max-width: 100%;
    height: auto;
    margin: 0 auto;
}

.table-container {
    max-height: 230px;
    overflow-y: auto;
    margin: 0 auto;
    border: 1px solid #dee2e6;
    border-radius: 0.35rem;
}

/* 隐藏垂直滚动条但保持滚动功能 */
.table-container {
    -ms-overflow-style: none;  /* IE and Edge */
    scrollbar-width: none;  /* Firefox */
}

.table-container::-webkit-scrollbar {
    display: none;  /* Chrome, Safari, Opera */
}

/* 添加阴影效果 */
.table-container:hover {
    box-shadow: 0 0.15rem 1.75rem 0 rgba(58, 59, 69, 0.15);
}

.chart-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
}

.text-center {
    text-center: center;
}

.mt-2 {
    margin-top: 0.5rem;
}

#show-dread-jumbotron {
    padding: 0;
    margin: 0;
}

.dread-edit-section {
    background-color: #f8f9fa;
    border-radius: 5px;
    padding: 15px;
}

/* 旧的两列网格可保留，不再使用 */
.dread-inputs-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-top: 10px;
}

.dread-input-item {
    display: flex;
    align-items: center;
    gap: 5px;
}

.dread-label {
    font-weight: bold;
    margin: 0;
    min-width: 20px;
}

.dread-slider {
    width: 100%;
}

.dread-value {
    min-width: 20px;
    font-weight: bold;
    text-align: center;
}

.dread-label-text {
    font-size: 0.8rem;
    color: #6c757d;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.evaluation-section {
    background-color: #f8f9fa;
    border-radius: 5px;
    padding: 15px;
    margin-top: 15px;
}

/* 攻击树模态框样式 */
.attack-tree-wrapper {
  width: 100%;
  height: 90vh;
  overflow: hidden;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
}
.attack-tree-scroll {
  width: 100%;
  height: 100%;
  overflow: auto;
  cursor: grab;
}
.attack-tree-content {
  transform-origin: top left;
  transition: transform 0.1s;
  background: #fff;
  padding: 20px;
  width: max-content;
  min-width: 100%;
  min-height: 100%;
}
/* 遮蔽 modal-body 溢出 */
.attack-tree-modal .modal-body {
  padding: 0;
  overflow: hidden;
}

/* 表格容器样式（另一处定义统一保留） */
.table-container {
    max-height: 300px;
    overflow-y: auto;
    position: relative;
    border: 1px solid #dee2e6;
    border-radius: 0.25rem;
}

/* 固定表头样式 */
.table-container ::v-deep .table thead th {
    position: sticky;
    top: 0;
    background-color: #f8f9fa;
    z-index: 10;
    border-top: none;
    box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.1);
}

/* 防止表格按钮换行 */
.table-container ::v-deep .btn-sm {
  white-space: nowrap;
  min-width: 100px;
}

/* 警告抖动动画 */
@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20%, 60% { transform: translateX(-5px); }
  40%, 80% { transform: translateX(5px); }
}

.warning-shake {
  border-color: #dc3545 !important;
  box-shadow: 0 0 0 0.2rem rgba(220, 53, 69, 0.25) !important;
  animation: shake 0.5s ease-in-out;
}
</style>

<script>
import Chart from 'chart.js/auto';
import axios from 'axios';
import mermaid from 'mermaid/dist/mermaid.esm.min.mjs';

// 根据分数映射风险等级与展示文本/颜色
function mapRiskByScore(score) {
  const s = Number(score || 0);
  if (s >= 41 && s <= 50) {
    return { level: '严重风险', range: '41–50', text: '严重风险（41–50）', variant: 'danger' };
  } else if (s >= 31 && s <= 40) {
    return { level: '高风险', range: '31–40', text: '高风险（31–40）', variant: 'warning' };
  } else if (s >= 21 && s <= 30) {
    return { level: '中风险', range: '21–30', text: '中风险（21–30）', variant: 'info' };
  } else { // 0–20
    return { level: '低风险', range: '0–20',  text: '低风险（0–20）',  variant: 'secondary' };
  }
}

// 计算 DREAD 总分
function calcTotalDread(dread) {
    if (!dread || typeof dread !== 'object') return 0;
    const A = Number(dread.A || dread.a || 0);
    const D = Number(dread.D || dread.d || 0);
    const D2 = Number(dread.D2 || dread.d2 || 0);
    const E = Number(dread.E || dread.e || 0);
    const R = Number(dread.R || dread.r || 0);
    return A + D + D2 + E + R;
}

export default {
    name: 'ShowDREAD',
    components: {},
    data() {
        return {
            nodes: [],
            selectedNode: null,
            selectedThreat: null,
            selectedThreatType: null,
            evaluationText: '',
            threatLabels: {
                'S': 'Spoofing (伪装)',
                'T': 'Tampering (篡改)',
                'R': 'Repudiation (抵赖)',
                'I': 'Information Disclosure (信息泄露)',
                'D': 'Denial of Service (拒绝服务)',
                'E': 'Elevation of Privilege (权限提升)'
            },
            dreadLabels: {
                'D': '潜在破坏程度',
                'R': '可再现性',
                'E': '可利用性',
                'A': '受影响用户范围',
                'D2': '可发现性'
            },
            editedDread: {
                'D': 0,
                'R': 0,
                'E': 0,
                'A': 0,
                'D2': 0
            },
            threatFields: [
              { key: 'nodeName',    label: '节点名称',           thStyle: { width: '160px', textAlign: 'center' }, tdClass: 'text-center' },
              { key: 'threatType',  label: '威胁类型',           thStyle: { width: '120px', textAlign: 'center' }, tdClass: 'text-center' },
              { key: 'description', label: '描述',               thStyle: { width: '320px', textAlign: 'center' } }, // 描述一般不居中
              { key: 'totalScore',  label: 'DREAD总分',          thStyle: { width: '110px', textAlign: 'center' }, tdClass: 'text-center' },
              { key: 'riskLevel',   label: '风险等级',           thStyle: { width: '140px', textAlign: 'center' }, tdClass: 'text-center' },
              { key: 'actions',     label: '威胁建模评级',       thStyle: { width: '140px', textAlign: 'center' }, tdClass: 'text-center' }
            ],

            chartInstance: null,
            loading: false,
            error: null,
            // 攻击树相关数据
            showModal: false,
            attackTreeMd: '',
            scale: 1,
            isDragging: false,
            dragStart: { x: 0, y: 0 },
            scrollStart: { left: 0, top: 0 },
            showEvaluationWarning: false,
            originalDreadScores: null,
            // 保存用户修改过的评分
            modifiedDreadScores: {}
        };
    },
    computed: {
        threatItems() {
            const items = [];
            this.nodes.forEach(node => {
                if (node.stride) {
                    Object.keys(node.stride).forEach(threatType => {
                        const threat = node.stride[threatType];
                        const __total = calcTotalDread(threat && threat.dread);
                        const __risk  = mapRiskByScore(__total);
                        items.push({
                            // 新增：总分与风险显示字段
                            totalScore: __total,
                            riskLevel:  __risk.level,
                            riskText:   __risk.text,
                            riskRange:  __risk.range,
                            riskVariant:__risk.variant,

                            // 原有字段
                            nodeName: node.name,
                            threatType: this.threatLabels[threatType],
                            description: threat.description,
                            node: node,
                            threat: threat,
                            type: threatType,
                        });
                    });
                }
            });
            return items;
        },
        isDreadModified() {
            if (!this.selectedThreat || !this.originalDreadScores) return false;
            for (const key in this.editedDread) {
                if (this.editedDread[key] !== this.originalDreadScores[key]) {
                    return true;
                }
            }
            return false;
        },
    },
    watch: {
        // 同步评价到 nodes.stride[*].commit
        evaluationText(newVal) {
            if (this.selectedNode && this.selectedThreatType) {
                const nodeIndex = this.nodes.findIndex(node => node.name === this.selectedNode.name);
                if (nodeIndex !== -1 && this.nodes[nodeIndex].stride && this.nodes[nodeIndex].stride[this.selectedThreatType]) {
                    this.nodes[nodeIndex].stride[this.selectedThreatType].commit = newVal || null;
                }
            }
        },
        isDreadModified: {
            handler(newVal) {
                // 当DREAD评分修改状态改变时，重置警告状态
                if (!newVal) {
                    this.showEvaluationWarning = false;
                }
            },
            immediate: true
        }
    },
    mounted() {
        // 页面加载时获取数据
        this.fetchDreadData();
        // 初始化 Mermaid
        mermaid.initialize({
            startOnLoad: false,
            theme: 'default',
            securityLevel: 'loose',
        });
    },
    methods: {
        async fetchDreadData() {
            this.loading = true;
            this.error = null;

            try {
                const hashId = localStorage.getItem('dfdHashId');
                if (!hashId) {
                    this.error = '未找到 DFD Hash ID，请先提交图数据。';
                    return;
                }

                const useLocalData = false; // 改为 true 可用本地演示数据
                if (useLocalData) {
                    const localData = await import('@/assets/dread_demo.json');
                    this.nodes = localData.nodes || [];
                } else {
                    // 原有 API 调用逻辑 + 轮询
                    const urlParams = new URLSearchParams(window.location.search);
                    const filePath = hashId;

                    let apiUrl;
                    let attacktreeurl;
                    if (filePath) {
                        const hashId = localStorage.getItem('dfdHashId');
                        apiUrl = `/DREAD?id=${encodeURIComponent(filePath)}`;
                        attacktreeurl = `/get-attack-tree/${encodeURIComponent(filePath)}`;
                    } else {
                        apiUrl = '/DREAD';
                        attacktreeurl = '/get-attack-tree';
                    }

                    await this.pollForData(apiUrl, 50, 15000);
                    if (this.nodes != []){
                        const res = await axios.get(attacktreeurl);
                        this.attackTreeMd = res.data
                        .trim()
                        .replace(/^```mermaid\s*/, '')
                        .replace(/\s*```$/, '');
                        localStorage.setItem('attackTreeMd', res.data);
                    }
                }

                // 为每个 stride[*] 初始化 commit 字段
                this.nodes = this.nodes.map(node => {
                    if (node.stride) {
                        Object.keys(node.stride).forEach(threatType => {
                            node.stride[threatType].commit = node.stride[threatType].commit ?? null;
                        });
                    }
                    return node;
                });

                if (this.nodes.length === 0) {
                    this.error = '未找到任何威胁数据';
                } else {
                    // 自动选择第一项
                    this.$nextTick(() => {
                        if (this.threatItems.length > 0) {
                            this.showThreatDetails(this.threatItems[0]);
                        }
                    });
                }
            } catch (error) {
                console.error('获取数据时出错:', error);
                this.error = `获取数据失败: ${error.message || '未知错误'}`;
            } finally {
                this.loading = false;
            }
        },

        async showAttackTree() {
            this.showModal = true;
            this.scale = 1;

            // 拉取 Mermaid 语法
            try {
                const filePath = localStorage.getItem('dfdHashId');
                let apiUrl;
                if (filePath) {
                    apiUrl = `/get-attack-tree/${encodeURIComponent(filePath)}`;
                } else {
                    apiUrl = '/get-attack-tree/';
                }
                
                if (localStorage.getItem('attackTreeMd')) {
                    this.attackTreeMd = localStorage.getItem('attackTreeMd');
                } else {
                    const res = await axios.get(apiUrl);
                    this.attackTreeMd = res.data
                    .trim()
                    .replace(/^```mermaid\s*/, '')
                    .replace(/\s*```$/, '');
                    localStorage.setItem('attackTreeMd', res.data);
                }
            } catch (err) {
                console.error('获取攻击树失败:', err);
                this.attackTreeMd = 'graph TD\n  error[加载失败，请检查后端接口]';
            }

            // 等 DOM 就绪后渲染
            this.$nextTick(() => {
                const container = this.$refs.contentRef;
                const scroll = this.$refs.scrollContainer;
                if (!container) return;

                container.innerHTML = `<div class="mermaid">${this.attackTreeMd}</div>`;

                try {
                    // 初始化Mermaid并配置样式：字体加粗放大、连线加粗
                    mermaid.initialize({
                        startOnLoad: false,
                        theme: 'default',
                        securityLevel: 'loose',
                        themeCSS: `
                            .nodeLabel {
                                font-weight: bold !important;
                                font-size: 32px !important;
                            }
                            .edgePath path {
                                stroke-width: 4px !important;
                                stroke: #333 !important;
                            }
                            .edgePath defs marker {
                                stroke-width: 6px !important;
                                stroke: #333 !important;
                            }
                            .flowchart-link {
                                stroke-width: 5px !important;
                                stroke: #333 !important;
                            }
                        `
                    });
                    mermaid.init(); 
                } catch (e) {
                    console.error('Mermaid init 出错:', e);
                    container.innerHTML = `<pre style="color:red">${e.message||e}</pre>`;
                }

                container.style.transform = 'scale(1)';
                if (scroll) {
                    scroll.scrollLeft = 0;
                    scroll.scrollTop = 0;
                }
            });
        },

        zoom(event) {
            const delta = event.deltaY < 0 ? 0.1 : -0.1;
            this.scale = Math.min(Math.max(this.scale + delta, 0.5), 10);
            const container = this.$refs.contentRef;
            if (container) {
                container.style.transform = `scale(${this.scale})`;
            }
        },

        startDrag(event) {
            this.isDragging = true;
            this.dragStart = { x: event.clientX, y: event.clientY };
            const scroll = this.$refs.scrollContainer;
            this.scrollStart = { left: scroll.scrollLeft, top: scroll.scrollTop };
            scroll.style.cursor = 'grabbing';
        },

        onDrag(event) {
            if (!this.isDragging) return;
            const dx = event.clientX - this.dragStart.x;
            const dy = event.clientY - this.dragStart.y;
            const scroll = this.$refs.scrollContainer;
            scroll.scrollLeft = this.scrollStart.left - dx;
            scroll.scrollTop = this.scrollStart.top - dy;
        },

        endDrag() {
            this.isDragging = false;
            const scroll = this.$refs.scrollContainer;
            if (scroll) scroll.style.cursor = 'grab';
        },

        // 轮询获取数据
        async pollForData(apiUrl, maxAttempts = 30, interval = 1000) {
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    const response = await fetch(apiUrl);

                    if (response.ok){
                        const data = await response.json();
                        if (data.nodes && data.nodes.length > 0) {
                            this.nodes = data.nodes || [];
                            return; // 成功获取数据，退出轮询
                        }
                    } else if (response.status === 202) {
                        // 202 Accepted - 数据仍在处理中
                        // 继续轮询
                    } else {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                } catch (error) {
                    if (attempt === maxAttempts) {
                        throw error;
                    }
                }
                await new Promise(resolve => setTimeout(resolve, interval));
            }
            throw new Error('获取数据超时，请稍后重试');
        },

        showThreatDetails(item) {
            // 有未保存修改但未填写评价时提示
            if (this.isDreadModified && (!this.evaluationText || this.evaluationText.trim() === '')) {
                this.showEvaluationWarning = true;
                setTimeout(() => { this.showEvaluationWarning = false; }, 1000);
                return;
            }
            
            this.selectedNode = item.node;
            this.selectedThreat = item.threat;
            this.selectedThreatType = item.type;

            // 评价文本
            this.evaluationText = (item.threat.commit !== undefined && item.threat.commit !== null) ? item.threat.commit : '';

            // 唯一标识
            const threatId = `${this.selectedNode.name}-${this.selectedThreatType}`;
            
            // 初始化编辑评分
            const originalDread = item.threat.dread;
            this.originalDreadScores = { ...originalDread };
            
            // 如果之前保存过修改，优先使用
            if (this.modifiedDreadScores[threatId]) {
                this.editedDread = { ...this.modifiedDreadScores[threatId] };
            } else {
                this.editedDread = { ...originalDread };
            }

            // 渲染雷达图
            setTimeout(() => {
                this.renderRadarChart();
            }, 0);
        },

        renderRadarChart() {
            this.$nextTick(() => {
                const ctx = document.getElementById('dreadRadarChart');
                if (!ctx) {
                    console.error('无法找到 dreadRadarChart canvas 元素');
                    return;
                }

                if (this.chartInstance) {
                    this.chartInstance.destroy();
                }

                const dread = this.editedDread;
                const originalDread = this.originalDreadScores;
                
                const data = {
                    labels: ['D潜在破坏程度', 'R可再现性', 'E可利用性', 'A受影响用户范围', 'D2可发现性'],
                    datasets: [
                        {
                            label: '当前 DREAD 评分',
                            data: [dread.D, dread.R, dread.E, dread.A, dread.D2],
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            borderColor: 'rgb(54, 162, 235)',
                            pointBackgroundColor: 'rgb(54, 162, 235)',
                            pointBorderColor: '#fff',
                            pointHoverBackgroundColor: '#fff',
                            pointHoverBorderColor: 'rgb(54, 162, 235)'
                        },
                        {
                            label: '原始 DREAD 评分',
                            data: [originalDread.D, originalDread.R, originalDread.E, originalDread.A, originalDread.D2],
                            backgroundColor: 'rgba(200, 200, 200, 0.2)',
                            borderColor: 'rgb(200, 200, 200)',
                            pointBackgroundColor: 'rgb(200, 200, 200)',
                            pointBorderColor: '#fff',
                            pointHoverBackgroundColor: '#fff',
                            pointHoverBorderColor: 'rgb(200, 200, 200)',
                            pointRadius: 0
                        },
                    ]
                };

                try {
                    this.chartInstance = new Chart(ctx, {
                        type: 'radar',
                        data: data,
                        options: {
                            plugins: {
                                legend: {
                                    display: true,
                                    position: 'top'
                                }
                            },
                            scales: {
                                r: {
                                    min: 0,
                                    max: 10,
                                    ticks: {
                                        stepSize: 2,
                                        font:{ weight: 'bold' }
                                    },
                                    pointLabels: {
                                        font: { weight: 'bold' }
                                    }
                                }
                            },
                            elements: {
                                line: { borderWidth: 3 }
                            }
                        }
                    });
                } catch (error) {
                    console.error('渲染雷达图时出错:', error);
                }
            });
        },

        updateChartOnEdit() {
            // 当用户编辑评分时更新图表
            if (this.chartInstance) {
                try {
                    this.chartInstance.data.datasets[0].data = [
                        this.editedDread.D,
                        this.editedDread.R,
                        this.editedDread.E,
                        this.editedDread.A,
                        this.editedDread.D2
                    ];
                    this.chartInstance.update();
                } catch (error) {
                    console.error('更新雷达图时出错:', error);
                }
            }
            
            // 保存修改的DREAD评分
            if (this.selectedNode && this.selectedThreatType) {
                const threatId = `${this.selectedNode.name}-${this.selectedThreatType}`;
                let isModified = false;
                for (const key in this.editedDread) {
                    if (this.editedDread[key] !== this.originalDreadScores[key]) {
                        isModified = true;
                        break;
                    }
                }
                
                if (isModified) {
                    this.modifiedDreadScores[threatId] = { ...this.editedDread };
                } else {
                    delete this.modifiedDreadScores[threatId];
                }
            }
        },

        submitEvaluation(evt) {
            evt.preventDefault();

            // 检查是否有评分被修改但未填写评价
            if (this.isDreadModified && (!this.evaluationText || this.evaluationText.trim() === '')) {
                this.showEvaluationWarning = true;
                setTimeout(() => { this.showEvaluationWarning = false; }, 1000);
                return;
            }

            // 将修改后的DREAD评分和评价文本更新到nodes数据中
            if (this.selectedNode && this.selectedThreatType) {
                const nodeIndex = this.nodes.findIndex(node => node.name === this.selectedNode.name);
                if (nodeIndex !== -1 && this.nodes[nodeIndex].stride && this.nodes[nodeIndex].stride[this.selectedThreatType]) {
                    // 更新DREAD评分
                    this.nodes[nodeIndex].stride[this.selectedThreatType].dread = { ...this.editedDread };
                    // 更新commit文本
                    this.nodes[nodeIndex].stride[this.selectedThreatType].commit = this.evaluationText || null;
                    
                    // 清除保存的修改数据
                    const threatId = `${this.selectedNode.name}-${this.selectedThreatType}`;
                    delete this.modifiedDreadScores[threatId];
                }
            }

            // 将nodes数据存储到localStorage中
            localStorage.setItem('dreadNodesData', JSON.stringify(this.nodes));

            const data = {
                id: localStorage.getItem('dfdHashId'),
                nodes: this.nodes
            };
            // 发送HTTP请求
            fetch('/commits', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
                .then(response => {
                    if (response.ok) {
                        this.$router.push('/mitigations');
                    } else {
                        alert('提交失败，请重试。');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('提交出错，请重试。');
                });
        }
    },
    beforeDestroy() {
        if (this.chartInstance) {
            this.chartInstance.destroy();
        }
    }
};
</script>
