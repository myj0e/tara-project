<template>
  <div class="td-report">
    <b-row class="no-print td-report-options sticky">
      <b-col>
        <b-form class="">
          <b-form-row>
            <b-col>
              <b-form-group label-cols="auto" id="model-group">
                <b-form-checkbox id="show_models" v-model="display.diagrams">
                  {{ $t('report.options.showModelDiagrams') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <b-col>
              <b-form-group label-cols="auto" id="mitigated-group">
                <b-form-checkbox id="show_mitigated" v-model="display.mitigated">
                  {{ $t('report.options.showMitigatedThreats') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <b-col>
              <b-form-group label-cols="auto" id="outofscope-group">
                <b-form-checkbox id="show_outofscope" v-model="display.outOfScope">
                  {{ $t('report.options.showOutOfScope') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <b-col>
              <b-form-group label-cols="auto" id="attacktree-group">
                <b-form-checkbox id="show_attacktree" v-model="display.attacktree">
                  {{ $t('report.options.attacktree') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>
          </b-form-row>

          <b-form-row>
            <b-col>
              <b-form-group label-cols="auto" id="dread-group">
                <b-form-checkbox id="show_dread" v-model="display.dread">
                  {{ $t('report.options.dread') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <b-col>
              <b-form-group label-cols="auto" id="mitigations-group">
                <b-form-checkbox id="show_mitigations" v-model="display.mitigations">
                  {{ $t('report.options.mitigations') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <b-col>
              <b-form-group label-cols="auto" id="empty-group">
                <b-form-checkbox id="show_empty" v-model="display.empty">
                  {{ $t('report.options.showEmpty') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>

            <!--
            <b-col>
              <b-form-group label-cols="auto" id="branding-group">
                <b-form-checkbox id="show_branding" v-model="display.branding">
                  {{ $t('report.options.showBranding') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>
            -->

            <b-col>
              <b-form-group label-cols="auto" id="properties-group">
                <b-form-checkbox id="show_attributes" v-model="display.properties">
                  {{ $t('report.options.showProperties') }}
                </b-form-checkbox>
              </b-form-group>
            </b-col>
          </b-form-row>
        </b-form>
      </b-col>

      <b-col class="text-right right">
        <b-btn-group>
          <td-form-button
            id="td-print-pdf-btn"
            :onBtnClick="printPdf"
            v-if="isElectron"
            icon="file-pdf"
            :text="$t('forms.exportPdf')"
          />
          <td-form-button
            id="td-print-btn"
            :onBtnClick="print"
            icon="print"
            :text="$t('forms.print')"
          />
          <td-form-button
            id="td-return-btn"
            :isPrimary="true"
            :onBtnClick="onCloseClick"
            icon="times"
            :text="$t('forms.close')"
          />
        </b-btn-group>
      </b-col>
    </b-row>

    <div v-if="!!model" class="td-report-container">
      <div class="td-report-section">
        <td-coversheet :branding="display.branding" />
        <td-print-coversheet
          :title="model.summary.title"
          :owner="model.summary.owner"
          :reviewer="model.detail.reviewer"
          :contributors="contributors"
          :branding="display.branding"
        />
      </div>

      <div class="td-report-section">
        <td-executive-summary
          :summary="model.summary.description"
          :threats="allThreats"
        />
        <td-print-executive-summary
          :summary="model.summary.description"
          :threats="allThreats"
        />
      </div>

      <td-diagram-detail
        v-for="(diagram, idx) in diagrams"
        :key="idx"
        :diagram="diagram"
        :showProperties="display.properties"
        :showMitigated="display.mitigated"
        :showOutOfScope="display.outOfScope"
        :showDiagram="display.diagrams"
        :showEmpty="display.empty"
      />

      <!-- 攻击树 -->
      <div v-if="display.attacktree && attackTreeHtml" class="td-report-section">
        <h2>攻击树</h2>
        <div class="attack-tree-content" v-html="attackTreeHtml"></div>
      </div>

      <!-- DREAD 雷达图 -->
      <div v-if="display.dread && dreadCharts.length > 0" class="td-report-section">
        <h2>DREAD 风险评估</h2>
        <div class="dread-charts-container">
          <b-row>
            <b-col
              v-for="(chart, index) in dreadCharts"
              :key="index"
              md="6"
              class="dread-chart-col"
            >
              <div class="dread-chart-item">
                <h5 class="dread-chart-title">{{ chart.title }}</h5>
                <div :id="'dread-chart-' + index" class="dread-chart-canvas-container">
                  <canvas :id="'dread-canvas-' + index" width="400" height="400"></canvas>
                </div>
              </div>
            </b-col>
          </b-row>
        </div>
      </div>

      <!-- DREAD 评级概览（无横向滚动、打印友好） -->
      <div v-if="display.dread && dreadItems.length > 0" class="td-report-section">
        <h3 class="mt-3">DREAD 评级概览</h3>
        <b-table
          class="dread-table"
          :items="dreadItems"
          :fields="dreadFields"
          striped
          hover
          small
          head-variant="light"
          :sort-by="'totalScore'"
          :sort-desc="true"
        >
          <template #cell(riskLevel)="row">
            <b-badge :variant="row.item.riskVariant" class="risk-badge">
              {{ row.item.riskText }}
            </b-badge>
          </template>
        </b-table>

        <div class="text-muted mt-2 rule-tip">
          * DREAD 总分 = D + R + E + A + D2；严重风险（41–50），高风险（31–40），中风险（21–30），低风险（0–20）。
        </div>
      </div>

      <!-- 缓解措施 -->
      <div v-if="mitigationsHtml" class="td-report-section">
        <h2>缓解措施</h2>
        <div class="mitigations-content" v-html="mitigationsHtml"></div>
      </div>
    </div>
  </div>
</template>

<style lang="scss">
.td-report-options label { padding-top: 4px; font-size: 12px !important; }
.card-header { font-size: 16px; }
</style>

<style lang="scss" scoped>
.td-branding { padding-left: 50px; }
.td-report { font-size: 12px; }
.td-report-section { margin-top: 15px; }
.td-report-container { margin-top: 5px; }
.sticky { position: sticky; top: 55px; margin-top: -5px; background-color: $white; padding-top: 15px; z-index: 100; }
.right { right: 0; }

/* 攻击树样式 */
.attack-tree-content {
  padding: 20px; background-color: #f8f9fa; border-radius: 5px; text-align: center;
  ::v-deep .mermaid { display: inline-block; text-align: center; width: 100%; }
  ::v-deep svg { max-width: 100%; height: auto; }
}

/* 缓解措施 Markdown 表格样式 */
.mitigations-content {
  padding: 20px; background-color: #f8f9fa; border-radius: 5px; font-size: 0.9rem;
  ::v-deep table { border-collapse: collapse; width: auto; margin: 1rem auto; display: block; overflow-x: auto; max-width: 100%; }
  ::v-deep table th, ::v-deep table td { border: 1px solid #ddd; padding: 12px 15px; text-align: left; }
  ::v-deep table th { background-color: #e9ecef; font-weight: bold; }
  ::v-deep table tbody tr:nth-child(odd) td { background-color: #ffffff; }
  ::v-deep table tbody tr:nth-child(even) td { background-color: #ffe5cc; }
  ::v-deep table tr:hover td { background-color: #e2e6ea; }
}

/* DREAD 图表区块 */
.dread-charts-container { margin-top: 20px; }
.dread-chart-col { margin-bottom: 30px; }
.dread-chart-item { background-color: #f8f9fa; border-radius: 5px; padding: 15px; text-align: center; }
.dread-chart-title { margin-bottom: 15px; font-weight: bold; color: #495057; }
.dread-chart-canvas-container { position: relative; margin: 0 auto; width: 300px; height: 300px; }

/* --- DREAD 表格（无滚动、强制换行、打印优化） --- */
.dread-table {
  font-size: 13px;

  /* 固定布局，列宽按百分比分配，防止超宽撑开 */
  ::v-deep table { table-layout: fixed; width: 100%; }

  /* 表头尽量不换行，数据允许换行 */
  ::v-deep thead th { white-space: nowrap; vertical-align: middle; }
  ::v-deep tbody td {
    white-space: normal;          /* 允许换行 */
    word-break: break-word;       /* 中英文可断行 */
    overflow-wrap: anywhere;      /* 极长 token/URL 也断 */
    line-height: 1.35;
    vertical-align: middle;
  }

  /* 列宽百分比：1=节点 2=威胁类型 3=描述 4=分数 5=等级 */
  ::v-deep thead th:nth-child(1), ::v-deep tbody td:nth-child(1) { width: 18%; }
  ::v-deep thead th:nth-child(2), ::v-deep tbody td:nth-child(2) { width: 16%; }
  ::v-deep thead th:nth-child(3), ::v-deep tbody td:nth-child(3) { width: 46%; } /* 描述最多 */
  ::v-deep thead th:nth-child(4), ::v-deep tbody td:nth-child(4) { width: 10%; text-align: center; }
  ::v-deep thead th:nth-child(5), ::v-deep tbody td:nth-child(5) { width: 10%; text-align: center; }

  .risk-badge { white-space: nowrap; display: inline-block; padding: 0.25rem 0.5rem; font-size: 12px; }
}

/* 打印优化：关闭 sticky、避免行被分页切断、统一页边距 */
@media print {
  .dread-table { font-size: 12px; }

  /* 关闭 sticky header 定位，防止重叠 */
  ::v-deep .b-table-sticky-header,
  ::v-deep thead.b-table-sticky-header > tr > th { position: static !important; }

  /* 避免行在分页处被劈开 */
  ::v-deep tbody tr, ::v-deep tbody td { break-inside: avoid; page-break-inside: avoid; }

  @page { margin: 12mm; }
}

/* 可选：屏幕上对描述列做 3 行截断，打印时会展开
@media screen {
  .dread-table ::v-deep tbody td:nth-child(3) {
    display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
  }
}
*/
</style>

<script>
import { mapState, mapGetters } from 'vuex';
import isElectron from 'is-electron';
import MarkdownIt from 'markdown-it';
import mermaid from 'mermaid/dist/mermaid.esm.min.mjs';
import Chart from 'chart.js/auto';

import { getProviderType } from '@/service/provider/providers.js';
import TdCoversheet from '@/components/report/Coversheet.vue';
import TdDiagramDetail from '@/components/report/DiagramDetail.vue';
import TdExecutiveSummary from '@/components/report/ExecutiveSummary.vue';
import TdFormButton from '@/components/FormButton.vue';
import TdPrintCoversheet from '@/components/printed-report/Coversheet.vue';
import TdPrintExecutiveSummary from '@/components/printed-report/ExecutiveSummary.vue';
import threatService from '@/service/threats/index.js';

export default {
  name: 'ReportModel',
  components: {
    TdCoversheet,
    TdDiagramDetail,
    TdExecutiveSummary,
    TdFormButton,
    TdPrintCoversheet,
    TdPrintExecutiveSummary
  },
  data() {
    return {
      display: {
        diagrams: true,
        mitigated: true,
        outOfScope: true,
        empty: false,
        properties: false,
        branding: false,
        attacktree: true,
        mitigations: true,
        dread: true
      },
      isElectron: isElectron(),
      mitigationsHtml: '',
      attackTreeHtml: '',
      dreadCharts: [],
      chartInstances: [],     // 收集 Chart 实例，统一销毁
      dreadRawNodes: [],
      threatLabels: {
        'S': 'Spoofing (伪装)',
        'T': 'Tampering (篡改)',
        'R': 'Repudiation (抵赖)',
        'I': 'Information Disclosure (信息泄露)',
        'D': 'Denial of Service (拒绝服务)',
        'E': 'Elevation of Privilege (权限提升)'
      },
      dreadFields: [
        { key: 'nodeName',   label: '节点',       thStyle: { width: '180px', textAlign: 'center' }, tdClass: 'text-center' },
        { key: 'threatType', label: '威胁类型',   thStyle: { width: '150px', textAlign: 'center' }, tdClass: 'text-center' },
        { key: 'description',label: '描述',       thStyle: { width: '360px' } },
        { key: 'totalScore', label: 'DREAD 总分', thStyle: { width: '120px', textAlign: 'center' }, tdClass: 'text-center' },
        { key: 'riskLevel',  label: '风险等级',   thStyle: { width: '130px', textAlign: 'center' }, tdClass: 'text-center' }
      ]
    };
  },
  computed: {
    ...mapState({
      model: (state) => state.threatmodel.data,
      providerType: (state) => getProviderType(state.provider.selected),
      allThreats: function (state) {
        return threatService.filter(state.threatmodel.data.detail.diagrams, {
          showMitigated: true,
          showOutOfScope: true,
          showProperties: false,
          showEmpty: true
        });
      }
    }),
    ...mapGetters({ contributors: 'contributors' }),
    diagrams() {
      const sortedDiagrams = this.model.detail.diagrams.slice().sort((a, b) => {
        if (a.title < b.title) return -1;
        if (a.title > b.title) return 1;
        return 0;
      });
      return sortedDiagrams;
    },
    // DREAD 表格数据源
    dreadItems() {
      const items = [];
      (this.dreadRawNodes || []).forEach(node => {
        if (!node || !node.stride) return;
        Object.keys(node.stride).forEach(type => {
          const threat = node.stride[type];
          if (!threat || !threat.dread || threat.description === 'None') return;

          const total = this.calcTotalDread(threat.dread);
          const risk = this.mapRiskByScore(total);

          items.push({
            nodeName:    node.name,
            threatType:  this.threatLabels[type] || type,
            description: threat.description,
            totalScore:  total,
            riskLevel:   risk.level,
            riskText:    risk.text,
            riskVariant: risk.variant
          });
        });
      });
      return items;
    }
  },
  mounted() {
    this.renderMitigations();
    this.renderAttackTree();
    this.renderDreadCharts();
  },
  methods: {
    onCloseClick() {
      this.$router.push({ name: `${this.providerType}ThreatModel`, params: this.$route.params });
    },
    print() { window.print(); },
    printPdf() {
      if (isElectron()) window.electronAPI.modelPrint('PDF');
    },

    /* 缓解措施 */
    renderMitigations() {
      try {
        const mitigationsMd = JSON.parse(localStorage.getItem('mitigationsMd') || '""');
        if (mitigationsMd) {
          const md = new MarkdownIt({ breaks: true, html: true });
          this.mitigationsHtml = md.render(mitigationsMd);
        }
      } catch (error) {
        console.error('渲染缓解措施时出错:', error);
      }
    },

    /* 攻击树 */
    renderAttackTree() {
      try {
        const attackTreeMd = localStorage.getItem('attackTreeMd');
        if (attackTreeMd) {
          this.attackTreeHtml = `<div class="mermaid">${attackTreeMd}</div>`;
          this.$nextTick(() => {
            mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'loose' });
            mermaid.init();
          });
        }
      } catch (error) {
        console.error('渲染攻击树时出错:', error);
      }
    },

    /* DREAD 工具函数 */
    mapRiskByScore(score) {
      const s = Number(score || 0);
      if (s >= 41 && s <= 50) {
        return { level: '严重风险', range: '41–50', text: '严重风险（41–50）', variant: 'danger' };
      } else if (s >= 31 && s <= 40) {
        return { level: '高风险', range: '31–40', text: '高风险（31–40）', variant: 'warning' };
      } else if (s >= 21 && s <= 30) {
        return { level: '中风险', range: '21–30', text: '中风险（21–30）', variant: 'info' };
      } else {
        return { level: '低风险', range: '0–20', text: '低风险（0–20）', variant: 'secondary' };
      }
    },
    calcTotalDread(dread) {
      if (!dread || typeof dread !== 'object') return 0;
      const A  = Number(dread.A  || dread.a  || 0);
      const D  = Number(dread.D  || dread.d  || 0);
      const D2 = Number(dread.D2 || dread.d2 || 0);
      const E  = Number(dread.E  || dread.e  || 0);
      const R  = Number(dread.R  || dread.r  || 0);
      return A + D + D2 + E + R;
    },

    /* Chart 实例管理 */
    destroyDreadCharts() {
      try {
        (this.chartInstances || []).forEach(c => { if (c && typeof c.destroy === 'function') c.destroy(); });
      } catch (e) {
        console.warn('销毁 Chart 实例异常：', e);
      } finally {
        this.chartInstances = [];
      }
    },

    /* 渲染 DREAD 雷达图 + 准备表格数据 */
    renderDreadCharts() {
      try {
        // 先销毁上一次的图表，避免叠加
        this.destroyDreadCharts();

        const dreadNodesDataStr = localStorage.getItem('dreadNodesData') || '[]';
        const dreadNodesData = JSON.parse(dreadNodesDataStr);

        if (!Array.isArray(dreadNodesData) || dreadNodesData.length === 0) {
          this.dreadRawNodes = [];
          this.dreadCharts = [];
          return;
        }

        // 用于表格
        this.dreadRawNodes = dreadNodesData;
        // 用于图表
        this.dreadCharts = [];

        dreadNodesData.forEach(node => {
          if (!node || !node.stride) return;
          Object.keys(node.stride).forEach(threatType => {
            const threat = node.stride[threatType];
            if (!threat || !threat.dread || threat.description === 'None') return;

            const dread = threat.dread;
            const title = `${node.name} - ${this.threatLabels[threatType] || threatType}`;
            this.dreadCharts.push({
              title,
              data: {
                labels: ['D潜在破坏程度', 'R可再现性', 'E可利用性', 'A受影响用户', 'D可发现性'],
                datasets: [{
                  label: 'DREAD 评分',
                  data: [dread.D, dread.R, dread.E, dread.A, dread.D2],
                  backgroundColor: 'rgba(54, 162, 235, 0.2)',
                  borderColor: 'rgb(54, 162, 235)',
                  pointBackgroundColor: 'rgb(54, 162, 235)',
                  pointBorderColor: '#fff',
                  pointHoverBackgroundColor: '#fff',
                  pointHoverBorderColor: 'rgb(54, 162, 235)'
                }]
              }
            });
          });
        });

        this.$nextTick(() => {
          this.dreadCharts.forEach((chart, index) => {
            const canvasId = 'dread-canvas-' + index;
            const ctx = document.getElementById(canvasId);
            if (!ctx) {
              console.error(`未找到 canvas 元素: ${canvasId}`);
              return;
            }
            try {
              const inst = new Chart(ctx, {
                type: 'radar',
                data: chart.data,
                options: {
                  plugins: { legend: { display: false } },
                  scales: {
                    r: {
                      min: 0, max: 10,
                      ticks: { stepSize: 2, font: { weight: 'bold' } },
                      pointLabels: { font: { weight: 'bold' } }
                    }
                  },
                  elements: { line: { borderWidth: 3 } }
                }
              });
              this.chartInstances.push(inst);
            } catch (chartError) {
              console.error(`创建图表 ${index} 时出错:`, chartError);
            }
          });
        });
      } catch (error) {
        console.error('渲染DREAD图表时出错:', error);
      }
    }
  },
  watch: {
    'display.attacktree': function (val) {
      if (val) this.renderAttackTree();
      else this.attackTreeHtml = '';
    },
    'display.dread': function (val) {
      if (val) this.renderDreadCharts();
      else {
        this.destroyDreadCharts();
        this.dreadCharts = [];
        this.dreadRawNodes = [];
      }
    },
    'display.mitigations': function (val) {
      if (val) this.renderMitigations();
      else this.mitigationsHtml = '';
    }
  }
};
</script>
