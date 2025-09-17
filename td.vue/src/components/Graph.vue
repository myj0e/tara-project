<template>
  <div>
    <b-row>
      <b-col md="2">
        <div ref="stencil_container"></div>
      </b-col>

      <b-col md="10">
        <b-row>
          <b-col>
            <!-- 优先显示模型 summary 的标题，退回 diagram.title -->
            <h3 class="td-graph-title">{{ modelSummary.title || diagram.title }}</h3>
          </b-col>
          <b-col align="right">
            <td-graph-buttons :graph="graph" @saved="saved" @closed="closed" />
          </b-col>
        </b-row>

        <b-row>
          <b-col style="display: flex; width: 100vw;">
            <div
              id="graph-container"
              ref="graph_container"
              style="height: 65vh; width: 100%; flex: 1;"
            />
          </b-col>
        </b-row>
      </b-col>
    </b-row>

    <td-graph-meta @threatSelected="threatSelected" @threatSuggest="threatSuggest" />

    <div>
      <td-keyboard-shortcuts />
      <td-threat-edit-dialog ref="threatEditDialog" />
      <td-threat-suggest-dialog ref="threatSuggestDialog" />
    </div>
  </div>
</template>

<script>
import { mapState } from 'vuex';

import TdGraphButtons from '@/components/GraphButtons.vue';
import TdGraphMeta from '@/components/GraphMeta.vue';
import TdKeyboardShortcuts from '@/components/KeyboardShortcuts.vue';
import TdThreatEditDialog from '@/components/ThreatEditDialog.vue';
import TdThreatSuggestDialog from './ThreatSuggestDialog.vue';

import { getProviderType } from '@/service/provider/providers.js';
import diagramService from '@/service/diagram/diagram.js';
import stencil from '@/service/x6/stencil.js';
import tmActions from '@/store/actions/threatmodel.js';

export default {
  name: 'TdGraph',
  components: {
    TdGraphButtons,
    TdGraphMeta,
    TdKeyboardShortcuts,
    TdThreatEditDialog,
    TdThreatSuggestDialog
  },

  computed: {
    // 从 store 里拿当前 diagram 与 providerType
    ...mapState({
      diagram: (state) => state.threatmodel.selectedDiagram,
      providerType: (state) => getProviderType(state.provider.selected)
    }),
    // 关键：从整个 threatmodel 的模型对象中稳健取 summary（Demo JSON: {summary:{...}, detail:{...}}）
    modelSummary() {
      const tm = this.$store?.state?.threatmodel || {};
      const modelLike = tm.model || tm.selected || tm.data || {};
      return modelLike.summary || {};
    }
  },

  data() {
    return {
      graph: null
    };
  },

  async mounted() {
    this.init();
  },

  methods: {
    init() {
      // 初始化 X6 画布 & 左侧 stencil
      this.graph = diagramService.edit(this.$refs.graph_container, this.diagram);
      stencil.get(this.graph, this.$refs.stencil_container);

      // 刚进入编辑页，状态置为未修改
      this.$store.dispatch(tmActions.notModified);

      // 监听历史变化，回写 cells 到 store（不动其它元数据）
      this.graph.getPlugin('history').on('change', () => {
        const updated = Object.assign({}, this.diagram);
        updated.cells = this.graph.toJSON().cells;
        this.$store.dispatch(tmActions.diagramModified, updated);
      });
    },

    // 侧栏点中某个威胁，打开编辑对话框
    threatSelected(threatId, state) {
      this.$refs.threatEditDialog.editThreat(threatId, state);
    },

    // 打开“威胁推荐”对话框
    threatSuggest(type) {
      this.$refs.threatSuggestDialog.showModal(type);
    },

    // 顶部保存
    saved() {
      console.debug('Save diagram');
      const updated = Object.assign({}, this.diagram);
      updated.cells = this.graph.toJSON().cells;

      // 先标记保存，再触发模型保存
      this.$store.dispatch(tmActions.diagramSaved, updated);
      this.$store.dispatch(tmActions.saveModel);
    },

    // 关闭返回
    async closed() {
      if (!this.$store.getters.modelChanged || await this.getConfirmModal()) {
        await this.$store.dispatch(tmActions.diagramClosed);
        this.$router.push({ name: `${this.providerType}ThreatModel`, params: this.$route.params });
      }
    },

    /**
     * 后端需要的“简化版 DFD JSON”
     * 结构：{ title, description, nodes[], edges[] }
     * - title/description 来自模型 summary
     * - nodes/edges 来自当前画布 cells
     */
    getSimplifiedDiagramData() {
      const rawCells = this.graph.toJSON().cells;

      // 1) 节点（store / process / actor）
      const nodes = (rawCells || [])
        .filter(cell => ['store', 'process', 'actor'].includes(cell.shape))
        .map(cell => ({
          id: cell.id,
          name: cell.data?.name || cell.attrs?.text?.text || 'Unnamed',
          description: cell.data?.description || '',
          type: cell.shape,
          hasOpenThreats: !!cell.data?.hasOpenThreats,
          threats: (cell.data?.threats || []).map(th => ({
            title: th?.title || '',
            severity: th?.severity || '',
            type: th?.type || '',
            mitigation: th?.mitigation || '',
            status: th?.status || ''
          }))
        }));

      // 2) 边（flow）
      const edges = (rawCells || [])
        .filter(cell => cell.shape === 'flow')
        .map(cell => ({
          id: cell.id,
          name: cell.data?.name || 'Unnamed Flow',
          description: cell.data?.description || '',
          source: cell.source?.cell || null,
          target: cell.target?.cell || null,
          isEncrypted: !!cell.data?.isEncrypted,
          isPublicNetwork: !!cell.data?.isPublicNetwork,
          hasOpenThreats: !!cell.data?.hasOpenThreats,
          protocol: cell.data?.protocol || '',
          threats: (cell.data?.threats || []).map(th => ({
            title: th?.title || '',
            severity: th?.severity || '',
            type: th?.type || '',
            mitigation: th?.mitigation || '',
            status: th?.status || ''
          }))
        }));

      // 3) 关键：从 summary 中取标题与描述
      const { title = '', description = '' } = this.modelSummary;

      return { title, description, nodes, edges };
    },

    // 如果你仍然需要完整 diagram json（包含元数据等）
    getDiagramJson() {
      const updated = Object.assign({}, this.diagram);
      updated.cells = this.graph.toJSON().cells;
      return updated;
    },

    // 关闭确认弹窗
    getConfirmModal() {
      return this.$bvModal.msgBoxConfirm(this.$t('forms.discardMessage'), {
        title: this.$t('forms.discardTitle'),
        okVariant: 'danger',
        okTitle: this.$t('forms.ok'),
        cancelTitle: this.$t('forms.cancel'),
        hideHeaderClose: true,
        centered: true
      });
    }
  },

  destroyed() {
    diagramService.dispose(this.graph);
  }
};
</script>

<style lang="scss" scoped>
.td-graph-title {
  margin-right: 15px;
}
</style>
