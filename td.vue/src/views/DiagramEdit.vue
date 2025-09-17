<template>
  <div class="mt-5">
    <b-row class="mb-3">
      <b-col>
        <b-button variant="primary" @click="submitDiagram">威胁建模分析</b-button>
      </b-col>
    </b-row>

    <b-row>
      <b-col>
        <td-graph ref="graphRef" />
      </b-col>
    </b-row>
  </div>
</template>

<script>
// 请确保安装：npm install mermaid
import axios from 'axios';
// 从 ESM 包引入，保证有 init 方法
import mermaid from 'mermaid/dist/mermaid.esm.min.mjs';

export default {
  name: 'DiagramEdit',
  components: {
    TdGraph: () => import('@/components/Graph.vue')
  },
  data() {
    return {
      showModal: false,
      attackTreeMd: '',
      scale: 1,
      isDragging: false,
      dragStart: { x: 0, y: 0 },
      scrollStart: { left: 0, top: 0 }
    };
  },
  created() {
    // 初始化 Mermaid（全局扫描 .mermaid 元素）
    mermaid.initialize({
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'loose'
    });
  },
  methods: {
    async submitDiagram() {
      try {
        const diagramData = this.$refs.graphRef.getSimplifiedDiagramData();

        // 提交图数据到后端
        const response = await axios.post('/threat_model', diagramData);

        // 获取返回的 hash_id
        const hashId = response.data.id;
        console.log('生成的 hash_id:', hashId);

        // 存储到 localStorage，方便轮询或刷新页面后继续使用
        localStorage.setItem('dfdHashId', hashId);

        //alert('提交成功');

        // 跳转到 DREAD 页面，可以附带 hashId
        this.$router.push({ path: '/show-dread'});
        // 或者简单跳转，不带参数
        // this.$router.push('/show-dread');
      } catch (error) {
        console.error('提交失败', error);
        alert('提交失败，图数据未传输');
      }
    },



    zoom(event) {
      const delta = event.deltaY < 0 ? 0.1 : -0.1;
      this.scale = Math.min(Math.max(this.scale + delta, 0.5), 2);
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
    }
  }
};
</script>

<style scoped>
.attack-tree-wrapper {
  width: 100%;
  height: 70vh;
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
}
/* 遮蔽 modal-body 溢出 */
.attack-tree-modal .modal-body {
  padding: 0;
  overflow: hidden;
}
</style>
