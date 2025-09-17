<template>
  <div class="container py-4">
    <b-card>
      <div class="d-flex align-items-center mb-3">
        <h4 class="mb-0">Mitigations</h4>
        <b-badge variant="light" class="ml-2">共 {{ total }} 条</b-badge>
        <b-spinner small class="ml-2" v-if="loading" />
        <b-button size="sm" class="ml-auto" @click="fetchPage" :disabled="loading">刷新</b-button>
      </div>

      <b-alert v-if="error" show variant="danger" class="mb-3">
        加载失败：{{ error }}
      </b-alert>

      <b-table
        :items="items"
        :fields="fields"
        :busy="loading"
        hover small bordered responsive
        show-empty empty-text="暂无数据" head-variant="light"
      >
        <template #table-busy>
          <div class="text-center my-3">
            <b-spinner class="mr-2"></b-spinner> 正在加载…
          </div>
        </template>

        <!-- 时间字段格式化 -->
        <template #cell(created_at)="{ item }">
          {{ formatDate(item.created_at) }}
        </template>

        <!-- 操作列：下载 Excel -->
        <template #cell(actions)="{ item }">
          <b-button
            size="sm"
            variant="outline-primary"
            :disabled="downloadingId === item.id"
            @click="downloadById(item)"
          >
            <b-spinner small v-if="downloadingId === item.id" class="mr-1" />下载Excel
          </b-button>
        </template>
      </b-table>

      <div class="d-flex align-items-center mt-3">
        <b-form-select
          v-model="pageSize"
          :options="pageSizeOptions"
          size="sm"
          class="w-auto mr-3"
          @change="onPageSizeChange"
        />
        <b-pagination
          v-model="page"
          :per-page="pageSize"
          :total-rows="total"
          size="sm"
          align="right"
          class="mb-0 ml-auto"
          @input="fetchPage"
        />
      </div>
    </b-card>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  name: 'MitigationsExport',
  data() {
    return {
      // 列表接口
      endpoint: '/mitigationstable',

      exportEndpoint: '/mitigationsexport',

      loading: false,
      error: '',
      items: [],
      fields: [
        { key: 'id',         label: 'ID',       class: 'text-nowrap' },
        { key: 'created_at', label: '创建时间', class: 'text-nowrap' },
        { key: 'dfd_title',  label: 'DFD 标题' },
        { key: 'actions',    label: '操作',     class: 'text-nowrap', thStyle: { width: '120px' } } // 新增
      ],
      page: 1,
      pageSize: 5,
      total: 0,
      pageSizeOptions: [
        { value: 5, text: '每页 5 条' },
        { value: 10, text: '每页 10 条' },
        { value: 20, text: '每页 20 条' },
        { value: 50, text: '每页 50 条' }
      ],
      downloadingId: null
    };
  },
  created() {
    this.fetchPage();
  },
  methods: {
    async fetchPage() {
      this.loading = true; this.error = '';
      try {
        const { data } = await axios.get(this.endpoint, {
          params: { page: this.page, page_size: this.pageSize }
        });
        this.total = Number(data.total || 0);
        this.items = Array.isArray(data.data) ? data.data : [];
        const last = Math.max(1, Math.ceil(this.total / this.pageSize));
        if (this.page > last && this.total > 0) {
          this.page = last;
          await this.fetchPage();
        }
      } catch (e) {
        this.error = e?.response?.data?.message || e.message || '未知错误';
        this.items = [];
      } finally {
        this.loading = false;
      }
    },
    onPageSizeChange() {
      this.page = 1;
      this.fetchPage();
    },
    formatDate(val) {
      if (!val) return '';
      const d = new Date(val);
      if (isNaN(d.getTime())) return String(val);
      return d.toLocaleString('zh-CN', { hour12: false });
    },

downloadById(row) {
  // 点击后禁用按钮一会，避免重复触发
  this.downloadingId = row.id;
  const url = `${this.exportEndpoint}/${encodeURIComponent(row.id)}`;

  // 直接同窗口跳转，浏览器按响应头下载到默认下载目录
  window.location.href = url;

  // 1.5 秒后恢复按钮（避免卡住）
  setTimeout(() => { this.downloadingId = null; }, 1500);
}

,
    getFilenameFromDisposition(disposition) {
      // 解析 Content-Disposition: attachment; filename="xxx.xlsx"
      try {
        const match = /filename\*?=(?:UTF-8'')?["']?([^;"']+)/i.exec(disposition);
        if (match && match[1]) return decodeURIComponent(match[1].replace(/["']/g, ''));
      } catch {}
      return '';
    }
  }
};
</script>

<style scoped>
.container { max-width: 1200px; }
</style>
