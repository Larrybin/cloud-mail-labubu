<template>
  <div class="subscriber-page">
    <div class="toolbar">
      <el-input
        v-model="filters.keyword"
        :placeholder="$t('searchByEmail')"
        class="toolbar-item keyword-input"
        clearable
        @keyup.enter="reload"
      />
      <el-input
        v-model="filters.listKey"
        :placeholder="$t('subscriberListKey')"
        class="toolbar-item"
        clearable
        @keyup.enter="reload"
      />
      <el-select v-model="filters.status" class="toolbar-item" clearable>
        <el-option :label="$t('all')" value="" />
        <el-option :label="$t('subscriberSubscribed')" value="subscribed" />
      </el-select>
      <el-button type="primary" :loading="loading" @click="reload">{{ $t('search') }}</el-button>
      <el-button :loading="exporting" @click="downloadCsv">{{ $t('exportCsv') }}</el-button>
    </div>

    <el-table v-loading="loading" :data="rows" border stripe>
      <el-table-column prop="email" :label="$t('tabEmailAddress')" min-width="220" />
      <el-table-column prop="listKey" :label="$t('subscriberListKey')" min-width="150" />
      <el-table-column prop="brandName" :label="$t('subscriberBrand')" min-width="180" />
      <el-table-column prop="locale" :label="$t('subscriberLocale')" width="100" />
      <el-table-column prop="sourcePath" :label="$t('subscriberSourcePath')" min-width="220" />
      <el-table-column
        prop="firstSubscribedAt"
        :label="$t('subscriberFirstSubscribedAt')"
        min-width="180"
      />
      <el-table-column
        prop="lastSubscribedAt"
        :label="$t('subscriberLastSubscribedAt')"
        min-width="180"
      />
    </el-table>

    <div class="pager">
      <el-pagination
        background
        layout="total, prev, pager, next"
        :current-page="filters.page"
        :page-size="filters.size"
        :total="total"
        @current-change="changePage"
      />
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { subscriberExport, subscriberList } from '@/request/subscriber.js'

defineOptions({
  name: 'subscriber'
})

const { t } = useI18n()
const loading = ref(false)
const exporting = ref(false)
const rows = ref([])
const total = ref(0)
const filters = reactive({
  keyword: '',
  listKey: '',
  status: '',
  page: 1,
  size: 20
})

async function reload() {
  loading.value = true
  try {
    const data = await subscriberList(filters)
    rows.value = Array.isArray(data?.list) ? data.list : []
    total.value = Number(data?.total || 0)
  } finally {
    loading.value = false
  }
}

function changePage(page) {
  filters.page = page
  reload()
}

async function downloadCsv() {
  exporting.value = true
  try {
    const blob = await subscriberExport(filters)
    const href = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = href
    link.download = 'subscribers.csv'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(href)
  } catch (error) {
    ElMessage({
      message: t('exportCsvFail'),
      type: 'error',
      plain: true
    })
  } finally {
    exporting.value = false
  }
}

onMounted(() => {
  reload()
})
</script>

<style lang="scss" scoped>
.subscriber-page {
  padding: 16px;
}

.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.toolbar-item {
  width: 180px;
}

.keyword-input {
  width: 260px;
}

.pager {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
