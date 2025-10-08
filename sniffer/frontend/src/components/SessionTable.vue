<template>
  <div class="session-table">
    <div class="table-header">
      <el-button :icon="Refresh" @click="$emit('refresh')" :loading="loading">
        Refresh
      </el-button>
      <span class="session-count">{{ data.length }} sessions</span>
    </div>

    <!-- DNS Table -->
    <el-table
      v-if="table === 'dns'"
      :data="displayData"
      height="calc(100vh - 350px)"
      stripe
      style="width: 100%"
    >
      <el-table-column prop="timestamp" label="Timestamp" width="200">
        <template #default="{ row }">
          {{ formatTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="five_tuple.src_ip" label="Source IP" width="150" />
      <el-table-column prop="domain" label="Domain" min-width="200" show-overflow-tooltip />
      <el-table-column prop="query_type" label="Query Type" width="120">
        <template #default="{ row }">
          <el-tag size="small">{{ row.query_type }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="response_ip" label="Response IP" width="150" />
      <el-table-column prop="payload_size" label="Size" width="100" />
    </el-table>

    <!-- HTTP Table -->
    <el-table
      v-else-if="table === 'http'"
      :data="displayData"
      height="calc(100vh - 350px)"
      stripe
      style="width: 100%"
    >
      <el-table-column prop="timestamp" label="Timestamp" width="200">
        <template #default="{ row }">
          {{ formatTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="method" label="Method" width="100">
        <template #default="{ row }">
          <el-tag :type="getMethodType(row.method)" size="small">
            {{ row.method }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="host" label="Host" width="200" show-overflow-tooltip />
      <el-table-column prop="path" label="Path" min-width="200" show-overflow-tooltip />
      <el-table-column prop="status_code" label="Status" width="100">
        <template #default="{ row }">
          <el-tag v-if="row.status_code" :type="getStatusType(row.status_code)" size="small">
            {{ row.status_code }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="user_agent" label="User Agent" min-width="200" show-overflow-tooltip />
    </el-table>

    <!-- ICMP Table -->
    <el-table
      v-else-if="table === 'icmp'"
      :data="displayData"
      height="calc(100vh - 350px)"
      stripe
      style="width: 100%"
    >
      <el-table-column prop="timestamp" label="Timestamp" width="200">
        <template #default="{ row }">
          {{ formatTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="five_tuple.src_ip" label="Source IP" width="150" />
      <el-table-column prop="five_tuple.dst_ip" label="Destination IP" width="150" />
      <el-table-column prop="icmp_type" label="Type" width="100" />
      <el-table-column prop="icmp_code" label="Code" width="100" />
      <el-table-column prop="icmp_seq" label="Sequence" width="120" />
      <el-table-column prop="payload_size" label="Size" width="100" />
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Refresh } from '@element-plus/icons-vue'

const props = defineProps<{
  table: string
  data: any[]
  loading: boolean
}>()

defineEmits(['refresh'])

const displayData = computed(() => {
  return props.data.slice(0, 200)
})

function formatTimestamp(ts: string): string {
  const date = new Date(ts)
  return date.toLocaleString()
}

function getMethodType(method: string): string {
  switch (method) {
    case 'GET':
      return 'success'
    case 'POST':
      return 'primary'
    case 'PUT':
      return 'warning'
    case 'DELETE':
      return 'danger'
    default:
      return 'info'
  }
}

function getStatusType(status: number): string {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'info'
  if (status >= 400 && status < 500) return 'warning'
  if (status >= 500) return 'danger'
  return 'info'
}
</script>

<style scoped lang="scss">
.session-table {
  height: 100%;
  display: flex;
  flex-direction: column;

  .table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;

    .session-count {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }
}
</style>

