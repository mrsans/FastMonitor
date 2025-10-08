<template>
  <div class="packet-table">
    <div class="table-header">
      <el-button :icon="Refresh" @click="$emit('refresh')" :loading="loading">
        Refresh
      </el-button>
      <span class="packet-count">{{ data.length }} packets</span>
    </div>

    <el-table
      :data="displayData"
      height="calc(100vh - 350px)"
      stripe
      style="width: 100%"
      :default-sort="{ prop: 'timestamp', order: 'descending' }"
    >
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="timestamp" label="Timestamp" width="200">
        <template #default="{ row }">
          {{ formatTimestamp(row.timestamp) }}
        </template>
      </el-table-column>
      <el-table-column prop="src_ip" label="Source IP" width="150" />
      <el-table-column prop="dst_ip" label="Destination IP" width="150" />
      <el-table-column prop="src_port" label="Src Port" width="100" />
      <el-table-column prop="dst_port" label="Dst Port" width="100" />
      <el-table-column prop="protocol" label="Protocol" width="100">
        <template #default="{ row }">
          <el-tag :type="getProtocolType(row.protocol)" size="small">
            {{ row.protocol }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="length" label="Length" width="100" />
      <el-table-column prop="layer_info" label="Layers" min-width="200" show-overflow-tooltip />
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Refresh } from '@element-plus/icons-vue'

const props = defineProps<{
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

function getProtocolType(protocol: string): string {
  switch (protocol.toUpperCase()) {
    case 'TCP':
      return 'primary'
    case 'UDP':
      return 'success'
    case 'ICMP':
      return 'warning'
    default:
      return 'info'
  }
}
</script>

<style scoped lang="scss">
.packet-table {
  height: 100%;
  display: flex;
  flex-direction: column;

  .table-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;

    .packet-count {
      font-size: 14px;
      color: var(--el-text-color-secondary);
    }
  }
}
</style>

