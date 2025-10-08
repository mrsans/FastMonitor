<template>
  <div class="settings-panel">
    <el-card header="Ring Buffer Limits" shadow="never">
      <el-form :model="limits" label-width="200px">
        <el-form-item label="Raw Packets Max">
          <el-input-number v-model="limits.raw_max" :min="1000" :max="100000" :step="1000" />
        </el-form-item>
        <el-form-item label="DNS Sessions Max">
          <el-input-number v-model="limits.dns_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item label="HTTP Sessions Max">
          <el-input-number v-model="limits.http_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item label="ICMP Sessions Max">
          <el-input-number v-model="limits.icmp_max" :min="1000" :max="50000" :step="1000" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="saveLimits" :loading="saving">
            Apply Changes
          </el-button>
          <el-button @click="resetLimits">Reset to Default</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card header="Storage Statistics" shadow="never" style="margin-top: 20px;">
      <el-descriptions :column="2" border>
        <el-descriptions-item label="Total Packets">
          {{ stats.raw_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="DNS Sessions">
          {{ stats.dns_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="HTTP Sessions">
          {{ stats.http_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="ICMP Sessions">
          {{ stats.icmp_count?.toLocaleString() || 0 }}
        </el-descriptions-item>
        <el-descriptions-item label="Storage Size">
          {{ formatBytes(stats.total_size || 0) }}
        </el-descriptions-item>
        <el-descriptions-item label="PCAP Files">
          {{ stats.pcap_file_count || 0 }}
        </el-descriptions-item>
      </el-descriptions>

      <el-button
        type="warning"
        style="margin-top: 20px;"
        @click="runVacuum"
        :loading="vacuuming"
      >
        Run Storage Cleanup
      </el-button>
    </el-card>

    <el-card header="About" shadow="never" style="margin-top: 20px;">
      <p><strong>Network Packet Sniffer</strong></p>
      <p>A powerful network packet capture and analysis tool built with Wails and Go.</p>
      <p style="margin-top: 10px; color: var(--el-text-color-secondary);">
        <el-icon><InfoFilled /></el-icon>
        Requires administrator/root privileges to capture packets.
      </p>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { InfoFilled } from '@element-plus/icons-vue'
import { GetLimits, UpdateLimits, GetStorageStats, VacuumStorage } from '../../wailsjs/go/server/App'

const emit = defineEmits(['config-updated'])

const limits = ref({
  raw_max: 20000,
  dns_max: 5000,
  http_max: 5000,
  icmp_max: 5000
})

const stats = ref<any>({})
const saving = ref(false)
const vacuuming = ref(false)

onMounted(async () => {
  await loadLimits()
  await loadStats()
})

async function loadLimits() {
  try {
    limits.value = await GetLimits()
  } catch (error) {
    ElMessage.error('Failed to load limits: ' + error)
  }
}

async function loadStats() {
  try {
    stats.value = await GetStorageStats()
  } catch (error) {
    console.error('Failed to load stats:', error)
  }
}

async function saveLimits() {
  try {
    saving.value = true
    await UpdateLimits(limits.value)
    ElMessage.success('Settings saved successfully')
    emit('config-updated')
  } catch (error) {
    ElMessage.error('Failed to save settings: ' + error)
  } finally {
    saving.value = false
  }
}

function resetLimits() {
  limits.value = {
    raw_max: 20000,
    dns_max: 5000,
    http_max: 5000,
    icmp_max: 5000
  }
}

async function runVacuum() {
  try {
    vacuuming.value = true
    await VacuumStorage()
    await loadStats()
    ElMessage.success('Storage cleanup completed')
  } catch (error) {
    ElMessage.error('Failed to run cleanup: ' + error)
  } finally {
    vacuuming.value = false
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}
</script>

<style scoped lang="scss">
.settings-panel {
  padding: 20px;
  max-width: 800px;
}
</style>

