<template>
  <div class="main-view">
    <!-- Header -->
    <div class="header">
      <div class="header-left">
        <h1><el-icon><Monitor /></el-icon> Network Packet Sniffer</h1>
      </div>
      <div class="header-right">
        <el-tag :type="isCapturing ? 'success' : 'info'" size="large">
          {{ isCapturing ? (isPaused ? 'PAUSED' : 'CAPTURING') : 'STOPPED' }}
        </el-tag>
      </div>
    </div>

    <!-- Control Panel -->
    <div class="control-panel">
      <div class="control-left">
        <el-select
          v-model="selectedInterface"
          placeholder="Select Network Interface"
          :disabled="isCapturing"
          style="width: 300px"
        >
          <el-option
            v-for="iface in interfaces"
            :key="iface.name"
            :label="`${iface.name} ${iface.description ? '- ' + iface.description : ''}`"
            :value="iface.name"
          >
            <span style="float: left">{{ iface.name }}</span>
            <span style="float: right; color: var(--el-text-color-secondary); font-size: 12px">
              <el-icon v-if="iface.is_physical"><Connection /></el-icon>
              <el-icon v-else><Link /></el-icon>
            </span>
          </el-option>
        </el-select>

        <el-button
          v-if="!isCapturing"
          type="primary"
          :icon="VideoPlay"
          @click="startCapture"
          :disabled="!selectedInterface"
        >
          Start Capture
        </el-button>
        <template v-else>
          <el-button
            v-if="!isPaused"
            type="warning"
            :icon="VideoPause"
            @click="pauseCapture"
          >
            Pause
          </el-button>
          <el-button
            v-else
            type="success"
            :icon="VideoPlay"
            @click="resumeCapture"
          >
            Resume
          </el-button>
          <el-button
            type="danger"
            :icon="VideoCamera"
            @click="stopCapture"
          >
            Stop
          </el-button>
        </template>
      </div>

      <div class="control-right">
        <el-statistic
          title="Packets/s"
          :value="metrics.packets_per_sec"
          :precision="1"
        />
        <el-statistic
          title="KB/s"
          :value="(metrics.bytes_per_sec / 1024)"
          :precision="1"
        />
        <el-statistic
          title="Total Packets"
          :value="metrics.packets_total"
        />
      </div>
    </div>

    <!-- Tabs -->
    <div class="content-area">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="Raw Packets" name="raw">
          <PacketTable
            :data="rawPackets"
            :loading="loading"
            @refresh="loadRawPackets"
          />
        </el-tab-pane>
        <el-tab-pane name="dns">
          <template #label>
            <span>DNS Sessions <el-badge :value="metrics.dns_count" /></span>
          </template>
          <SessionTable
            table="dns"
            :data="dnsSessions"
            :loading="loading"
            @refresh="loadDNSSessions"
          />
        </el-tab-pane>
        <el-tab-pane name="http">
          <template #label>
            <span>HTTP Sessions <el-badge :value="metrics.http_count" /></span>
          </template>
          <SessionTable
            table="http"
            :data="httpSessions"
            :loading="loading"
            @refresh="loadHTTPSessions"
          />
        </el-tab-pane>
        <el-tab-pane name="icmp">
          <template #label>
            <span>ICMP Sessions <el-badge :value="metrics.icmp_count" /></span>
          </template>
          <SessionTable
            table="icmp"
            :data="icmpSessions"
            :loading="loading"
            @refresh="loadICMPSessions"
          />
        </el-tab-pane>
        <el-tab-pane label="Settings" name="settings">
          <SettingsPanel @config-updated="loadConfig" />
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Monitor, VideoPlay, VideoPause, VideoCamera, Connection, Link } from '@element-plus/icons-vue'
import PacketTable from '../components/PacketTable.vue'
import SessionTable from '../components/SessionTable.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import { GetInterfaces, StartCapture, StopCapture, PauseCapture, ResumeCapture, GetMetrics, GetRawPackets, GetSessions } from '../../wailsjs/go/server/App'

const interfaces = ref<any[]>([])
const selectedInterface = ref('')
const isCapturing = ref(false)
const isPaused = ref(false)
const activeTab = ref('raw')
const loading = ref(false)

const metrics = ref({
  packets_per_sec: 0,
  bytes_per_sec: 0,
  packets_total: 0,
  dns_count: 0,
  http_count: 0,
  icmp_count: 0
})

const rawPackets = ref<any[]>([])
const dnsSessions = ref<any[]>([])
const httpSessions = ref<any[]>([])
const icmpSessions = ref<any[]>([])

let metricsTimer: any = null

onMounted(async () => {
  await loadInterfaces()
  await loadConfig()
  startMetricsPolling()
})

onUnmounted(() => {
  stopMetricsPolling()
})

async function loadInterfaces() {
  try {
    interfaces.value = await GetInterfaces()
    if (interfaces.value.length > 0) {
      // Select first physical interface by default
      const physical = interfaces.value.find(i => i.is_physical && !i.is_loopback)
      selectedInterface.value = physical ? physical.name : interfaces.value[0].name
    }
  } catch (error) {
    ElMessage.error('Failed to load network interfaces: ' + error)
  }
}

async function loadConfig() {
  // Configuration is loaded on demand
}

async function startCapture() {
  if (!selectedInterface.value) {
    ElMessage.warning('Please select a network interface')
    return
  }

  try {
    await StartCapture(selectedInterface.value)
    isCapturing.value = true
    isPaused.value = false
    ElMessage.success('Capture started on ' + selectedInterface.value)
    
    // Start auto-refresh
    startDataRefresh()
  } catch (error) {
    ElMessage.error('Failed to start capture: ' + error)
  }
}

async function stopCapture() {
  try {
    await StopCapture()
    isCapturing.value = false
    isPaused.value = false
    ElMessage.success('Capture stopped')
    
    // Stop auto-refresh
    stopDataRefresh()
  } catch (error) {
    ElMessage.error('Failed to stop capture: ' + error)
  }
}

async function pauseCapture() {
  try {
    await PauseCapture()
    isPaused.value = true
    ElMessage.info('Capture paused')
  } catch (error) {
    ElMessage.error('Failed to pause capture: ' + error)
  }
}

async function resumeCapture() {
  try {
    await ResumeCapture()
    isPaused.value = false
    ElMessage.success('Capture resumed')
  } catch (error) {
    ElMessage.error('Failed to resume capture: ' + error)
  }
}

function startMetricsPolling() {
  metricsTimer = setInterval(async () => {
    try {
      const m = await GetMetrics()
      metrics.value = m
      isCapturing.value = m.is_capturing
      isPaused.value = m.is_paused
    } catch (error) {
      // Ignore errors in polling
    }
  }, 1000)
}

function stopMetricsPolling() {
  if (metricsTimer) {
    clearInterval(metricsTimer)
    metricsTimer = null
  }
}

let dataRefreshTimer: any = null

function startDataRefresh() {
  dataRefreshTimer = setInterval(async () => {
    if (activeTab.value === 'raw') {
      await loadRawPackets()
    } else if (activeTab.value === 'dns') {
      await loadDNSSessions()
    } else if (activeTab.value === 'http') {
      await loadHTTPSessions()
    } else if (activeTab.value === 'icmp') {
      await loadICMPSessions()
    }
  }, 2000)
}

function stopDataRefresh() {
  if (dataRefreshTimer) {
    clearInterval(dataRefreshTimer)
    dataRefreshTimer = null
  }
}

async function loadRawPackets() {
  try {
    loading.value = true
    rawPackets.value = await GetRawPackets(200)
  } catch (error) {
    console.error('Failed to load raw packets:', error)
  } finally {
    loading.value = false
  }
}

async function loadDNSSessions() {
  try {
    loading.value = true
    dnsSessions.value = await GetSessions('dns', 200)
  } catch (error) {
    console.error('Failed to load DNS sessions:', error)
  } finally {
    loading.value = false
  }
}

async function loadHTTPSessions() {
  try {
    loading.value = true
    httpSessions.value = await GetSessions('http', 200)
  } catch (error) {
    console.error('Failed to load HTTP sessions:', error)
  } finally {
    loading.value = false
  }
}

async function loadICMPSessions() {
  try {
    loading.value = true
    icmpSessions.value = await GetSessions('icmp', 200)
  } catch (error) {
    console.error('Failed to load ICMP sessions:', error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="scss">
.main-view {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 16px;
  gap: 16px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 20px;
  background: var(--el-bg-color-overlay);
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);

  h1 {
    font-size: 24px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
  }
}

.control-panel {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 20px;
  background: var(--el-bg-color-overlay);
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);

  .control-left {
    display: flex;
    gap: 12px;
    align-items: center;
  }

  .control-right {
    display: flex;
    gap: 32px;
  }
}

.content-area {
  flex: 1;
  overflow: hidden;

  :deep(.el-tabs) {
    height: 100%;
    display: flex;
    flex-direction: column;

    .el-tabs__content {
      flex: 1;
      overflow: hidden;
    }

    .el-tab-pane {
      height: 100%;
    }
  }
}
</style>

