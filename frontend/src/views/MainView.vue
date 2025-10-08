<template>
  <div class="main-view">
    <!-- 合并的顶部标题栏和控制面板 -->
    <div class="header-merged">
      <div class="header-left">
        <h1><el-icon><Monitor /></el-icon> 网络抓包分析器</h1>
      </div>
      
      <!-- 控制面板居中 -->
      <div class="header-center">
        <el-select
          v-model="selectedInterface"
          placeholder="选择网络接口"
          :disabled="isCapturing"
          style="width: 300px"
          size="small"
        >
          <el-option
            v-for="iface in interfaces"
            :key="iface.name"
            :label="formatInterfaceLabel(iface)"
            :value="iface.name"
          >
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <span style="font-weight: 600; font-size: 13px;">{{ iface.description || iface.name }}</span>
              <span v-if="iface.addresses && iface.addresses.length > 0" style="font-size: 11px; color: var(--el-text-color-secondary);">
                {{ iface.addresses.slice(0, 1).join(', ') }}
              </span>
            </div>
          </el-option>
        </el-select>

        <el-button
          v-if="!isCapturing"
          type="primary"
          :icon="VideoPlay"
          @click="startCapture"
          :disabled="!selectedInterface"
          size="small"
        >
          开始
        </el-button>
        <template v-else>
          <el-button
            v-if="!isPaused"
            type="warning"
            :icon="VideoPause"
            @click="pauseCapture"
            size="small"
          >
            暂停
          </el-button>
          <el-button
            v-else
            type="success"
            :icon="VideoPlay"
            @click="resumeCapture"
            size="small"
          >
            恢复
          </el-button>
          <el-button
            type="danger"
            :icon="VideoCamera"
            @click="stopCapture"
            size="small"
          >
            停止
          </el-button>
        </template>
        <el-button
          v-if="!isCapturing"
          type="info"
          :icon="Delete"
          @click="clearData"
          size="small"
        >
          清空
        </el-button>
        
        <!-- 实时指标 -->
        <div class="metrics-compact">
          <el-tag type="info" size="small">{{ metrics.packets_per_sec.toFixed(1) }} pps</el-tag>
          <el-tag type="success" size="small">{{ (metrics.bytes_per_sec / 1024).toFixed(1) }} KB/s</el-tag>
          <el-tag type="warning" size="small">{{ metrics.packets_total.toLocaleString() }} 包</el-tag>
        </div>
      </div>

      <div class="header-right">
        <el-switch
          v-model="isDark"
          inline-prompt
          active-text="深色"
          inactive-text="浅色"
          @change="toggleTheme"
          size="small"
          style="margin-right: 15px"
        />
        <el-tag :type="isCapturing ? 'success' : 'info'" size="small">
          {{ statusText }}
        </el-tag>
      </div>
    </div>

    <!-- 标签页 -->
    <div class="content-area">
      <el-tabs v-model="activeTab" type="border-card">
        <el-tab-pane label="仪表盘" name="dashboard">
          <DashboardView ref="dashboardRef" />
        </el-tab-pane>
        <el-tab-pane label="数据包" name="raw">
          <PacketTable
            :data="rawPackets"
            :total="rawTotal"
            :loading="loading"
            @refresh="loadRawPackets"
            @page-change="handleRawPageChange"
            @size-change="handleRawSizeChange"
            @sort-change="handleRawSortChange"
          />
        </el-tab-pane>
        <el-tab-pane name="dns">
          <template #label>
            <span>DNS<el-badge :value="dnsTotal" /></span>
          </template>
          <SessionTable
            table="dns"
            :data="dnsSessions"
            :total="dnsTotal"
            :loading="loading"
            @refresh="loadDNSSessions"
            @page-change="handleDNSPageChange"
            @size-change="handleDNSSizeChange"
            @sort-change="handleDNSSortChange"
          />
        </el-tab-pane>
        <el-tab-pane name="http">
          <template #label>
            <span>HTTP<el-badge :value="httpTotal" /></span>
          </template>
          <SessionTable
            table="http"
            :data="httpSessions"
            :total="httpTotal"
            :loading="loading"
            @refresh="loadHTTPSessions"
            @page-change="handleHTTPPageChange"
            @size-change="handleHTTPSizeChange"
            @sort-change="handleHTTPSortChange"
          />
        </el-tab-pane>
        <el-tab-pane name="icmp">
          <template #label>
            <span>ICMP<el-badge :value="icmpTotal" /></span>
          </template>
          <SessionTable
            table="icmp"
            :data="icmpSessions"
            :total="icmpTotal"
            :loading="loading"
            @refresh="loadICMPSessions"
            @page-change="handleICMPPageChange"
            @size-change="handleICMPSizeChange"
            @sort-change="handleICMPSortChange"
          />
        </el-tab-pane>
        <el-tab-pane name="sessions">
          <template #label>
            <span>会话流 <el-badge :value="sessionFlowTotal" /></span>
          </template>
          <SessionFlowTable
            :data="sessionFlows"
            :total="sessionFlowTotal"
            :loading="loading"
            @refresh="loadSessionFlows"
            @page-change="handleSessionFlowPageChange"
            @size-change="handleSessionFlowSizeChange"
            @sort-change="handleSessionFlowSortChange"
          />
        </el-tab-pane>
        <el-tab-pane label="进程" name="process">
          <ProcessView />
        </el-tab-pane>
        <el-tab-pane label="告警" name="alert">
          <el-tabs v-model="alertSubTab" type="border-card" @tab-change="handleAlertTabChange">
            <el-tab-pane label="告警列表" name="alert-logs">
              <AlertLogs ref="alertLogsRef" />
            </el-tab-pane>
            <el-tab-pane label="告警规则" name="alert-rules">
              <AlertRules ref="alertRulesRef" />
            </el-tab-pane>
          </el-tabs>
        </el-tab-pane>
        <el-tab-pane label="设置" name="settings">
          <SettingsPanel @config-updated="loadConfig" />
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Monitor, VideoPlay, VideoPause, VideoCamera, Connection, Link, Delete } from '@element-plus/icons-vue'
import PacketTable from '../components/PacketTable.vue'
import SessionTable from '../components/SessionTable.vue'
import SessionFlowTable from '../components/SessionFlowTable.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import DashboardView from './DashboardView.vue'
import ProcessView from './ProcessView.vue'
import AlertLogs from '../components/AlertLogs.vue'
import AlertRules from '../components/AlertRules.vue'
import { useThemeStore } from '../stores/theme'
import { GetInterfaces, StartCapture, StopCapture, PauseCapture, ResumeCapture, GetMetrics, GetRawPackets, QuerySessions, QuerySessionFlows, ClearAllData } from '../../wailsjs/go/server/App'

const themeStore = useThemeStore()
const isDark = ref(themeStore.isDark)

const interfaces = ref<any[]>([])
const selectedInterface = ref('')
const isCapturing = ref(false)
const isPaused = ref(false)
const activeTab = ref('dashboard')
const alertSubTab = ref('alert-logs')
const loading = ref(false)

// 告警组件的引用
const alertLogsRef = ref()
const alertRulesRef = ref()

const metrics = ref({
  packets_per_sec: 0,
  bytes_per_sec: 0,
  packets_total: 0,
  dns_count: 0,
  http_count: 0,
  icmp_count: 0
})

// 数据和分页
const rawPackets = ref<any[]>([])
const rawTotal = ref(0)
const rawPage = ref(1)
const rawPageSize = ref(100)
const rawSortBy = ref('timestamp')
const rawSortOrder = ref('desc')

const dnsSessions = ref<any[]>([])
const dnsTotal = ref(0)
const dnsPage = ref(1)
const dnsPageSize = ref(50)
const dnsSortBy = ref('timestamp')
const dnsSortOrder = ref('desc')

const httpSessions = ref<any[]>([])
const httpTotal = ref(0)
const httpPage = ref(1)
const httpPageSize = ref(50)
const httpSortBy = ref('timestamp')
const httpSortOrder = ref('desc')

const icmpSessions = ref<any[]>([])
const icmpTotal = ref(0)
const icmpPage = ref(1)
const icmpPageSize = ref(50)
const icmpSortBy = ref('timestamp')
const icmpSortOrder = ref('desc')

const sessionFlows = ref<any[]>([])
const sessionFlowTotal = ref(0)
const sessionFlowPage = ref(1)
const sessionFlowPageSize = ref(50)
const sessionFlowSortBy = ref('packet_count')
const sessionFlowSortOrder = ref('desc')

let metricsTimer: any = null
let dataRefreshTimer: any = null

const statusText = computed(() => {
  if (!isCapturing.value) return '已停止'
  if (isPaused.value) return '已暂停'
  return '正在抓包'
})

function toggleTheme() {
  themeStore.setTheme(isDark.value)
}

function formatInterfaceLabel(iface: any): string {
  const desc = iface.description || iface.name
  const ips = iface.addresses && iface.addresses.length > 0 
    ? ` (${iface.addresses.slice(0, 2).join(', ')})` 
    : ''
  return `${desc}${ips}`
}

onMounted(async () => {
  await loadInterfaces()
  await loadConfig()
  startMetricsPolling()
})

onUnmounted(() => {
  stopMetricsPolling()
  stopDataRefresh()
})

// 监听标签页变化，立即刷新数据
watch(activeTab, () => {
  loadCurrentTab()
})

async function loadInterfaces() {
  try {
    interfaces.value = await GetInterfaces()
    if (interfaces.value.length > 0) {
      const physical = interfaces.value.find(i => i.is_physical && !i.is_loopback)
      selectedInterface.value = physical ? physical.name : interfaces.value[0].name
    }
  } catch (error) {
    ElMessage.error('加载网络接口失败: ' + error)
  }
}

async function loadConfig() {
  // 配置按需加载
}

async function startCapture() {
  if (!selectedInterface.value) {
    ElMessage.warning('请选择网络接口')
    return
  }

  try {
    await StartCapture(selectedInterface.value)
    isCapturing.value = true
    isPaused.value = false
    ElMessage.success('抓包已开始: ' + selectedInterface.value)
    startDataRefresh()
  } catch (error) {
    ElMessage.error('启动抓包失败: ' + error)
  }
}

async function stopCapture() {
  try {
    await StopCapture()
    isCapturing.value = false
    isPaused.value = false
    ElMessage.success('抓包已停止')
    stopDataRefresh()
  } catch (error) {
    ElMessage.error('停止抓包失败: ' + error)
  }
}

async function pauseCapture() {
  try {
    await PauseCapture()
    isPaused.value = true
    ElMessage.info('抓包已暂停')
  } catch (error) {
    ElMessage.error('暂停抓包失败: ' + error)
  }
}

async function resumeCapture() {
  try {
    await ResumeCapture()
    isPaused.value = false
    ElMessage.success('抓包已恢复')
  } catch (error) {
    ElMessage.error('恢复抓包失败: ' + error)
  }
}

async function clearData() {
  try {
    await ElMessageBox.confirm(
      '确定要清空所有抓包数据吗？此操作不可恢复！',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    
    await ClearAllData()
    
    // 清空前端数据
    rawPackets.value = []
    dnsSessions.value = []
    httpSessions.value = []
    icmpSessions.value = []
    sessionFlows.value = []
    rawTotal.value = 0
    dnsTotal.value = 0
    httpTotal.value = 0
    icmpTotal.value = 0
    sessionFlowTotal.value = 0
    
    ElMessage.success('数据已清空')
    
    // 刷新当前标签页
    await loadCurrentTab()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(`清空失败: ${error}`)
    }
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
      // 忽略轮询错误
    }
  }, 1000)
}

function stopMetricsPolling() {
  if (metricsTimer) {
    clearInterval(metricsTimer)
    metricsTimer = null
  }
}

function startDataRefresh() {
  loadCurrentTab()
  dataRefreshTimer = setInterval(async () => {
    if (isCapturing.value && !isPaused.value) {
      // 只在活动标签页不是 dashboard、process 和 settings 时刷新
      if (activeTab.value !== 'dashboard' && activeTab.value !== 'process' && activeTab.value !== 'settings') {
        loadCurrentTab()
      }
    }
  }, 5000) // 降低刷新频率到5秒，减少干扰
}

function stopDataRefresh() {
  if (dataRefreshTimer) {
    clearInterval(dataRefreshTimer)
    dataRefreshTimer = null
  }
}

function loadCurrentTab() {
  switch (activeTab.value) {
    case 'raw':
      loadRawPackets()
      break
    case 'dns':
      loadDNSSessions()
      break
    case 'http':
      loadHTTPSessions()
      break
    case 'icmp':
      loadICMPSessions()
      break
    case 'sessions':
      loadSessionFlows()
      break
  }
}

async function loadRawPackets() {
  try {
    loading.value = true
    console.log('Loading raw packets...', { limit: rawPageSize.value })
    // 从内存获取所有包，然后前端分页
    const packets = await GetRawPackets(20000) // 获取所有
    const allPackets = packets || []
    
    // 前端分页
    const start = (rawPage.value - 1) * rawPageSize.value
    const end = start + rawPageSize.value
    rawPackets.value = allPackets.slice(start, end)
    rawTotal.value = allPackets.length
    
    console.log('Raw packets loaded:', { total: rawTotal.value, displayed: rawPackets.value.length })
  } catch (error) {
    console.error('加载原始包失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadDNSSessions() {
  try {
    loading.value = true
    console.log('Loading DNS sessions...', {
      limit: dnsPageSize.value,
      offset: (dnsPage.value - 1) * dnsPageSize.value,
      sort_by: dnsSortBy.value,
      sort_order: dnsSortOrder.value
    })
    const result = await QuerySessions({
      table: 'dns',
      limit: dnsPageSize.value,
      offset: (dnsPage.value - 1) * dnsPageSize.value,
      sort_by: dnsSortBy.value,
      sort_order: dnsSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    console.log('DNS result:', result)
    dnsSessions.value = result.data || []
    dnsTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 DNS 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadHTTPSessions() {
  try {
    loading.value = true
    const result = await QuerySessions({
      table: 'http',
      limit: httpPageSize.value,
      offset: (httpPage.value - 1) * httpPageSize.value,
      sort_by: httpSortBy.value,
      sort_order: httpSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    httpSessions.value = result.data || []
    httpTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 HTTP 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadICMPSessions() {
  try {
    loading.value = true
    const result = await QuerySessions({
      table: 'icmp',
      limit: icmpPageSize.value,
      offset: (icmpPage.value - 1) * icmpPageSize.value,
      sort_by: icmpSortBy.value,
      sort_order: icmpSortOrder.value,
      search_text: '',
      search_type: 'all'
    })
    icmpSessions.value = result.data || []
    icmpTotal.value = result.total || 0
  } catch (error) {
    console.error('加载 ICMP 会话失败:', error)
  } finally {
    loading.value = false
  }
}

async function loadSessionFlows() {
  try {
    loading.value = true
    console.log('Loading session flows...', {
      limit: sessionFlowPageSize.value,
      offset: (sessionFlowPage.value - 1) * sessionFlowPageSize.value,
      sort_by: sessionFlowSortBy.value,
      sort_order: sessionFlowSortOrder.value
    })
    const result = await QuerySessionFlows({
      limit: sessionFlowPageSize.value,
      offset: (sessionFlowPage.value - 1) * sessionFlowPageSize.value,
      sort_by: sessionFlowSortBy.value,
      sort_order: sessionFlowSortOrder.value
    })
    console.log('Session flows result:', result)
    sessionFlows.value = result.data || []
    sessionFlowTotal.value = result.total || 0
  } catch (error) {
    console.error('加载会话流失败:', error)
    ElMessage.error('加载会话流失败: ' + error)
  } finally {
    loading.value = false
  }
}

// 分页处理函数
function handleRawPageChange(page: number) {
  rawPage.value = page
  loadRawPackets()
}

function handleRawSizeChange(size: number) {
  rawPageSize.value = size
  rawPage.value = 1
  loadRawPackets()
}

function handleDNSPageChange(page: number) {
  dnsPage.value = page
  loadDNSSessions()
}

function handleDNSSizeChange(size: number) {
  dnsPageSize.value = size
  dnsPage.value = 1
  loadDNSSessions()
}

function handleHTTPPageChange(page: number) {
  httpPage.value = page
  loadHTTPSessions()
}

function handleHTTPSizeChange(size: number) {
  httpPageSize.value = size
  httpPage.value = 1
  loadHTTPSessions()
}

function handleICMPPageChange(page: number) {
  icmpPage.value = page
  loadICMPSessions()
}

function handleICMPSizeChange(size: number) {
  icmpPageSize.value = size
  icmpPage.value = 1
  loadICMPSessions()
}

function handleRawSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  rawSortBy.value = sortBy
  rawSortOrder.value = sortOrder
  rawPage.value = 1
  loadRawPackets()
}

function handleDNSSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  dnsSortBy.value = sortBy
  dnsSortOrder.value = sortOrder
  dnsPage.value = 1
  loadDNSSessions()
}

function handleHTTPSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  httpSortBy.value = sortBy
  httpSortOrder.value = sortOrder
  httpPage.value = 1
  loadHTTPSessions()
}

function handleICMPSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  icmpSortBy.value = sortBy
  icmpSortOrder.value = sortOrder
  icmpPage.value = 1
  loadICMPSessions()
}

function handleSessionFlowPageChange(page: number) {
  sessionFlowPage.value = page
  loadSessionFlows()
}

function handleSessionFlowSizeChange(size: number) {
  sessionFlowPageSize.value = size
  sessionFlowPage.value = 1
  loadSessionFlows()
}

function handleSessionFlowSortChange({ sortBy, sortOrder }: { sortBy: string, sortOrder: string }) {
  sessionFlowSortBy.value = sortBy
  sessionFlowSortOrder.value = sortOrder
  sessionFlowPage.value = 1  // 排序时重置到第一页
  loadSessionFlows()
}

// 告警标签切换处理
function handleAlertTabChange(tabName: string) {
  if (tabName === 'alert-logs' && alertLogsRef.value) {
    alertLogsRef.value.refresh()
  } else if (tabName === 'alert-rules' && alertRulesRef.value) {
    alertRulesRef.value.refresh()
  }
}

// 监听主标签切换，当切换到告警标签时自动刷新
watch(activeTab, (newTab) => {
  if (newTab === 'alert') {
    // 延迟一下确保子组件已挂载
    setTimeout(() => {
      if (alertSubTab.value === 'alert-logs' && alertLogsRef.value) {
        alertLogsRef.value.refresh()
      } else if (alertSubTab.value === 'alert-rules' && alertRulesRef.value) {
        alertRulesRef.value.refresh()
      }
    }, 100)
  }
})
</script>

<style scoped lang="scss">
.main-view {
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 16px;
  gap: 16px;
}

/* 合并的顶部栏 */
.header-merged {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 20px;
  background: var(--el-bg-color-overlay);
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  margin-bottom: 16px;
  
  .header-left {
    flex: 0 0 auto;
    
    h1 {
      font-size: 20px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
    }
  }
  
  .header-center {
    flex: 1;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
    padding: 0 20px;
    
    .metrics-compact {
      display: flex;
      gap: 8px;
      margin-left: 12px;
    }
  }

  .header-right {
    flex: 0 0 auto;
    display: flex;
    align-items: center;
  }
}

/* 保留旧样式以防兼容性问题 */
.header {
  display: none;
}

.control-panel {
  display: none;
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

<style>
/* 网卡选择下拉框自定义样式 */
.network-interface-select .el-select-dropdown__item {
  height: auto !important;
  line-height: normal !important;
  padding: 0 !important;
}
</style>
