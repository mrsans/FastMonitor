<template>
  <div class="dashboard-view dashboard-bigscreen-style">
    <!-- 科技感扫描线效果 -->
    <div class="scan-line"></div>

    <!-- 大屏标题 -->
    <div class="bigscreen-title">
      <div class="title-main">
        <img src="/bigscreen/img/icon01.png" class="title-icon" alt="icon">
        <span class="title-text">数据实时监控大屏</span>
        <div class="title-decoration">
          <span class="decoration-line"></span>
          <span class="decoration-dot"></span>
          <span class="decoration-line"></span>
        </div>
      </div>
      <div class="title-time">
        <span class="time-date">{{ currentDate }}</span>
        <span class="time-clock">{{ currentTime }}</span>
      </div>
      <!-- 全屏按钮 -->
      <el-button
        :icon="isFullscreen ? Close : FullScreen"
        @click="toggleFullscreen"
        circle
        type="primary"
        class="fullscreen-btn"
        :title="isFullscreen ? '退出全屏' : '全屏查看'"
      />
      <!-- 实时状态指示器 -->
      <div class="status-indicator">
        <span class="status-dot"></span>
        <span class="status-text">实时监控中</span>
      </div>
    </div>

    <!-- 核心指标卡片 -->
    <el-row :gutter="16" class="stats-row">
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00a8ff 0%, #0080ff 100%);">
              <el-icon :size="24"><DataAnalysis /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总数据包</div>
              <div class="stat-value">{{ (stats.total_packets || 0).toLocaleString() }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00d0ff 0%, #00a0ff 100%);">
              <el-icon :size="24"><DataLine /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">总流量</div>
              <div class="stat-value">{{ formatBytes(stats.total_bytes || 0) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00c8ff 0%, #0090ff 100%);">
              <el-icon :size="24"><Odometer /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">平均包大小</div>
              <div class="stat-value">{{ (stats.avg_packet_size || 0).toFixed(0) }}B</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00b8ff 0%, #0088ff 100%);">
              <el-icon :size="24"><Clock /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">抓包时长</div>
              <div class="stat-value">{{ formatDuration(stats.capture_time || 0) }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00e0ff 0%, #00b0ff 100%);">
              <el-icon :size="24"><Connection /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">会话流数</div>
              <div class="stat-value">{{ (stats.session_flows_count || 0).toLocaleString() }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="4">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-content">
            <div class="stat-icon" style="background: linear-gradient(135deg, #00f0ff 0%, #00c0ff 100%);">
              <el-icon :size="24"><TrendCharts /></el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-label">实时速率</div>
              <div class="stat-value">{{ formatBytes(stats.bytes_per_sec || 0) }}/s</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 告警统计行 -->
    <el-row :gutter="16" style="margin-top: 16px;">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card alert-stat-card alert-large-card" :class="{ 'has-alerts': alertStats.total_unack > 0 }">
          <div class="stat-content-large">
            <div class="stat-icon-large" style="background: linear-gradient(135deg, #ff4d4f 0%, #ff7875 100%);">
              <el-icon :size="40"><Warning /></el-icon>
            </div>
            <div class="stat-info-large">
              <div class="stat-label-large">未确认告警</div>
              <div class="stat-value-large alert-value">{{ (alertStats.total_unack || 0).toLocaleString() }}</div>
              <div class="stat-detail-large">
                <span class="detail-item critical">严重: {{ alertStats.critical || 0 }}</span>
                <span class="detail-item error">错误: {{ alertStats.error || 0 }}</span>
                <span class="detail-item warning">警告: {{ alertStats.warning || 0 }}</span>
                <span class="detail-item info">信息: {{ alertStats.info || 0 }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card alert-large-card">
          <div class="stat-content-large">
            <div class="stat-icon-large" style="background: linear-gradient(135deg, #52c41a 0%, #73d13d 100%);">
              <el-icon :size="40"><DocumentChecked /></el-icon>
            </div>
            <div class="stat-info-large">
              <div class="stat-label-large">启用规则</div>
              <div class="stat-value-large">{{ (alertStats.enabled_rules || 0).toLocaleString() }}</div>
              <div class="stat-detail-large">
                <span class="detail-item">今日告警: {{ alertStats.today_alerts || 0 }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover" class="alert-list-card">
          <template #header>
            <div class="card-header">
              <el-icon><Bell /></el-icon>
              <span>最近告警</span>
            </div>
          </template>
          <div class="alert-list">
            <div v-if="recentAlerts.length === 0" class="no-alerts">
              <el-icon :size="32"><SuccessFilled /></el-icon>
              <span>暂无告警</span>
            </div>
            <div v-else class="alert-item" v-for="alert in recentAlerts" :key="alert.id">
              <el-tag :type="getAlertLevelType(alert.alert_level)" size="small" effect="dark">
                {{ getAlertLevelText(alert.alert_level) }}
              </el-tag>
              <span class="alert-name">{{ alert.rule_name }}</span>
              <span class="alert-target">{{ alert.domain || alert.dst_ip || '-' }}</span>
              <span class="alert-time">{{ formatShortTime(alert.triggered_at) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px;">
      <!-- 协议分布饼图 -->
      <el-col :span="8">
        <el-card shadow="hover" header="协议分布" style="height: 400px;">
          <div ref="protocolChart" style="width: 100%; height: 320px;"></div>
        </el-card>
      </el-col>

      <!-- 流量趋势图 -->
      <el-col :span="8">
        <el-card shadow="hover" header="流量趋势" style="height: 400px;">
          <div ref="trafficChart" style="width: 100%; height: 320px;"></div>
        </el-card>
      </el-col>

      <!-- 告警统计 -->
      <el-col :span="8">
        <el-card shadow="hover" header="告警统计" style="height: 400px;">
          <div ref="alertChart" style="width: 100%; height: 320px;"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 第三行：Top统计 -->
    <el-row :gutter="16" style="margin-top: 20px;">
      <!-- Top 源IP -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Location /></el-icon>
              <span>Top 10 源IP（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_src_ips || []" height="280" size="small" stripe>
            <el-table-column prop="ip" label="IP地址" show-overflow-tooltip min-width="120" />
            <el-table-column prop="count" label="次数" width="70" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- Top 目标IP -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Pointer /></el-icon>
              <span>Top 10 目标IP（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_dst_ips || []" height="280" size="small" stripe>
            <el-table-column prop="ip" label="IP地址" show-overflow-tooltip min-width="120" />
            <el-table-column prop="count" label="次数" width="70" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- Top 端口（带服务识别） -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Grid /></el-icon>
              <span>Top 10 端口（按流量）</span>
            </div>
          </template>
          <el-table :data="stats.top_ports || []" height="280" size="small" stripe>
            <el-table-column prop="port" label="端口" width="60" sortable>
              <template #default="{ row }">
                <el-tag size="small" :type="getPortType(row.port)">{{ row.port }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="服务" min-width="80">
              <template #default="{ row }">
                <span style="color: var(--el-text-color-secondary); font-size: 12px;">
                  {{ getPortService(row.port) }}
                </span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="次数" width="60" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="bytes" label="流量" width="80" align="right" sortable>
              <template #default="{ row }">
                {{ formatBytes(row.bytes) }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 第四行：协议详细统计和域名 -->
    <el-row :gutter="16" style="margin-top: 20px;">
      <!-- 协议详细统计 -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Share /></el-icon>
              <span>协议详细统计</span>
            </div>
          </template>
          <el-table :data="protocolStats" height="280" size="small" stripe>
            <el-table-column prop="protocol" label="协议" width="80">
              <template #default="{ row }">
                <el-tag :type="row.type" size="small">{{ row.protocol }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="数量" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="percentage" label="占比" width="80" align="right">
              <template #default="{ row }">
                {{ row.percentage }}%
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- Top 域名 -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Coordinate /></el-icon>
              <span>Top 10 域名</span>
            </div>
          </template>
          <el-table :data="stats.top_domains || []" height="280" size="small" stripe>
            <el-table-column prop="domain" label="域名" show-overflow-tooltip min-width="150" />
            <el-table-column prop="count" label="访问次数" width="90" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <!-- 会话类型统计 -->
      <el-col :span="8">
        <el-card shadow="hover" class="stat-table-card">
          <template #header>
            <div class="card-header">
              <el-icon><Connection /></el-icon>
              <span>会话类型分布</span>
            </div>
          </template>
          <el-table :data="sessionStats" height="280" size="small" stripe>
            <el-table-column prop="type" label="类型" width="100">
              <template #default="{ row }">
                <el-tag :type="row.tagType" size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="会话数" align="right" sortable>
              <template #default="{ row }">
                {{ row.count.toLocaleString() }}
              </template>
            </el-table-column>
            <el-table-column prop="percentage" label="占比" width="80" align="right">
              <template #default="{ row }">
                {{ row.percentage }}%
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { FullScreen, Close } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
// import { GetDashboardStats, GetAlertStats, QueryAlertLogs } from '../../wailsjs/go/server/App'
import { GetDashboardStats, GetAlertStats, QueryAlertLogs } from '../../wailsjs/go/server/App.js'

const stats = ref<any>({})
const isFullscreen = ref(false)
const alertStats = ref<any>({
  critical: 0,
  error: 0,
  warning: 0,
  info: 0,
  enabled_rules: 0,
  today_alerts: 0,
  total_unack: 0
})
const recentAlerts = ref<any[]>([])
const protocolChart = ref<HTMLElement>()
const trafficChart = ref<HTMLElement>()
const alertChart = ref<HTMLElement>()

let protocolChartInstance: echarts.ECharts | null = null
let trafficChartInstance: echarts.ECharts | null = null
let alertChartInstance: echarts.ECharts | null = null
let refreshTimer: any = null
let timeTimer: any = null

const currentDate = ref('')
const currentTime = ref('')

// 更新时间
function updateTime() {
  const now = new Date()
  currentDate.value = now.toLocaleDateString('zh-CN')
  currentTime.value = now.toLocaleTimeString('zh-CN', { hour12: false })
}

// 计算协议详细统计
const protocolStats = computed(() => {
  const total = (stats.value.tcp_count || 0) + (stats.value.udp_count || 0) + (stats.value.icmp_count || 0) + (stats.value.other_count || 0)
  if (total === 0) return []
  
  const protocols = [
    { protocol: 'TCP', count: stats.value.tcp_count || 0, type: 'success' },
    { protocol: 'UDP', count: stats.value.udp_count || 0, type: 'warning' },
    { protocol: 'ICMP', count: stats.value.icmp_count || 0, type: 'danger' },
    { protocol: 'Other', count: stats.value.other_count || 0, type: 'info' },
  ]
  
  return protocols.map(p => ({
    ...p,
    percentage: ((p.count / total) * 100).toFixed(1)
  })).filter(p => p.count > 0)
})

// 计算会话类型统计
const sessionStats = computed(() => {
  const total = (stats.value.dns_sessions || 0) + (stats.value.http_sessions || 0) + (stats.value.icmp_sessions || 0)
  if (total === 0) return []
  
  const sessions = [
    { type: 'DNS', count: stats.value.dns_sessions || 0, tagType: 'warning' },
    { type: 'HTTP', count: stats.value.http_sessions || 0, tagType: 'success' },
    { type: 'ICMP', count: stats.value.icmp_sessions || 0, tagType: 'danger' },
  ]
  
  return sessions.map(s => ({
    ...s,
    percentage: ((s.count / total) * 100).toFixed(1)
  })).filter(s => s.count > 0)
})

onMounted(async () => {
  updateTime()
  await loadStats()
  initCharts()
  startAutoRefresh()
  timeTimer = setInterval(updateTime, 1000)
  
  // 添加全屏状态监听
  document.addEventListener('fullscreenchange', handleFullscreenChange)
})

onUnmounted(() => {
  stopAutoRefresh()
  if (timeTimer) clearInterval(timeTimer)
  
  // 移除全屏监听
  document.removeEventListener('fullscreenchange', handleFullscreenChange)
  
  if (protocolChartInstance) {
    protocolChartInstance.dispose()
  }
  if (trafficChartInstance) {
    trafficChartInstance.dispose()
  }
})

// 全屏功能
function toggleFullscreen() {
  const dashboardEl = document.querySelector('.dashboard-view')
  if (!dashboardEl) return
  
  if (!isFullscreen.value) {
    // 进入全屏
    if (dashboardEl.requestFullscreen) {
      dashboardEl.requestFullscreen()
    }
  } else {
    // 退出全屏
    if (document.exitFullscreen) {
      document.exitFullscreen()
    }
  }
}

// 监听全屏状态变化
function handleFullscreenChange() {
  isFullscreen.value = !!document.fullscreenElement
  // 全屏状态改变时调整图表大小
  setTimeout(() => {
    if (protocolChartInstance) protocolChartInstance.resize()
    if (topIPsChartInstance) topIPsChartInstance.resize()
    if (topPortsChartInstance) topPortsChartInstance.resize()
    if (topDomainsChartInstance) topDomainsChartInstance.resize()
    if (trafficChartInstance) trafficChartInstance.resize()
    if (alertChartInstance) alertChartInstance.resize()
  }, 100)
}

async function loadStats() {
  try {
    stats.value = await GetDashboardStats()
    alertStats.value = await GetAlertStats()
    
    // 加载最近5条告警
    const alertLogsResult = await QueryAlertLogs({
      acknowledged: false,
      limit: 5,
      offset: 0,
      sort_by: 'triggered_at',
      sort_order: 'desc'
    })
    recentAlerts.value = alertLogsResult.data || []
    
    updateCharts()
  } catch (error) {
    console.error('加载仪表盘数据失败:', error)
  }
}

function initCharts() {
  // 延迟初始化，确保 DOM 已渲染和数据加载
  setTimeout(() => {
    if (protocolChart.value) {
      protocolChartInstance = echarts.init(protocolChart.value)
      protocolChartInstance.resize() // 立即调整大小
    }
    if (trafficChart.value) {
      trafficChartInstance = echarts.init(trafficChart.value)
      trafficChartInstance.resize() // 立即调整大小
    }
    if (alertChart.value) {
      alertChartInstance = echarts.init(alertChart.value)
      alertChartInstance.resize() // 立即调整大小
    }
    updateCharts()
    
    // 再次延迟调整，确保布局稳定
    setTimeout(() => {
      protocolChartInstance?.resize()
      trafficChartInstance?.resize()
      alertChartInstance?.resize()
    }, 200)
    
    // 窗口大小改变时重新调整
    window.addEventListener('resize', () => {
      protocolChartInstance?.resize()
      trafficChartInstance?.resize()
      alertChartInstance?.resize()
    })
  }, 100)
}

function updateCharts() {
  if (!stats.value) return

  // 协议分布饼图（大屏风格）
  if (protocolChartInstance) {
    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'item',
        formatter: '{b}: {c} ({d}%)',
        backgroundColor: 'rgba(23, 62, 105, 0.9)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        textStyle: {
          color: '#f7ffff'
        }
      },
      legend: {
        orient: 'vertical',
        left: 'left',
        textStyle: {
          color: '#6fc7e3'
        }
      },
      series: [
        {
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['60%', '50%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 10,
            borderColor: '#0b2f55',
            borderWidth: 2
          },
          label: {
            show: true,
            formatter: '{b}: {c}',
            color: '#6fc7e3'
          },
          emphasis: {
            label: {
              show: true,
              fontSize: 16,
              fontWeight: 'bold',
              color: '#00ffea'
            },
            itemStyle: {
              shadowBlur: 15,
              shadowColor: 'rgba(0, 212, 255, 0.5)'
            }
          },
          data: [
            { 
              value: stats.value.tcp_count || 0, 
              name: 'TCP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#00d4ff' },
                  { offset: 1, color: '#0090ff' }
                ])
              }
            },
            { 
              value: stats.value.udp_count || 0, 
              name: 'UDP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#00ffea' },
                  { offset: 1, color: '#00b8ff' }
                ])
              }
            },
            { 
              value: stats.value.icmp_count || 0, 
              name: 'ICMP',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#a855f7' },
                  { offset: 1, color: '#6366f1' }
                ])
              }
            },
            { 
              value: stats.value.other_count || 0, 
              name: '其他',
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                  { offset: 0, color: '#10b981' },
                  { offset: 1, color: '#059669' }
                ])
              }
            }
          ]
        }
      ]
    }
    protocolChartInstance.setOption(option, true)
    protocolChartInstance.resize()
  }

  // 流量趋势图（大屏风格）
  if (trafficChartInstance) {
    const trend = stats.value.traffic_trend || []
    const timestamps = trend.length > 0 
      ? trend.map((p: any) => new Date(p.timestamp * 1000).toLocaleTimeString())
      : ['00:00', '00:01', '00:02']
    const packets = trend.length > 0
      ? trend.map((p: any) => p.packets)
      : [0, 0, 0]
    const bytes = trend.length > 0
      ? trend.map((p: any) => (p.bytes / 1024).toFixed(2))
      : [0, 0, 0]

    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'cross',
          crossStyle: {
            color: '#00d4ff'
          }
        },
        backgroundColor: 'rgba(23, 62, 105, 0.9)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        textStyle: {
          color: '#f7ffff'
        }
      },
      legend: {
        data: ['数据包', '流量(KB)'],
        top: 0,
        textStyle: {
          color: '#6fc7e3'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '10%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: timestamps,
        axisLabel: {
          rotate: 30,
          fontSize: 10,
          color: '#6fc7e3'
        },
        axisLine: {
          lineStyle: {
            color: 'rgba(92, 154, 227, 0.5)'
          }
        }
      },
      yAxis: [
        {
          type: 'value',
          name: '数据包',
          position: 'left',
          nameTextStyle: {
            color: '#6fc7e3'
          },
          axisLabel: {
            color: '#6fc7e3'
          },
          axisLine: {
            lineStyle: {
              color: 'rgba(92, 154, 227, 0.5)'
            }
          },
          splitLine: {
            lineStyle: {
              color: 'rgba(92, 154, 227, 0.1)'
            }
          }
        },
        {
          type: 'value',
          name: '流量(KB)',
          position: 'right',
          nameTextStyle: {
            color: '#6fc7e3'
          },
          axisLabel: {
            color: '#6fc7e3'
          },
          axisLine: {
            lineStyle: {
              color: 'rgba(92, 154, 227, 0.5)'
            }
          },
          splitLine: {
            show: false
          }
        }
      ],
      series: [
        {
          name: '数据包',
          type: 'line',
          data: packets,
          smooth: true,
          lineStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: '#00d4ff' },
              { offset: 1, color: '#00ffea' }
            ]),
            width: 2
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(0, 212, 255, 0.3)' },
              { offset: 1, color: 'rgba(0, 212, 255, 0.05)' }
            ])
          }
        },
        {
          name: '流量(KB)',
          type: 'line',
          yAxisIndex: 1,
          data: bytes,
          smooth: true,
          lineStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: '#a855f7' },
              { offset: 1, color: '#ec4899' }
            ]),
            width: 2
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(168, 85, 247, 0.3)' },
              { offset: 1, color: 'rgba(168, 85, 247, 0.05)' }
            ])
          }
        }
      ]
    }
    trafficChartInstance.setOption(option, true)
    trafficChartInstance.resize()
  }

  // 告警统计柱状图
  if (alertChartInstance && alertStats.value) {
    const option = {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        },
        backgroundColor: 'rgba(23, 62, 105, 0.9)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        textStyle: {
          color: '#f7ffff'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        top: '15%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: ['严重', '错误', '警告', '信息'],
        axisLabel: {
          color: '#6fc7e3',
          fontSize: 12
        },
        axisLine: {
          lineStyle: {
            color: 'rgba(92, 154, 227, 0.5)'
          }
        }
      },
      yAxis: {
        type: 'value',
        name: '数量',
        nameTextStyle: {
          color: '#6fc7e3'
        },
        axisLabel: {
          color: '#6fc7e3'
        },
        axisLine: {
          lineStyle: {
            color: 'rgba(92, 154, 227, 0.5)'
          }
        },
        splitLine: {
          lineStyle: {
            color: 'rgba(92, 154, 227, 0.2)',
            type: 'dashed'
          }
        }
      },
      series: [
        {
          name: '告警数量',
          type: 'bar',
          barWidth: '60%',
          data: [
            {
              value: alertStats.value.critical || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ff4d4f' },
                  { offset: 1, color: '#cf1322' }
                ])
              }
            },
            {
              value: alertStats.value.error || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ff7a45' },
                  { offset: 1, color: '#d4380d' }
                ])
              }
            },
            {
              value: alertStats.value.warning || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#ffc53d' },
                  { offset: 1, color: '#faad14' }
                ])
              }
            },
            {
              value: alertStats.value.info || 0,
              itemStyle: {
                color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                  { offset: 0, color: '#40a9ff' },
                  { offset: 1, color: '#096dd9' }
                ])
              }
            }
          ],
          label: {
            show: true,
            position: 'top',
            color: '#f7ffff',
            fontSize: 12,
            fontWeight: 'bold'
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowColor: 'rgba(0, 212, 255, 0.5)'
            }
          }
        }
      ]
    }
    alertChartInstance.setOption(option, true)
    alertChartInstance.resize()
  }
}

function startAutoRefresh() {
  refreshTimer = setInterval(loadStats, 3000) // 每3秒刷新
}

function stopAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return seconds + ' 秒'
  if (seconds < 3600) return Math.floor(seconds / 60) + ' 分钟'
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' 小时'
  return Math.floor(seconds / 86400) + ' 天'
}

function formatShortTime(timestamp: string) {
  if (!timestamp) return '-'
  const date = new Date(timestamp)
  const now = new Date()
  const isToday = date.toDateString() === now.toDateString()
  
  if (isToday) {
    return date.toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    })
  }
  
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  })
}

function getAlertLevelType(level: string) {
  const types: any = {
    critical: 'danger',
    error: 'danger',
    warning: 'warning',
    info: 'info'
  }
  return types[level] || ''
}

function getAlertLevelText(level: string) {
  const texts: any = {
    critical: '严重',
    error: '错误',
    warning: '警告',
    info: '信息'
  }
  return texts[level] || level
}

// 端口服务识别
function getPortService(port: number): string {
  const services: Record<number, string> = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
  }
  return services[port] || '未知'
}

// 端口类型标签
function getPortType(port: number): string {
  if (port < 1024) return 'success'  // 系统端口
  if (port < 49152) return 'warning' // 注册端口
  return 'info' // 动态端口
}
</script>

<style scoped lang="scss">
/* 引入大屏字体 */
@font-face {
  font-family: 'DigitalFont';
  src: url('/bigscreen/font/DS-DIGI.TTF');
}

@font-face {
  font-family: 'DigitalFontBold';
  src: url('/bigscreen/font/DS-DIGIB.TTF');
}

.dashboard-view {
  padding: 24px;
  height: calc(100vh - 200px);
  overflow-y: auto;
  
  &.dashboard-bigscreen-style {
    background: url('/bigscreen/img/bg.png') no-repeat center center;
    background-size: cover;
    background-attachment: fixed;
    border-radius: 12px;
    position: relative;
    
    /* 深色遮罩增强对比度 */
    &::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(10, 25, 41, 0.85);
      border-radius: 12px;
      pointer-events: none;
      z-index: 0;
    }
    
    /* 确保内容在遮罩之上 */
    > * {
      position: relative;
      z-index: 1;
    }
  }
}

/* 大屏标题区域 */
.bigscreen-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 12px 20px;
  background: linear-gradient(90deg, rgba(0, 85, 150, 0.6) 0%, rgba(0, 120, 200, 0.3) 50%, rgba(0, 85, 150, 0.6) 100%);
  border: 1px solid rgba(0, 180, 255, 0.5);
  border-radius: 8px;
  box-shadow: 0 0 20px rgba(0, 180, 255, 0.4), inset 0 0 15px rgba(0, 180, 255, 0.1);
  position: relative;
  overflow: hidden;
  
  /* 标题背景流光效果 */
  &::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: linear-gradient(45deg, transparent, rgba(0, 180, 255, 0.15), transparent);
    animation: title-flow 6s linear infinite;
  }
  
  .title-main {
    flex: 1;
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    gap: 12px;
    
    .title-icon {
      width: 32px;
      height: 32px;
      filter: drop-shadow(0 0 8px rgba(0, 180, 255, 0.6));
      animation: icon-pulse 2s ease-in-out infinite;
    }
    
    .title-text {
      font-size: 26px;
      font-weight: bold;
      font-family: 'DigitalFontBold', 'Microsoft YaHei', sans-serif;
      background: linear-gradient(135deg, #00b4ff 0%, #00e0ff 50%, #0090ff 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      filter: drop-shadow(0 0 12px rgba(0, 180, 255, 0.6));
      letter-spacing: 2px;
    }
    
    .title-decoration {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      
      .decoration-line {
        height: 2px;
        width: 60px;
        background: linear-gradient(90deg, #00d4ff 0%, transparent 100%);
        border-radius: 1px;
      }
      
      .decoration-dot {
        width: 6px;
        height: 6px;
        background: #00ffea;
        border-radius: 50%;
        box-shadow: 0 0 10px rgba(0, 255, 234, 0.8);
        animation: pulse-dot 2s infinite;
      }
    }
  }
  
  .title-time {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 5px;
    position: relative;
    z-index: 1;
    
    .time-date {
      font-size: 16px;
      color: #9cc2ef;
      font-weight: 500;
    }
    
    .time-clock {
      font-size: 24px;
      font-family: 'DigitalFont', monospace;
      color: #00ffea;
      filter: drop-shadow(0 2px 4px rgba(0, 255, 234, 0.5));
      letter-spacing: 2px;
    }
  }
  
  /* 全屏按钮 */
  .fullscreen-btn {
    position: relative;
    z-index: 1;
    background: linear-gradient(135deg, #0090ff 0%, #00d4ff 100%);
    border: none;
    box-shadow: 0 0 10px rgba(0, 180, 255, 0.5);
    transition: all 0.3s ease;
    
    &:hover {
      background: linear-gradient(135deg, #00b4ff 0%, #00ffea 100%);
      box-shadow: 0 0 20px rgba(0, 255, 234, 0.8);
      transform: scale(1.1);
    }
    
    :deep(.el-icon) {
      color: white;
      font-size: 20px;
    }
  }
}

@keyframes title-flow {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

@keyframes pulse-dot {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.6;
    transform: scale(1.2);
  }
}

/* 科技感扫描线 */
.scan-line {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent 0%, #00d4ff 50%, transparent 100%);
  opacity: 0.6;
  animation: scan 3s linear infinite;
  z-index: 10;
  pointer-events: none;
}

@keyframes scan {
  0% {
    top: 0;
    opacity: 0;
  }
  10% {
    opacity: 0.6;
  }
  90% {
    opacity: 0.6;
  }
  100% {
    top: 100%;
    opacity: 0;
  }
}

/* 图标脉冲动画 */
@keyframes icon-pulse {
  0%, 100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.8;
    transform: scale(1.05);
  }
}

/* 实时状态指示器 */
.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: rgba(0, 212, 255, 0.1);
  border: 1px solid rgba(0, 212, 255, 0.3);
  border-radius: 20px;
  margin-left: 20px;
  
  .status-dot {
    width: 10px;
    height: 10px;
    background: #00ff00;
    border-radius: 50%;
    box-shadow: 0 0 15px rgba(0, 255, 0, 0.8);
    animation: pulse-status 1.5s infinite;
  }
  
  .status-text {
    font-size: 14px;
    color: #00ffea;
    font-weight: 500;
  }
}

@keyframes pulse-status {
  0%, 100% {
    opacity: 1;
    box-shadow: 0 0 15px rgba(0, 255, 0, 0.8);
  }
  50% {
    opacity: 0.5;
    box-shadow: 0 0 5px rgba(0, 255, 0, 0.4);
  }
}

.stats-row {
  margin-bottom: 20px;
}

.stat-table-card {
  :deep(.el-card__header) {
    padding: 12px 16px;
    background: var(--el-fill-color-light);
    border-bottom: 1px solid var(--el-border-color);
  }
  
  .card-header {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 600;
    font-size: 14px;
    
    .el-icon {
      font-size: 16px;
      color: var(--el-color-primary);
    }
  }
}

.stat-card {
  transition: all 0.3s ease;
  border-radius: 12px;
  background: rgba(15, 50, 90, 0.5) !important;
  border: 1px solid rgba(0, 150, 220, 0.4) !important;
  position: relative;
  overflow: hidden;
  
  /* 卡片内部发光边框 */
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00b4ff, transparent);
    animation: card-shine 3s infinite;
  }
  
  &:hover {
    transform: translateY(-4px);
    box-shadow: 0 0 25px rgba(0, 180, 255, 0.5) !important;
    border-color: rgba(0, 180, 255, 0.7) !important;
    
    &::before {
      animation: card-shine 1s infinite;
    }
  }
  
  :deep(.el-card__body) {
    padding: 20px;
  }
}

@keyframes card-shine {
  0% {
    left: -100%;
  }
  100% {
    left: 200%;
  }
}

.stat-content {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon {
  width: 56px;
  height: 56px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-label {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  font-family: 'DigitalFont', 'Consolas', monospace;
  background: linear-gradient(135deg, #00b8ff 0%, #00e0ff 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  filter: drop-shadow(0 2px 4px rgba(0, 180, 255, 0.6));
}

/* 告警卡片特殊样式 */
.alert-stat-card {
  &.has-alerts {
    animation: alert-pulse 2s infinite;
    border-color: rgba(255, 77, 79, 0.6) !important;
    
    &::before {
      background: linear-gradient(90deg, transparent, #ff4d4f, transparent);
    }
  }
  
  .alert-value {
    background: linear-gradient(135deg, #ff4d4f 0%, #ff7875 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    filter: drop-shadow(0 2px 4px rgba(255, 77, 79, 0.6));
  }
}

@keyframes alert-pulse {
  0%, 100% {
    box-shadow: 0 0 10px rgba(255, 77, 79, 0.3);
  }
  50% {
    box-shadow: 0 0 20px rgba(255, 77, 79, 0.6);
  }
}

/* 告警大卡片样式 */
.alert-large-card {
  height: 160px;
  
  :deep(.el-card__body) {
    padding: 24px;
    height: 100%;
  }
}

.stat-content-large {
  display: flex;
  align-items: center;
  gap: 20px;
  height: 100%;
}

.stat-icon-large {
  width: 80px;
  height: 80px;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  flex-shrink: 0;
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
}

.stat-info-large {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.stat-label-large {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-bottom: 8px;
}

.stat-value-large {
  font-size: 36px;
  font-weight: 700;
  font-family: 'DigitalFont', 'Consolas', monospace;
  background: linear-gradient(135deg, #00b8ff 0%, #00e0ff 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  filter: drop-shadow(0 2px 4px rgba(0, 180, 255, 0.6));
  line-height: 1.2;
  margin-bottom: 8px;
}

.stat-detail-large {
  display: flex;
  gap: 16px;
  font-size: 13px;
  flex-wrap: wrap;
  
  .detail-item {
    color: #70d0ff;
    white-space: nowrap;
    
    &.critical {
      color: #ff4d4f;
      font-weight: 600;
    }
    &.error {
      color: #ff7875;
    }
    &.warning {
      color: #ffc53d;
    }
    &.info {
      color: #40a9ff;
    }
  }
}

.alert-list-card {
  height: 160px;
  
  :deep(.el-card__body) {
    padding: 0;
    height: calc(100% - 56px);
    overflow: hidden;
  }
}

.alert-list {
  height: 100%;
  overflow-y: auto;
  padding: 12px;
  
  &::-webkit-scrollbar {
    width: 6px;
  }
  
  &::-webkit-scrollbar-thumb {
    background: rgba(0, 150, 220, 0.5);
    border-radius: 3px;
  }
  
  &::-webkit-scrollbar-track {
    background: rgba(15, 45, 80, 0.3);
  }
}

.no-alerts {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #52c41a;
  gap: 8px;
}

.alert-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px;
  background: rgba(15, 45, 80, 0.3);
  border: 1px solid rgba(0, 150, 220, 0.2);
  border-radius: 6px;
  margin-bottom: 8px;
  transition: all 0.3s ease;
  
  &:hover {
    background: rgba(0, 150, 220, 0.2);
    border-color: rgba(0, 150, 220, 0.4);
    transform: translateX(4px);
  }
  
  .alert-name {
    flex: 1;
    color: #00e0ff;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  
  .alert-target {
    color: #70d0ff;
    font-size: 12px;
    max-width: 150px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  
  .alert-time {
    color: #909399;
    font-size: 12px;
    min-width: 60px;
    text-align: right;
  }
}

/* 图表卡片美化 */
:deep(.el-card) {
  border-radius: 12px;
  background: rgba(15, 50, 90, 0.5) !important;
  border: 1px solid rgba(0, 150, 220, 0.4) !important;
  
  .el-card__header {
    background: rgba(0, 100, 180, 0.3) !important;
    border-bottom: 1px solid rgba(0, 150, 220, 0.4) !important;
    font-weight: 600;
    font-size: 16px;
    color: #00b8ff !important;
    text-shadow: 0 0 10px rgba(0, 180, 255, 0.6);
  }
}

/* 表格美化 - 深色大屏风格 */
:deep(.el-table) {
  background: rgba(15, 45, 80, 0.4) !important;
  --el-table-border-color: rgba(0, 150, 200, 0.3);
  --el-table-bg-color: rgba(15, 45, 80, 0.4);
  --el-table-tr-bg-color: rgba(15, 45, 80, 0.3);
  --el-table-row-hover-bg-color: rgba(0, 150, 200, 0.2);
  color: #70d0ff !important;
  
  .el-table__header {
    font-weight: 600;
    
    th {
      background: rgba(0, 100, 180, 0.4) !important;
      color: #00d4ff !important;
      border-bottom: 1px solid rgba(0, 180, 255, 0.4) !important;
    }
  }
  
  .el-table__body {
    tr {
      background: rgba(15, 45, 80, 0.3) !important;
      
      td {
        color: #70d0ff !important;
        border-bottom: 1px solid rgba(0, 150, 200, 0.2) !important;
        
        /* 强制覆盖所有可能的白色文字 */
        * {
          color: #70d0ff !important;
        }
      }
      
      &:hover > td {
        background-color: rgba(0, 150, 200, 0.25) !important;
        color: #00e0ff !important;
        
        * {
          color: #00e0ff !important;
        }
      }
      
      &.el-table__row--striped {
        background: rgba(15, 45, 80, 0.35) !important;
        
        td {
          background: rgba(15, 45, 80, 0.35) !important;
        }
      }
    }
  }
  
  /* 数字列增强 */
  .cell {
    font-family: 'DigitalFont', 'Consolas', monospace;
    color: #70d0ff !important;
  }
  
  /* Tag 标签样式覆盖 */
  .el-tag {
    background: rgba(0, 150, 200, 0.3) !important;
    border-color: rgba(0, 180, 255, 0.5) !important;
    color: #00d4ff !important;
  }
}
</style>


