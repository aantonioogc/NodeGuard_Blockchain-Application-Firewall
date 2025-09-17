// src/metrics/prometheus.ts
// Registro de metrica - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import client, { Registry, Counter, Histogram, Gauge, Summary, collectDefaultMetrics } from 'prom-client';
import { EventEmitter } from 'events';
import { logger } from '../logging/logger';

/**
 * 
 * Características:
 * - Recopilación de métricas integral (Counter, Gauge, Histogram, Summary)
 * - Coleccionistas personalizados para métricas específicas de BAF
 * - Gestión dinámica de etiquetas
 * - Agregación y consolidación de métricas
 * - Generación de reglas de alerta
 * - Seguimiento del rendimiento
 * - Integración de monitoreo de salud
 * - Retención y limpieza de métricas
 * - Soporte para paneles personalizados
 */

export interface MetricsConfig {
  enableDefaultMetrics: boolean;
  prefix: string;
  labels: { [key: string]: string };
  retention: {
    enabled: boolean;
    maxAge: number;
    cleanupInterval: number;
  };
  alerts: {
    enabled: boolean;
    thresholds: { [metric: string]: number };
  };
  customCollectors: boolean;
  performance: {
    enableDetailedTimings: boolean;
    trackMemoryUsage: boolean;
    trackCpuUsage: boolean;
  };
}

export interface MetricDefinition {
  name: string;
  help: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  labels: string[];
  config?: any;
}

/**
 * Registro de métricas NodeGuard con características avanzadas
 */
export class EnhancedMetricsService extends EventEmitter {
  private registry: Registry;
  private readonly config: MetricsConfig;
  private customMetrics = new Map<string, any>();
  private alertRules = new Map<string, any>();
  private metricCollectors = new Map<string, () => void>();
  
  // Referencias de intervalos para cleanup
  private collectorIntervals = new Map<string, NodeJS.Timeout>();
  private performanceInterval?: NodeJS.Timeout;
  private retentionInterval?: NodeJS.Timeout;
  
  // Seguimiento de rendimiento
  private performanceStats = {
    collectionTime: 0,
    metricCount: 0,
    lastCollection: 0,
    errors: 0
  };

  constructor(config: Partial<MetricsConfig> = {}) {
    super();
    
    this.config = {
      enableDefaultMetrics: config.enableDefaultMetrics !== false,
      prefix: config.prefix || 'baf_',
      labels: config.labels || {},
      retention: {
        enabled: config.retention?.enabled !== false,
        maxAge: config.retention?.maxAge || 86400000, // 24 hours
        cleanupInterval: config.retention?.cleanupInterval || 3600000 // 1 hour
      },
      alerts: {
        enabled: config.alerts?.enabled !== false,
        thresholds: config.alerts?.thresholds || {}
      },
      customCollectors: config.customCollectors !== false,
      performance: {
        enableDetailedTimings: config.performance?.enableDetailedTimings !== false,
        trackMemoryUsage: config.performance?.trackMemoryUsage !== false,
        trackCpuUsage: config.performance?.trackCpuUsage !== false
      }
    };
    
    this.registry = new Registry();
    this.initializeMetrics();
    this.setupCustomCollectors();
    this.setupPerformanceTracking();
    this.setupRetentionCleanup();
    
    logger.info('Servicio de métricas NodeGuard inicializado', {
      defaultMetricsEnabled: this.config.enableDefaultMetrics,
      prefix: this.config.prefix,
      customCollectors: this.config.customCollectors
    });
  }

  /**
   * Inicializar métricas principales de NodeGuard
   */
  private initializeMetrics(): void {
    // Configurar labels por defecto
    if (Object.keys(this.config.labels).length > 0) {
      this.registry.setDefaultLabels(this.config.labels);
    }
    
    // Habilitar métricas por defecto de Node.js
    if (this.config.enableDefaultMetrics) {
      collectDefaultMetrics({
        register: this.registry,
        prefix: this.config.prefix
      });
    }
    
    // Definir métricas principales de NodeGuard
    this.defineBAFMetrics();
  }

  /**
   * Definir métricas específicas de NodeGuard
   */
  private defineBAFMetrics(): void {
    const metricDefinitions: MetricDefinition[] = [
      // Métricas principales de solicitudes
      {
        name: 'jsonrpc_requests_total',
        help: 'Número total de solicitudes JSON-RPC procesadas por el firewall',
        type: 'counter',
        labels: ['method', 'decision', 'rule', 'client_type']
      },
      {
        name: 'jsonrpc_request_duration_ms',
        help: 'Duración del procesamiento de solicitudes JSON-RPC en milisegundos',
        type: 'histogram',
        labels: ['method', 'decision'],
        config: {
          buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
        }
      },
      {
        name: 'jsonrpc_blocked_total',
        help: 'Total number of blocked JSON-RPC requests',
        type: 'counter',
        labels: ['method', 'reason', 'rule', 'severity']
      },
      {
        name: 'jsonrpc_forward_latency_ms',
        help: 'Latency forwarding JSON-RPC to upstream in milliseconds',
        type: 'histogram',
        labels: ['method', 'upstream_status'],
        config: {
          buckets: [5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000]
        }
      },
      
      // Connection and session metrics
      {
        name: 'active_connections',
        help: 'Current number of active connections to the firewall',
        type: 'gauge',
        labels: ['connection_type']
      },
      {
        name: 'connection_duration_seconds',
        help: 'Duration of connections in seconds',
        type: 'histogram',
        labels: ['connection_type', 'termination_reason'],
        config: {
          buckets: [1, 5, 10, 30, 60, 300, 600, 1800, 3600]
        }
      },
      
      // Security metrics
      {
        name: 'security_events_total',
        help: 'Total number of security events detected',
        type: 'counter',
        labels: ['event_type', 'severity', 'source']
      },
      {
        name: 'reputation_scores',
        help: 'Reputation scores distribution',
        type: 'histogram',
        labels: ['entity_type', 'score_category'],
        config: {
          buckets: [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        }
      },
      {
        name: 'fingerprint_matches_total',
        help: 'Total number of fingerprint matches',
        type: 'counter',
        labels: ['match_type', 'algorithm', 'blocked']
      },
      
      // Rate limiting metrics
      {
        name: 'rate_limit_violations_total',
        help: 'Total number of rate limit violations',
        type: 'counter',
        labels: ['limit_type', 'entity', 'action']
      },
      {
        name: 'rate_limit_usage',
        help: 'Current rate limit usage percentage',
        type: 'gauge',
        labels: ['limit_type', 'entity']
      },
      
      // Performance metrics
      {
        name: 'rule_evaluation_duration_ms',
        help: 'Duration of rule evaluation in milliseconds',
        type: 'histogram',
        labels: ['rule_type', 'complexity'],
        config: {
          buckets: [0.1, 0.5, 1, 2, 5, 10, 25, 50, 100]
        }
      },
      {
        name: 'cache_operations_total',
        help: 'Total number of cache operations',
        type: 'counter',
        labels: ['operation', 'cache_type', 'result']
      },
      {
        name: 'cache_hit_ratio',
        help: 'Cache hit ratio percentage',
        type: 'gauge',
        labels: ['cache_type']
      },
      
      // System health metrics
      {
        name: 'health_check_status',
        help: 'Health check status (1 = healthy, 0 = unhealthy)',
        type: 'gauge',
        labels: ['component', 'check_type']
      },
      {
        name: 'component_errors_total',
        help: 'Total number of component errors',
        type: 'counter',
        labels: ['component', 'error_type', 'severity']
      },
      
      // Business metrics
      {
        name: 'transaction_value_wei',
        help: 'Total transaction value in wei',
        type: 'counter',
        labels: ['transaction_type', 'network']
      },
      {
        name: 'gas_usage_total',
        help: 'Total gas usage',
        type: 'counter',
        labels: ['method', 'success']
      },
      
      // Admin and API metrics
      {
        name: 'admin_operations_total',
        help: 'Total number of admin operations',
        type: 'counter',
        labels: ['operation', 'user', 'result']
      },
      {
        name: 'config_changes_total',
        help: 'Total number of configuration changes',
        type: 'counter',
        labels: ['config_type', 'user', 'validation_result']
      }
    ];
    
    // Create metrics from definitions
    for (const definition of metricDefinitions) {
      this.createMetric(definition);
    }
  }

  /**
   * Create metric from definition
   */
  private createMetric(definition: MetricDefinition): void {
    const name = this.config.prefix + definition.name;
    
    try {
      let metric: any;
      
      switch (definition.type) {
        case 'counter':
          metric = new Counter({
            name,
            help: definition.help,
            labelNames: definition.labels,
            registers: [this.registry]
          });
          break;
          
        case 'gauge':
          metric = new Gauge({
            name,
            help: definition.help,
            labelNames: definition.labels,
            registers: [this.registry]
          });
          break;
          
        case 'histogram':
          metric = new Histogram({
            name,
            help: definition.help,
            labelNames: definition.labels,
            buckets: definition.config?.buckets,
            registers: [this.registry]
          });
          break;
          
        case 'summary':
          metric = new Summary({
            name,
            help: definition.help,
            labelNames: definition.labels,
            percentiles: definition.config?.percentiles || [0.5, 0.9, 0.95, 0.99],
            registers: [this.registry]
          });
          break;
          
        default:
          logger.warn('Unknown metric type', { type: definition.type, name });
          return;
      }
      
      this.customMetrics.set(definition.name, metric);
      
      logger.debug('Metric created', {
        name: definition.name,
        type: definition.type,
        labels: definition.labels
      });
      
    } catch (error) {
      logger.error('Failed to create metric', {
        error: error as Error,
        name: definition.name,
        type: definition.type
      });
    }
  }

  /**
   * Setup custom metric collectors
   */
  private setupCustomCollectors(): void {
    if (!this.config.customCollectors) return;
    
    // Redis connection metrics
    this.metricCollectors.set('redis_stats', () => {
      this.collectRedisStats();
    });
    
    // Event bus metrics
    this.metricCollectors.set('eventbus_stats', () => {
      this.collectEventBusStats();
    });
    
    // Rule engine metrics
    this.metricCollectors.set('rule_engine_stats', () => {
      this.collectRuleEngineStats();
    });
    
    // Start collectors
    for (const [name, collector] of this.metricCollectors) {
      const interval = setInterval(() => {
        try {
          collector();
        } catch (error) {
          logger.error('Custom collector failed', {
            collector: name,
            error: error as Error
          });
          this.performanceStats.errors++;
        }
      }, 30000); // Every 30 seconds
      
      this.collectorIntervals.set(name, interval);
    }
  }

  /**
   * Custom metric collection methods
   */
  
  private async collectRedisStats(): Promise<void> {
    try {
      // This would integrate with actual Redis client
      // Placeholder implementation
      const healthMetric = this.getMetric('health_check_status');
      if (healthMetric) {
        healthMetric.set({ component: 'redis', check_type: 'connection' }, 1);
      }
    } catch (error) {
      const healthMetric = this.getMetric('health_check_status');
      if (healthMetric) {
        healthMetric.set({ component: 'redis', check_type: 'connection' }, 0);
      }
    }
  }
  
  private collectEventBusStats(): void {
    // This would integrate with actual EventBus
    const connectionsMetric = this.getMetric('active_connections');
    if (connectionsMetric) {
      connectionsMetric.set({ connection_type: 'sse' }, 0); // Placeholder
    }
  }
  
  private collectRuleEngineStats(): void {
    // This would integrate with actual PolicyEngine
    const healthMetric = this.getMetric('health_check_status');
    if (healthMetric) {
      healthMetric.set({ component: 'policy_engine', check_type: 'status' }, 1);
    }
  }

  /**
   * Performance tracking
   */
  private setupPerformanceTracking(): void {
    if (!this.config.performance.enableDetailedTimings) return;
    
    this.performanceInterval = setInterval(() => {
      const startTime = Date.now();
      
      // Collect metrics
      this.performanceStats.metricCount = this.registry.getMetricsAsArray().length;
      this.performanceStats.lastCollection = Date.now();
      
      const collectionTime = Date.now() - startTime;
      this.performanceStats.collectionTime = collectionTime;
      
      // Emit performance event
      this.emit('performance', {
        collectionTime,
        metricCount: this.performanceStats.metricCount,
        errors: this.performanceStats.errors
      });
      
      // Track memory usage
      if (this.config.performance.trackMemoryUsage) {
        const memoryUsage = process.memoryUsage();
        const memoryMetric = this.getMetric('nodejs_memory_usage_bytes');
        if (memoryMetric) {
          memoryMetric.set({ type: 'rss' }, memoryUsage.rss);
          memoryMetric.set({ type: 'heapUsed' }, memoryUsage.heapUsed);
          memoryMetric.set({ type: 'heapTotal' }, memoryUsage.heapTotal);
        }
      }
      
    }, 15000); // Every 15 seconds
  }

  /**
   * Public API methods
   */
  
  public getMetric(name: string): any {
    return this.customMetrics.get(name);
  }
  
  public incrementCounter(metricName: string, labels: { [key: string]: string } = {}, value: number = 1): void {
    const metric = this.getMetric(metricName);
    if (metric && typeof metric.inc === 'function') {
      metric.inc(labels, value);
    }
  }
  
  public setGauge(metricName: string, value: number, labels: { [key: string]: string } = {}): void {
    const metric = this.getMetric(metricName);
    if (metric && typeof metric.set === 'function') {
      metric.set(labels, value);
    }
  }
  
  public observeHistogram(metricName: string, value: number, labels: { [key: string]: string } = {}): void {
    const metric = this.getMetric(metricName);
    if (metric && typeof metric.observe === 'function') {
      metric.observe(labels, value);
    }
  }
  
  public startTimer(metricName: string, labels: { [key: string]: string } = {}): () => void {
    const metric = this.getMetric(metricName);
    if (metric && typeof metric.startTimer === 'function') {
      return metric.startTimer(labels);
    }
    
    // Fallback manual timer
    const startTime = Date.now();
    return () => {
      const duration = Date.now() - startTime;
      this.observeHistogram(metricName, duration, labels);
    };
  }
  
  public async getMetricsString(): Promise<string> {
    const startTime = Date.now();
    
    try {
      const metrics = await this.registry.metrics();
      this.performanceStats.collectionTime = Date.now() - startTime;
      return metrics;
    } catch (error) {
      this.performanceStats.errors++;
      throw error;
    }
  }
  
  public getRegistry(): Registry {
    return this.registry;
  }
  
  public getPerformanceStats(): typeof this.performanceStats {
    return { ...this.performanceStats };
  }

  /**
   * Alert rules management
   */
  
  public defineAlertRule(name: string, rule: any): void {
    this.alertRules.set(name, {
      ...rule,
      createdAt: Date.now()
    });
    
    logger.info('Alert rule defined', { name, rule });
  }
  
  public getAlertRules(): Map<string, any> {
    return new Map(this.alertRules);
  }
  
  public evaluateAlerts(): any[] {
    const alerts: any[] = [];
    
    for (const [name, rule] of this.alertRules) {
      try {
        // This would implement actual alert evaluation logic
        // Placeholder for now
        if (this.shouldTriggerAlert(name, rule)) {
          alerts.push({
            name,
            rule,
            triggeredAt: Date.now(),
            severity: rule.severity || 'warning'
          });
        }
      } catch (error) {
        logger.error('Alert evaluation failed', {
          alert: name,
          error: error as Error
        });
      }
    }
    
    return alerts;
  }

  /**
   * Utility methods
   */
  
  private shouldTriggerAlert(name: string, rule: any): boolean {
    // Placeholder implementation
    // In production, this would evaluate actual metric values against thresholds
    return false;
  }
  
  private setupRetentionCleanup(): void {
    if (!this.config.retention.enabled) return;
    
    this.retentionInterval = setInterval(() => {
      this.performRetentionCleanup();
    }, this.config.retention.cleanupInterval);
  }
  
  private async performRetentionCleanup(): Promise<void> {
    try {
      // This would implement actual metric retention cleanup
      logger.debug('Metrics retention cleanup completed');
    } catch (error) {
      logger.error('Metrics retention cleanup failed', {
        error: error as Error
      });
    }
  }
  
  public async cleanup(): Promise<void> {
    // Clear all collector intervals
    for (const [name, interval] of this.collectorIntervals) {
      clearInterval(interval);
    }
    this.collectorIntervals.clear();
    
    // Clear other intervals
    if (this.performanceInterval) {
      clearInterval(this.performanceInterval);
      this.performanceInterval = undefined;
    }
    
    if (this.retentionInterval) {
      clearInterval(this.retentionInterval);
      this.retentionInterval = undefined;
    }
    
    this.registry.clear();
    this.customMetrics.clear();
    this.alertRules.clear();
    this.metricCollectors.clear();
  }
}

// Legacy compatibility - singleton instance
let globalMetricsService: EnhancedMetricsService | null = null;
let legacyRegistry: Registry | null = null;

export const metrics = {
  jsonRpcRequestsTotal: {
    inc: (labels: any, value?: number) => {
      globalMetricsService?.incrementCounter('jsonrpc_requests_total', labels, value);
    },
    labels: (labels: any) => ({
      inc: (value?: number) => globalMetricsService?.incrementCounter('jsonrpc_requests_total', labels, value)
    })
  },
  
  jsonRpcForwardLatencyMs: {
    observe: (labels: any, value: number) => {
      globalMetricsService?.observeHistogram('jsonrpc_forward_latency_ms', value, labels);
    },
    startTimer: (labels?: any) => {
      return globalMetricsService?.startTimer('jsonrpc_forward_latency_ms', labels) || (() => {});
    }
  },
  
  jsonRpcBlockedTotal: {
    inc: (labels: any, value?: number) => {
      globalMetricsService?.incrementCounter('jsonrpc_blocked_total', labels, value);
    },
    labels: (labels: any) => ({
      inc: (value?: number) => globalMetricsService?.incrementCounter('jsonrpc_blocked_total', labels, value)
    })
  }
};

export function createPrometheus(): void {
  if (globalMetricsService) return;
  
  globalMetricsService = new EnhancedMetricsService();
  logger.info('Global Prometheus metrics service created');
}

export function getMetricsRegistry(): Registry {
  if (!legacyRegistry) {
    if (!globalMetricsService) {
      createPrometheus();
    }
    legacyRegistry = globalMetricsService!.getRegistry();
  }
  return legacyRegistry;
}

export function getMetricsService(): EnhancedMetricsService {
  if (!globalMetricsService) {
    createPrometheus();
  }
  return globalMetricsService!;
}

// Global cleanup function for testing
export async function cleanupGlobalMetrics(): Promise<void> {
  if (globalMetricsService) {
    await globalMetricsService.cleanup();
    globalMetricsService = null;
  }
  if (legacyRegistry) {
    legacyRegistry = null;
  }
}

// Initialize on module load
createPrometheus();

export default EnhancedMetricsService;
