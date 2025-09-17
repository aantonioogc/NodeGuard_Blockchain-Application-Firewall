// src/metrics/performance-monitor.ts
// Monitor de rendimiento - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import { EventEmitter } from 'events';
import { logger } from '../logging/logger';

export interface PerformanceRecord {
  processingTime: number;
  requestCount: number;
  timestamp: number;
}

export interface PerformanceMetrics {
  averageProcessingTime: number;
  requestsPerSecond: number;
  peakProcessingTime: number;
  totalRequests: number;
}

export class PerformanceMonitor extends EventEmitter {
  private records: PerformanceRecord[] = [];
  private metrics: PerformanceMetrics = {
    averageProcessingTime: 0,
    requestsPerSecond: 0,
    peakProcessingTime: 0,
    totalRequests: 0
  };

  constructor() {
    super();
    this.setupPeriodicCalculations();
  }

  async initialize(): Promise<void> {
    logger.info('Monitor de rendimiento inicializado');
  }

  recordRequest(record: PerformanceRecord): void {
    this.records.push(record);
    
    // Mantener solo los últimos 1000 registros
    if (this.records.length > 1000) {
      this.records = this.records.slice(-1000);
    }

    this.updateMetrics();
  }

  recordUpstreamRequest(metrics: any): void {
    this.recordRequest({
      processingTime: metrics.duration || 0,
      requestCount: 1,
      timestamp: Date.now()
    });
  }

  recordUpstreamError(error: any): void {
    logger.warn('Error upstream registrado', { error: error.message || error });
    this.emit('alert', {
      type: 'upstream_error',
      message: error.message || 'Error upstream desconocido',
      timestamp: Date.now()
    });
  }

  private updateMetrics(): void {
    if (this.records.length === 0) return;

    const recent = this.records.slice(-100); // Últimos 100 registros
    
    this.metrics.averageProcessingTime = 
      recent.reduce((sum, r) => sum + r.processingTime, 0) / recent.length;
    
    this.metrics.peakProcessingTime = Math.max(
      ...recent.map(r => r.processingTime)
    );
    
    this.metrics.totalRequests = this.records.length;

    // Calcular RPS en los últimos 60 segundos
    const now = Date.now();
    const lastMinute = this.records.filter(r => (now - r.timestamp) < 60000);
    this.metrics.requestsPerSecond = lastMinute.length / 60;
  }

  getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  private setupPeriodicCalculations(): void {
    // ajgc: actualizar métricas cada 10 segundos
    setInterval(() => {
      this.updateMetrics();
      this.emit('metricsUpdated', this.metrics);
    }, 10000);
  }

  async cleanup(): Promise<void> {
    this.records = [];
    logger.info('Monitor de rendimiento limpiado');
  }
}

export default PerformanceMonitor;
