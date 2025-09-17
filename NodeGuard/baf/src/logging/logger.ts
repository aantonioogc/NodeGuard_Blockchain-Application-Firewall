// src/logging/logger.ts
// Logger - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';

/**
 * Enterprise Logging System with Winston Integration
 * 
 * Features:
 * - Multi-transport logging (console, file, Redis, HTTP)
 * - Structured logging with metadata
 * - Log rotation and archival
 * - Security event logging
 * - Performance tracking
 * - Compliance logging (GDPR, SOX, etc.)
 * - Log correlation and tracing
 * - Error aggregation and alerting
 * - Contextual logging with request correlation
 */

export interface LogContext {
  requestId?: string;
  userId?: string;
  sessionId?: string;
  correlationId?: string;
  component?: string;
  action?: string;
  resource?: string;
  ipAddress?: string;
  userAgent?: string;
  method?: string;
  duration?: number;
  statusCode?: number;
  error?: Error;
  metadata?: { [key: string]: any };
  reason?: string; // Added to support unhandledRejection logging
  timestamp?: string;
  level?: string;
  hostname?: string;
  pid?: number;
  exitCode?: number;
  stack?: string;
  // Fingerprint-specific properties
  algorithm?: string;
  hash?: string;
  count?: number;
  blocked?: boolean;
  confidence?: number;
  keysProcessed?: number;
  keysExpired?: number;
  cacheSize?: number;
  processingTime?: string;
  key?: string;
  ip?: string;
  crossBatchEnabled?: boolean;
  // Metrics-specific properties
  defaultMetricsEnabled?: boolean;
  prefix?: string;
  customCollectors?: boolean;
  type?: string;
  name?: string;
  labels?: string[];
  collector?: string;
  alert?: string;
  rule?: any;
  // Client-specific properties
  rpcUrl?: string;
  adminUrl?: string;
  circuitBreakerEnabled?: boolean;
  eventsEnabled?: boolean;
  role?: string;
  // Reputation-specific properties
  mlEnabled?: boolean;
  geoEnabled?: boolean;
  realtimeEnabled?: boolean;
  incidentId?: string;
  entityType?: string;
  entityId?: string;
  incidentType?: string;
  severity?: number;
  // Server-specific properties
  attackType?: string;
  contentLength?: number;
  url?: string;
  // EventBus-specific properties
  maxHistory?: number;
  persistEvents?: boolean;
  rateLimitPerSubscriber?: number;
  current?: number;
  max?: number;
  subscriberId?: string;
  clientIp?: string;
  filtersCount?: number;
  activeSubscribers?: number;
  eventType?: string;
  eventId?: string;
  deliveredCount?: number;
  failedCount?: number;
  latency?: number;
  lastEventAge?: number;
  // Validation-specific properties
  validationTime?: string;
  batchSize?: number;
  batchIndex?: number;
  totalEvents?: number;
  failures?: number;
  inactiveDuration?: number;
  eventsReceived?: number;
  eventCount?: number;
  // Redis-specific properties
  host?: string;
  port?: number;
  cluster?: boolean;
  tls?: boolean;
  delay?: string;
  node?: string;
  commandLatency?: string;
  // Rate limiter-specific properties
  windowSizeMs?: number;
  maxRequests?: number;
  keyPrefix?: string;
  keysCleaned?: number;
  cleanupTime?: string;
  limit?: number;
  windowSeconds?: number;
  // Token bucket-specific properties
  capacity?: number;
  refillRate?: number;
  scriptPath?: string;
  tokens?: number;
  // In-memory store-specific properties
  maxMemoryMb?: number;
  freedBytes?: number;
  cleanedEntries?: number;
  remainingEntries?: number;
  evictedEntries?: number;
  currentUsage?: number;
  freedMemory?: number;
  // Redis store-specific properties
  serializer?: string;
  keyCount?: number;
  entryCount?: number;
  pattern?: string;
  cursor?: string;
  delta?: number;
  ttlMs?: number;
}

export interface SecurityEvent {
  eventType: 'authentication' | 'authorization' | 'data_access' | 'configuration_change' | 'system_event';
  severity: 'low' | 'medium' | 'high' | 'critical';
  actor: string;
  resource: string;
  action: string;
  outcome: 'success' | 'failure' | 'unknown';
  sourceIp?: string;
  userAgent?: string;
  additionalData?: any;
  timestamp?: string;
  eventId?: string;
  hostname?: string;
  processId?: number;
  environment?: string;
}

export interface PerformanceMetrics {
  operation: string;
  duration: number;
  memoryUsage?: NodeJS.MemoryUsage;
  cpuUsage?: NodeJS.CpuUsage;
  throughput?: number;
  errorRate?: number;
  additionalMetrics?: { [key: string]: number };
}

/**
 * Logger mejorado con integración Winston
 */
export class EnhancedLogger {
  private winston: winston.Logger;
  private securityLogger: winston.Logger;
  private performanceLogger: winston.Logger;
  private auditLogger: winston.Logger;
  
  // Seguimiento de rendimiento
  private performanceData = new Map<string, PerformanceMetrics[]>();
  private errorCounts = new Map<string, number>();
  
  // Buffer de eventos de seguridad
  private securityEventBuffer: SecurityEvent[] = [];
  private readonly maxBufferSize = 1000;
  
  // Cleanup de intervalos
  private performanceInterval?: NodeJS.Timeout;
  private securityInterval?: NodeJS.Timeout;
  
  constructor() {
    this.winston = this.createMainLogger();
    this.securityLogger = this.createSecurityLogger();
    this.performanceLogger = this.createPerformanceLogger();
    this.auditLogger = this.createAuditLogger();
    
    this.setupPerformanceTracking();
    this.setupSecurityEventProcessing();
    this.setupProcessHandlers();
    
    this.info('Logger NodeGuard inicializado', {
      component: 'logger'
    });
  }

  /**
   * Métodos principales de logging
   */
  
  error(message: string, context?: LogContext): void {
    const enhancedContext = this.enhanceContext('error', context);
    this.winston.error(message, enhancedContext);
    
    // Seguir errores para métricas
    const errorKey = context?.component || 'unknown';
    this.errorCounts.set(errorKey, (this.errorCounts.get(errorKey) || 0) + 1);
    
    // Auto-crear evento de seguridad para ciertos errores
    if (context?.error && this.isSecurityRelevantError(context.error)) {
      this.logSecurityEvent({
        eventType: 'system_event',
        severity: 'high',
        actor: context.userId || 'system',
        resource: context.resource || 'unknown',
        action: 'error_occurred',
        outcome: 'failure',
        sourceIp: context.ipAddress,
        additionalData: {
          message,
          errorType: context.error.name,
          stack: context.error.stack
        }
      });
    }
  }
  
  warn(message: string, context?: LogContext): void {
    const enhancedContext = this.enhanceContext('warn', context);
    this.winston.warn(message, enhancedContext);
  }
  
  info(message: string, context?: LogContext): void {
    const enhancedContext = this.enhanceContext('info', context);
    this.winston.info(message, enhancedContext);
  }
  
  debug(message: string, context?: LogContext): void {
    const enhancedContext = this.enhanceContext('debug', context);
    this.winston.debug(message, enhancedContext);
  }
  
  verbose(message: string, context?: LogContext): void {
    const enhancedContext = this.enhanceContext('verbose', context);
    this.winston.verbose(message, enhancedContext);
  }

  /**
   * Specialized logging methods
   */
  
  logSecurityEvent(event: SecurityEvent): void {
    const enhancedEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      hostname: require('os').hostname(),
      processId: process.pid,
      environment: process.env.NODE_ENV || 'development'
    };
    
    this.securityLogger.info('Security Event', enhancedEvent);
    
    // Add to buffer for batch processing
    this.securityEventBuffer.push(enhancedEvent);
    
    if (this.securityEventBuffer.length > this.maxBufferSize) {
      this.securityEventBuffer.shift(); // Remove oldest
    }
    
    // Alert on critical events
    if (event.severity === 'critical') {
      this.sendSecurityAlert(enhancedEvent);
    }
  }
  
  logPerformanceMetrics(metrics: PerformanceMetrics): void {
    const enhancedMetrics = {
      ...metrics,
      timestamp: new Date().toISOString(),
      hostname: require('os').hostname(),
      processId: process.pid
    };
    
    this.performanceLogger.info('Performance Metrics', enhancedMetrics);
    
    // Store for aggregation
    const operationMetrics = this.performanceData.get(metrics.operation) || [];
    operationMetrics.push(metrics);
    
    // Keep last 100 entries per operation
    if (operationMetrics.length > 100) {
      operationMetrics.shift();
    }
    
    this.performanceData.set(metrics.operation, operationMetrics);
  }
  
  logAuditEvent(action: string, context: LogContext & {
    before?: any;
    after?: any;
    changes?: any;
  }): void {
    const auditEvent = {
      action,
      timestamp: new Date().toISOString(),
      actor: context.userId || 'unknown',
      sessionId: context.sessionId,
      resource: context.resource,
      sourceIp: context.ipAddress,
      userAgent: context.userAgent,
      before: context.before,
      after: context.after,
      changes: context.changes,
      requestId: context.requestId,
      correlationId: context.correlationId,
      metadata: context.metadata
    };
    
    this.auditLogger.info('Audit Event', auditEvent);
  }
  
  // Métodos de logging especializados para NodeGuard
  blocked(reason: string, context?: LogContext & { rule?: string; from?: string; to?: string }): void {
    this.warn(`Solicitud bloqueada: ${reason}`, {
      ...context,
      component: 'firewall',
      action: 'block_request'
    });
    
    this.logSecurityEvent({
      eventType: 'authorization',
      severity: 'medium',
      actor: context?.userId || 'unknown',
      resource: context?.resource || 'rpc_endpoint',
      action: 'request_blocked',
      outcome: 'success',
      sourceIp: context?.ipAddress,
      additionalData: {
        reason,
        rule: context?.rule,
        from: context?.from,
        to: context?.to
      }
    });
  }
  
  allowed(method: string, context?: LogContext & { from?: string }): void {
    this.debug(`Solicitud permitida: ${method}`, {
      ...context,
      component: 'firewall',
      action: 'allow_request',
      method
    });
  }
  
  attack(type: string, context: LogContext & { details: any }): void {
    this.error(`Ataque detectado: ${type}`, {
      ...context,
      component: 'security',
      action: 'attack_detected'
    });
    
    this.logSecurityEvent({
      eventType: 'system_event',
      severity: 'critical',
      actor: context.userId || 'unknown',
      resource: 'system',
      action: 'attack_detected',
      outcome: 'unknown',
      sourceIp: context.ipAddress,
      additionalData: {
        attackType: type,
        details: context.details
      }
    });
  }
  
  transaction(txHash: string, context: LogContext & { 
    from?: string; 
    to?: string; 
    value?: string; 
    gasUsed?: string 
  }): void {
    this.info(`Transacción: ${txHash}`, {
      ...context,
      component: 'blockchain',
      action: 'transaction',
      resource: 'transaction'
    });
    
    this.logAuditEvent('transaction_processed', {
      ...context,
      resource: `transaction:${txHash}`,
      metadata: {
        txHash,
        from: context.from,
        to: context.to,
        value: context.value,
        gasUsed: context.gasUsed
      }
    });
  }
  
  ruleChange(action: 'create' | 'update' | 'delete', context: LogContext & {
    ruleId?: string;
    before?: any;
    after?: any;
  }): void {
    this.info(`Cambio de regla ${action}: ${context.ruleId}`, {
      ...context,
      component: 'rules',
      action: `rule_${action}`
    });
    
    this.logAuditEvent(`rule_${action}`, {
      ...context,
      resource: `rule:${context.ruleId}`,
      before: context.before,
      after: context.after
    });
    
    this.logSecurityEvent({
      eventType: 'configuration_change',
      severity: 'medium',
      actor: context.userId || 'system',
      resource: `rule:${context.ruleId}`,
      action: `rule_${action}`,
      outcome: 'success',
      sourceIp: context.ipAddress,
      additionalData: {
        ruleId: context.ruleId,
        changes: this.calculateChanges(context.before, context.after)
      }
    });
  }

  /**
   * Utility methods
   */
  
  startTimer(label: string): () => number {
    const start = process.hrtime.bigint();
    return () => {
      const end = process.hrtime.bigint();
      const duration = Number((end - start) / BigInt(1000000)); // Convert to milliseconds
      
      this.logPerformanceMetrics({
        operation: label,
        duration
      });
      
      return duration;
    };
  }
  
  createChildLogger(defaultContext: Partial<LogContext>): winston.Logger {
    return this.winston.child(defaultContext);
  }
  
  getPerformanceStats(operation?: string): any {
    if (operation) {
      const metrics = this.performanceData.get(operation) || [];
      if (metrics.length === 0) return null;
      
      const durations = metrics.map(m => m.duration);
      return {
        operation,
        count: metrics.length,
        avgDuration: durations.reduce((a, b) => a + b, 0) / durations.length,
        minDuration: Math.min(...durations),
        maxDuration: Math.max(...durations),
        lastRecorded: metrics[metrics.length - 1].duration
      };
    }
    
    const stats: any = {};
    for (const [op, metrics] of this.performanceData.entries()) {
      stats[op] = this.getPerformanceStats(op);
    }
    return stats;
  }
  
  getSecurityEventsSummary(timeRange?: { start: Date; end: Date }): any {
    let events = this.securityEventBuffer;
    
    if (timeRange) {
      events = events.filter(event => {
        if (!event.timestamp) return false;
        const eventTime = new Date(event.timestamp);
        return eventTime >= timeRange.start && eventTime <= timeRange.end;
      });
    }
    
    const summary = {
      totalEvents: events.length,
      byEventType: {} as any,
      bySeverity: {} as any,
      byOutcome: {} as any,
      criticalEvents: events.filter(e => e.severity === 'critical').length
    };
    
    events.forEach(event => {
      summary.byEventType[event.eventType] = (summary.byEventType[event.eventType] || 0) + 1;
      summary.bySeverity[event.severity] = (summary.bySeverity[event.severity] || 0) + 1;
      summary.byOutcome[event.outcome] = (summary.byOutcome[event.outcome] || 0) + 1;
    });
    
    return summary;
  }

  /**
   * Private helper methods
   */
  
  private createMainLogger(): winston.Logger {
    const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
    const enableConsoleOutput = process.env.BAF_CONSOLE_LOGS !== 'false'; // Flag para controlar logs en consola
    
    // Ensure log directory exists
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    const transports: winston.transport[] = [
      // File transport with rotation
      new winston.transports.File({
        filename: path.join(logDir, 'baf.log'),
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true
      }),
      
      // Error file
      new winston.transports.File({
        filename: path.join(logDir, 'error.log'),
        level: 'error',
        maxsize: 10 * 1024 * 1024,
        maxFiles: 5,
        tailable: true
      })
    ];

    // Solo agregar Console transport si está habilitado
    if (enableConsoleOutput) {
      transports.unshift(new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple(),
          winston.format.printf(({ timestamp, level, message, component, requestId, ...meta }) => {
            let output = `${timestamp} [${level}]`;
            if (component) output += ` [${component}]`;
            if (requestId) output += ` [${requestId}]`;
            output += ` ${message}`;
            
            if (Object.keys(meta).length > 0) {
              output += ` ${JSON.stringify(meta)}`;
            }
            
            return output;
          })
        )
      }));
    }
    
    return winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            level,
            message,
            ...meta
          });
        })
      ),
      defaultMeta: {
        service: 'baf',
        hostname: require('os').hostname(),
        pid: process.pid,
        version: process.env.npm_package_version || '2.0.0'
      },
      transports,
      exitOnError: false
    });
  }
  
  private createSecurityLogger(): winston.Logger {
    const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
    
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(logDir, 'security.log'),
          maxsize: 50 * 1024 * 1024, // 50MB
          maxFiles: 10,
          tailable: true
        })
      ],
      exitOnError: false
    });
  }
  
  private createPerformanceLogger(): winston.Logger {
    const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
    
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(logDir, 'performance.log'),
          maxsize: 25 * 1024 * 1024, // 25MB
          maxFiles: 5,
          tailable: true
        })
      ],
      exitOnError: false
    });
  }
  
  private createAuditLogger(): winston.Logger {
    const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
    
    return winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: path.join(logDir, 'audit.log'),
          maxsize: 100 * 1024 * 1024, // 100MB
          maxFiles: 20,
          tailable: true
        })
      ],
      exitOnError: false
    });
  }
  
  private enhanceContext(level: string, context?: LogContext): LogContext {
    return {
      ...context,
      timestamp: new Date().toISOString(),
      level,
      hostname: require('os').hostname(),
      pid: process.pid,
      correlationId: context?.correlationId || this.generateCorrelationId()
    };
  }
  
  private generateEventId(): string {
    return createHash('sha256')
      .update(`${Date.now()}-${Math.random()}`)
      .digest('hex')
      .substring(0, 16);
  }
  
  private generateCorrelationId(): string {
    return `corr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private isSecurityRelevantError(error: Error): boolean {
    const securityErrorPatterns = [
      /authentication/i,
      /authorization/i,
      /permission/i,
      /forbidden/i,
      /unauthorized/i,
      /token/i,
      /session/i,
      /csrf/i,
      /xss/i,
      /injection/i
    ];
    
    return securityErrorPatterns.some(pattern => 
      pattern.test(error.message) || pattern.test(error.name)
    );
  }
  
  private calculateChanges(before: any, after: any): any {
    if (!before || !after) return { before, after };
    
    const changes: any = {};
    const allKeys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
    
    for (const key of allKeys) {
      const beforeValue = before?.[key];
      const afterValue = after?.[key];
      
      if (JSON.stringify(beforeValue) !== JSON.stringify(afterValue)) {
        changes[key] = { before: beforeValue, after: afterValue };
      }
    }
    
    return changes;
  }
  
  private sendSecurityAlert(event: any): void {
    // Implementation would send alerts via email, Slack, PagerDuty, etc.
    this.error('Critical security event detected', {
      component: 'security_alert',
      metadata: { event }
    });
  }
  
  private setupPerformanceTracking(): void {
    // Track process performance metrics periodically
    this.performanceInterval = setInterval(() => {
      const memoryUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      
      this.logPerformanceMetrics({
        operation: 'process_metrics',
        duration: 0,
        memoryUsage,
        cpuUsage
      });
    }, 60000); // Every minute
  }
  
  private setupSecurityEventProcessing(): void {
    // Process security events in batches
    this.securityInterval = setInterval(() => {
      if (this.securityEventBuffer.length > 0) {
        const summary = this.getSecurityEventsSummary();
        
        if (summary.criticalEvents > 0) {
          this.warn(`Security alert: ${summary.criticalEvents} critical events in the last period`, {
            component: 'security_monitor',
            metadata: summary
          });
        }
      }
    }, 300000); // Every 5 minutes
  }
  
  private setupProcessHandlers(): void {
    // Log process events
    process.on('exit', (code) => {
      this.info('Process exiting', { component: 'process', exitCode: code });
    });
    
    process.on('uncaughtException', (error) => {
      this.error('Uncaught exception', { 
        component: 'process', 
        error,
        stack: error.stack 
      });
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      this.error('Unhandled promise rejection', {
        component: 'process',
        reason: reason instanceof Error ? reason.message : String(reason),
        stack: reason instanceof Error ? reason.stack : undefined
      });
    });
  }
  
  /**
   * Cleanup method for tests and graceful shutdown
   */
  cleanup(): void {
    if (this.performanceInterval) {
      clearInterval(this.performanceInterval);
      this.performanceInterval = undefined;
    }
    
    if (this.securityInterval) {
      clearInterval(this.securityInterval);
      this.securityInterval = undefined;
    }
    
    // Close winston transports
    this.winston.close();
    this.securityLogger.close();
    this.performanceLogger.close();
    this.auditLogger.close();
  }
}

// Create and export singleton instance
export const logger = new EnhancedLogger();

// Export the winston logger for compatibility with external libraries
export const winstonLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: path.join(__dirname, '../logs/app.log') })
  ]
});

// Export for backward compatibility
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3
}

export default logger;
