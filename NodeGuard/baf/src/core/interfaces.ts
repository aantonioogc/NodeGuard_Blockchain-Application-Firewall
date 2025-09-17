// src/core/interfaces.ts
// Interfaces NodeGuard - TFG 2025
// ajgc (Antonio José González Castillo)
import type { Logger } from "winston";
import type { EnhancedReqContext, EnhancedEvalExtraction } from "./base-provider";
import type * as EventBusModule from "../events/event-bus";

// Usar alias para evitar conflicto
export type EventBusInterface = EventBusModule.EventBus;

/**
 * Interface de decisión de regla
 */
export interface RuleDecision {
  decision: 'block' | 'allow' | 'monitor';
  reason: string;
  rule?: string;
  ruleId?: string;
  confidence?: number;
  metadata?: {
    severity: number;
    category: string;
    actionTaken: string;
    additionalInfo?: any;
  };
}

/**
 * Contexto de política
 */
export interface PolicyContext {
  method: string;
  params?: unknown[];
  clientIp: string;
  requestId: string;
  timestamp: number;
  extracted: EnhancedEvalExtraction;
  security: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    suspiciousPatterns: string[];
    riskFactors: {
      unusualGasPrice: boolean;
      suspiciousContract: boolean;
      replayAttempt: boolean;
      sybilIndicator: boolean;
      mevPotential: boolean;
    };
    compliance: {
      eip155: boolean;
      eip2718: boolean;
      eip1559: boolean;
    };
  };
  analytics: {
    gasPriceWei?: bigint;
    gasLimit?: bigint;
    payloadHash: string;
    complexity: number;
    processingTime?: number;
    cacheHit?: boolean;
  };
}

/**
 * Motor de políticas NodeGuard
 */
export interface PolicyEngine {
  initialize(): Promise<void>;
  evaluate(context: PolicyContext): Promise<RuleDecision>;
  updateRules(rules: any): Promise<void>;
  getRules(): Promise<any>;
  isHealthy(): boolean;
  getMetrics(): Promise<{
    totalEvaluations: number;
    blockedRequests: number;
    averageEvaluationTime: number;
    ruleHitRate: { [ruleName: string]: number };
  }>;
  cleanup?(): Promise<void>;
}

/**
 * Reenviador JSON-RPC
 */
export interface JsonRpcForwarder {
  send(payload: unknown): Promise<unknown>;
  isHealthy(): Promise<boolean>;
  getMetrics(): Promise<{
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageLatency: number;
    circuitBreakerStatus: 'closed' | 'open' | 'half-open';
  }>;
}

/**
 * Base Provider
 */
export interface BaseProvider {
  handleJsonRpc(payload: unknown, clientIp: string, userAgent?: string): Promise<unknown>;
  isHealthy(): boolean;
  cleanup(): Promise<void>;
}

/**
 * Firewall Provider NodeGuard
 */
export interface FirewallProvider extends BaseProvider {
  initialize(): Promise<void>;
  send(payload: unknown): Promise<unknown>;
  isUpstreamHealthy(): Promise<boolean>;
  getHealthStatus(): Promise<{
    healthy: boolean;
    issues: string[];
    metrics: any;
  }>;
}

/**
 * Opciones del cliente RPC
 */
export interface RpcClientOptions {
  upstreamUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  keepAliveEnabled?: boolean;
  compressionEnabled?: boolean;
  circuitBreaker?: CircuitBreaker;
  logger: Logger;
  validateResponse?: boolean;
  customHeaders?: { [key: string]: string };
}

/**
 * Circuit Breaker
 */
export interface CircuitBreaker {
  execute<T>(operation: () => Promise<T>): Promise<T>;
  isOpen(): boolean;
  getMetrics(): {
    failures: number;
    successes: number;
    timeouts: number;
    state: 'closed' | 'open' | 'half-open';
    nextAttempt?: number;
  };
}

/**
 * Rate Limiter Store Interface
 */
export interface RateLimiterStore {
  increment(key: string, windowMs: number): Promise<number>;
  get(key: string): Promise<number>;
  reset(key: string): Promise<void>;
  cleanup(): Promise<void>;
}

/**
 * Servicio de reputación
 */
export interface ReputationService {
  initialize(): Promise<void>;
  getScore(identifier: string): Promise<number>;
  updateScore(identifier: string, delta: number): Promise<void>;
  recordIncident(identifier: string, incident: {
    type: string;
    severity: number;
    details?: any;
  }): Promise<void>;
  recordPositiveInteraction(identifier: string): Promise<void>;
  isBlacklisted(identifier: string): Promise<boolean>;
  getThreatLevel(identifier: string): Promise<'low' | 'medium' | 'high' | 'critical'>;
  isHealthy(): Promise<boolean>;
  cleanup?(): Promise<void>;
}

/**
 * Monitor de rendimiento
 */
export interface PerformanceMonitor {
  initialize(): Promise<void>;
  recordRequest(metrics: {
    processingTime: number;
    requestCount: number;
    timestamp: number;
  }): void;
  recordUpstreamRequest(metrics: {
    latency: number;
    success: boolean;
    statusCode?: number;
  }): void;
  recordUpstreamError(error: {
    message: string;
    code?: string;
    timestamp: number;
  }): void;
  getMetrics(): Promise<{
    averageProcessingTime: number;
    requestsPerSecond: number;
    upstreamLatency: number;
    errorRate: number;
    alertsTriggered: number;
  }>;
  cleanup?(): Promise<void>;
}

/**
 * Evento del Bus de Eventos
 */
export interface BafEvent {
  type: 'block' | 'allow' | 'status' | 'connection' | 'ping';
  timestamp: number;
  message?: string;
  method: string;
  clientIp: string;
  reqId: string;
  reason?: string;
  rule?: string;
  from?: string;
  to?: string;
  level?: 'info' | 'warning' | 'error';
  metadata?: any;
}

/**
 * Bus de eventos NodeGuard
 */
export interface EventBus {
  emit(event: BafEvent): void;
  subscribe(listener: (event: BafEvent) => void): () => void;
  subscribe(response: any): void; // Para SSE
  isHealthy(): boolean;
  getMetrics(): {
    totalEvents: number;
    subscribers: number;
    eventsByType: { [type: string]: number };
  };
  cleanup?(): Promise<void>;
}

/**
 * Métricas
 */
export interface MetricsLike {
  jsonRpcRequestsTotal: { 
    labels: (...args: string[]) => { inc: (v?: number) => void } 
  };
  jsonRpcBlockedTotal: { 
    labels: (...args: string[]) => { inc: (v?: number) => void } 
  };
  jsonRpcForwardLatencyMs: { 
    startTimer: () => () => void 
  };
  upstreamConnectionsTotal: {
    labels: (...args: string[]) => { inc: (v?: number) => void }
  };
  upstreamErrorsTotal: {
    labels: (...args: string[]) => { inc: (v?: number) => void }
  };
}

/**
 * Almacén de configuración
 */
export interface ConfigStore {
  getRules(): Promise<any>;
  setRules(rules: any): Promise<void>;
  isRedisConnected(): boolean;
  isHealthy(): boolean;
  backup(): Promise<string>;
  restore(backupId: string): Promise<void>;
  cleanup?(): Promise<void>;
}

/**
 * Dependencias del Factory Provider 
 * ajgc: configuración centralizada para NodeGuard
 */
export interface ProviderFactoryDeps {
  rpcUrl: string;
  configStore: ConfigStore;
  eventBus: EventBus;
  enforcementMode: 'block' | 'monitor' | 'dry-run';
  logger: Logger;
  performance: {
    maxConcurrentRequests: number;
    requestTimeoutMs: number;
    circuitBreakerThreshold: number;
  };
  redis?: {
    enabled: boolean;
    fallbackToMemory: boolean;
    connectionTimeout: number;
  };
  security?: {
    enableReputationSystem: boolean;
    enableMLDetection: boolean;
    enableAdvancedFingerprinting: boolean;
  };
}

/**
 * Resultado de chequeo de salud
 */
export interface HealthCheckResult {
  service: string;
  healthy: boolean;
  responseTime?: number;
  error?: string;
  metadata?: any;
}

/**
 * Estado de salud del sistema NodeGuard
 */
export interface SystemHealthStatus {
  overall: 'healthy' | 'degraded' | 'unhealthy';
  components: HealthCheckResult[];
  timestamp: number;
  uptime: number;
}
