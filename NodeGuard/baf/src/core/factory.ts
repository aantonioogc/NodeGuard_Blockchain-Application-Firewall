// Factory principal - NodeGuard TFG 2025
// ajgc (Antonio José González Castillo)
import type { Logger } from "winston";
import { FirewallProvider } from "./firewall-provider";
import { RpcClient } from "./rpc-client";
import { PolicyEngine } from "./policy-engine";
import { ConfigStore } from "../storage/config-store";
import { EventBus } from "../events/event-bus";
import { ReputationService } from "../security/reputation/reputation-service";
import { InMemoryRateLimiterStore } from "../storage/memory-store";
import { RedisRateLimiterStore } from "../storage/redis-store";
import { PerformanceMonitor } from "../metrics/performance-monitor";
import { CircuitBreaker } from "../utils/circuit-breaker";
import redis from "../redis/redis-connection";

/**
 * Configuración del Factory
 */
export interface CreateFirewallProviderDeps {
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
 * Interfaz de componentes del Factory
 */
export interface FirewallProviderComponents {
  firewallProvider: FirewallProvider;
  rpcClient: RpcClient;
  policyEngine: PolicyEngine;
  eventBus: EventBus;
  reputationService: ReputationService;
  performanceMonitor: PerformanceMonitor;
  rateStore: InMemoryRateLimiterStore | RedisRateLimiterStore;
}

/**
 * Factory principal del NodeGuard
 * ajgc - configurar todos los componentes del sistema
 */
export async function createFirewallProvider(deps: CreateFirewallProviderDeps): Promise<FirewallProviderComponents> {
  const logger = deps.logger;
  
  try {
    logger.info('Inicializando factory del NodeGuard...');

    // 1. Crear cliente RPC con Circuit Breaker
    const circuitBreaker = new CircuitBreaker({
      failureThreshold: deps.performance.circuitBreakerThreshold,
      recoveryTimeout: Number(process.env.BAF_CIRCUIT_RECOVERY_TIMEOUT || 30000),
      monitorTimeout: Number(process.env.BAF_CIRCUIT_MONITOR_TIMEOUT || 5000)
    });

    const rpcClient = new RpcClient({
      upstreamUrl: deps.rpcUrl,
      timeoutMs: deps.performance.requestTimeoutMs,
      maxRetries: Number(process.env.BAF_UPSTREAM_RETRIES || 3),
      retryDelayMs: Number(process.env.BAF_RETRY_DELAY_MS || 1000),
      keepAliveEnabled: true,
      compressionEnabled: true,
      circuitBreaker,
      logger,
      validateResponse: true,
      customHeaders: {
        'User-Agent': 'NodeGuard-BAF/2.0',
        'X-Request-Source': 'blockchain-firewall'
      }
    });
    
    logger.debug('Cliente RPC creado con circuit breaker');

    // 2. ajgc: crear store de rate limiting con fallback a memoria
    let rateStore: InMemoryRateLimiterStore | RedisRateLimiterStore;
    
    try {
      if (process.env.USE_REDIS_RATE !== 'false' && redis) {
        // Probar conexión Redis
        await redis.ping();
        rateStore = new RedisRateLimiterStore();
        logger.debug('Store Redis para rate limiting creado');
      } else {
        throw new Error('Redis deshabilitado o no disponible');
      }
    } catch (error) {
      logger.warn('Redis no disponible, usando memoria', { 
        error: (error as Error).message 
      });
      rateStore = new InMemoryRateLimiterStore();
    }

    // 3. Crear servicio de reputación
    const reputationService = new ReputationService({
      scoring: {
        initialScore: 50,
        minScore: 0,
        maxScore: 100,
        decayEnabled: true,
        decayRate: Number(process.env.BAF_REPUTATION_DECAY || 0.1),
        decayInterval: Number(process.env.BAF_REPUTATION_DECAY_INTERVAL || 3600000) // 1 hora
      },
      thresholds: {
        trustworthy: 80,
        neutral: 50,
        suspicious: 40,
        malicious: 20,
        blocked: 10
      },
      geolocation: {
        enabled: process.env.BAF_GEOLOCATION_ENABLED === 'true',
        suspiciousCountries: (process.env.BAF_SUSPICIOUS_COUNTRIES || '').split(',').filter(Boolean),
        blockedCountries: (process.env.BAF_BLOCKED_COUNTRIES || '').split(',').filter(Boolean),
        vpnDetection: false
      }
    }, deps.eventBus);
    
    logger.debug('Servicio de reputación creado');

    // 4. Monitor de rendimiento - niquelao para métricas
    const performanceMonitor = new PerformanceMonitor();
    
    logger.debug('Monitor de rendimiento creado');

    // 5. Motor de políticas con ML
    const policyEngine = new PolicyEngine({
      configStore: deps.configStore,
      rateStore,
      reputationService,
      performanceMonitor,
      eventBus: deps.eventBus,
      config: {
        enforcementMode: deps.enforcementMode,
        enableHeuristics: true,
        enableMLDetection: deps.security?.enableMLDetection ?? false,
        enableBehaviorAnalysis: true,
        batchAnalysis: {
          enabled: true,
          maxBatchSize: Number(process.env.BAF_MAX_BATCH_SIZE || 100),
          crossRequestCorrelation: true,
          aggregateRateLimit: true
        },
        adaptiveThresholds: {
          enabled: true,
          learningRate: Number(process.env.BAF_LEARNING_RATE || 0.01),
          adaptationInterval: Number(process.env.BAF_ADAPTATION_INTERVAL || 1800000) // 30 minutos
        }
      },
      logger
    });

    // Inicializar el motor de políticas
    await policyEngine.initialize();
    logger.debug('Motor de políticas creado e inicializado');

    // 6. Crear el Firewall Provider principal - de locos la configuración
    const firewallProvider = new FirewallProvider({
      policy: policyEngine,
      rpc: rpcClient,
      events: deps.eventBus,
      reputation: reputationService,
      performanceMonitor,
      logger,
      config: {
        enforcementMode: deps.enforcementMode,
        maxConcurrentRequests: deps.performance.maxConcurrentRequests,
        enableBatchProcessing: true,
        enableAsyncProcessing: process.env.BAF_ASYNC_PROCESSING === 'true',
        requestQueue: {
          maxSize: Number(process.env.BAF_QUEUE_MAX_SIZE || 1000),
          timeoutMs: deps.performance.requestTimeoutMs,
          priorityEnabled: true
        },
        security: {
          enablePayloadSanitization: true,
          enableAdvancedParsing: true,
          enableEIP2718Support: true,
          enableEIP1559Support: true,
          enableReplayProtection: true,
          enableFunctionSelectorAnalysis: true,
          enableContractBlacklisting: true,
          enableSybilDetection: true
        }
      }
    });

    await firewallProvider.initialize();
    logger.debug('Firewall Provider creado e inicializado');

    // 7. ajgc: conectar componentes entre sí
    await setupComponentInterconnections({
      firewallProvider,
      rpcClient,
      policyEngine,
      reputationService,
      performanceMonitor,
      eventBus: deps.eventBus
    });

    logger.info('Factory NodeGuard completado - Todos los componentes conectados');

    return {
      firewallProvider,
      rpcClient,
      policyEngine,
      eventBus: deps.eventBus,
      reputationService,
      performanceMonitor,
      rateStore
    };

  } catch (error) {
    const err = error as Error;
    logger.error('Error en inicialización del factory', { 
      error: err.message, 
      stack: err.stack 
    });
    throw new Error(`Error en factory: ${err.message}`);
  }
}

/**
 * Configurar comunicación bidireccional entre componentes
 */
async function setupComponentInterconnections(components: {
  firewallProvider: FirewallProvider;
  rpcClient: RpcClient;
  policyEngine: PolicyEngine;
  reputationService: ReputationService;
  performanceMonitor: PerformanceMonitor;
  eventBus: EventBus;
}): Promise<void> {
  const { firewallProvider, rpcClient, policyEngine, reputationService, performanceMonitor, eventBus } = components;

  // Cliente RPC → Monitor de rendimiento
  rpcClient.on('request', (metrics) => {
    performanceMonitor.recordUpstreamRequest(metrics);
  });

  rpcClient.on('error', (error) => {
    performanceMonitor.recordUpstreamError(error);
    eventBus.emitEvent({
      type: 'status',
      timestamp: Date.now(),
      message: 'Error RPC upstream detectado',
      method: 'system',
      clientIp: 'system',
      reqId: 'rpc-error-' + Date.now()
    });
  });

  // Motor de políticas → Servicio de reputación
  policyEngine.on('block', async (context) => {
    await reputationService.recordIncident(context.clientIp, {
      entityType: 'ip',
      type: 'policy_breach',
      severity: getSeverityScore(context.reason),
      description: `Request bloqueado: ${context.reason}`,
      details: { 
        method: context.method,
        rule: context.rule || 'unknown'
      },
      source: 'policy_engine'
    });
  });

  // Servicio de reputación → EventBus
  reputationService.on('threat-level-changed', (event) => {
    eventBus.emitEvent({
      type: 'status',
      timestamp: Date.now(),
      message: `Nivel de amenaza cambiado: ${event.ip} → ${event.newLevel}`,
      method: 'reputation',
      clientIp: event.ip.substring(0, 12) + '...',
      reqId: 'reputation-' + Date.now()
    });
  });

  // Monitor de rendimiento → EventBus
  performanceMonitor.on('alert', (alert: any) => {
    eventBus.emitEvent({
      type: 'status',
      timestamp: Date.now(),
      message: `Alerta de rendimiento: ${alert.type} - ${alert.message}`,
      method: 'performance',
      clientIp: 'system',
      reqId: 'perf-alert-' + Date.now()
    });
  });

  // ajgc: health checks del firewall cada 30s - echarle un ojillo
  setInterval(async () => {
    const health = await firewallProvider.getHealthStatus();
    if (!health.healthy) {
      eventBus.emitEvent({
        type: 'status',
        timestamp: Date.now(),
        message: `Salud del firewall degradada: ${health.issues.join(', ')}`,
        method: 'system',
        clientIp: 'system',
        reqId: 'health-' + Date.now()
      });
    }
  }, Number(process.env.BAF_HEALTH_CHECK_INTERVAL || 30000));
}

/**
 * Obtener puntuación de severidad para el sistema de reputación
 */
function getSeverityScore(reason: string): number {
  const severityMap: { [key: string]: number } = {
    'rate_limit_ip': 5,
    'rate_limit_address': 7,
    'blocked_method': 15,
    'replay_protection': 25,
    'chainId_mismatch': 30,
    'invalid_raw_tx': 10,
    'repeated_payload': 8,
    'token_bucket': 6,
    'function_selector_blocked': 20,
    'contract_blacklisted': 35,
    'sybil_attack': 40,
    'mempool_flooding': 25,
    'gas_manipulation': 15,
    'nonce_manipulation': 20,
    'payload_too_large': 12,
    'suspicious_pattern': 18
  };
  
  return severityMap[reason] || 10;
}
