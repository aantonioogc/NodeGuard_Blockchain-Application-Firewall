// src/core/policy-engine.ts
// Motor de políticas - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import { EventEmitter } from 'events';
import { ConfigStore } from "../storage/config-store";
import { evaluateStaticRules } from "../rules/static-rules";
import { evaluateHeuristicRules } from "../rules/heuristic-rules";
import { logger } from "../logging/logger";
import { StaticRules, RuleDecision } from "../rules/types";
import { PolicyContext } from "./interfaces";
import { PerformanceMonitor } from "../metrics/performance-monitor";
import { ReputationService } from "../security/reputation/reputation-service";
import redis from "../redis/redis-connection";

/**
 * Configuración del motor de policias NodeGuard
 */
export interface PolicyEngineConfig {
  enforcementMode: 'block' | 'monitor' | 'dry-run';
  enableHeuristics: boolean;
  enableMLDetection: boolean;
  enableBehaviorAnalysis: boolean;
  batchAnalysis: {
    enabled: boolean;
    maxBatchSize: number;
    crossRequestCorrelation: boolean;
    aggregateRateLimit: boolean;
  };
  adaptiveThresholds: {
    enabled: boolean;
    learningRate: number;
    adaptationInterval: number;
  };
}

/**
 * Contexto de ejecución de reglas
 */
interface RuleExecutionContext {
  requestId: string;
  timestamp: number;
  clientIp: string;
  method: string;
  ruleType: 'static' | 'heuristic' | 'ml';
  executionTime?: number;
  cacheHit: boolean;
}

/**
 * Dependencias del motor de políticas
 */
export interface PolicyEngineDeps {
  configStore: any;
  rateStore: any;
  reputationService?: ReputationService;
  performanceMonitor?: PerformanceMonitor;
  eventBus: any;
  config: PolicyEngineConfig;
  logger: any;
}

/**
 * Motor de políticas avanzado para NodeGuard
 * Incluye análisis multicapa, detección ML y umbrales adaptativos
 * ajgc: sistema de caché para mejorar rendimiento
 */
export class PolicyEngine extends EventEmitter {
  private readonly configStore: any;
  private readonly rateStore: any;
  private readonly reputationService?: ReputationService;
  private readonly performanceMonitor?: PerformanceMonitor;
  private readonly eventBus: any;
  private readonly config: PolicyEngineConfig;
  private readonly logger: any;
  
  // Cache y rendimiento
  private evaluationCache = new Map<string, { decision: RuleDecision; timestamp: number; hits: number }>();
  private readonly cacheExpiry = 300000; // 5 minutos
  private lastRuleUpdateLog = 0;
  
  // Métricas
  private stats = {
    totalEvaluations: 0,
    blockedRequests: 0,
    allowedRequests: 0,
    monitoredRequests: 0,
    cacheHits: 0,
    averageEvaluationTime: 0,
    ruleHitRate: new Map<string, number>(),
    lastOptimization: Date.now()
  };
  
  // Umbrales adaptativos
  private adaptiveThresholds = new Map<string, {
    value: number;
    confidence: number;
    lastUpdate: number;
    samples: number[];
  }>();
  
  private initialized = false;

  constructor(deps: PolicyEngineDeps) {
    super();
    
    this.configStore = deps.configStore;
    this.rateStore = deps.rateStore;
    this.reputationService = deps.reputationService;
    this.performanceMonitor = deps.performanceMonitor;
    this.eventBus = deps.eventBus;
    this.config = deps.config;
    this.logger = deps.logger;
    
    this.setupCacheCleanup();
    this.setupAdaptiveThresholdUpdates();
  }

  /**
   * Inicializar motor de políticas
   */
  public async initialize(): Promise<void> {
    try {
      this.logger.info('Inicializando motor de políticas NodeGuard...');
      
      // Cargar reglas iniciales
      await this.configStore.getRules();
      
      // ajgc: listener para actualizaciones de reglas
      this.configStore.on('updated', this.onRulesUpdated.bind(this));
      
      // Inicializar umbrales adaptativos si están habilitados
      if (this.config.adaptiveThresholds.enabled) {
        await this.initializeAdaptiveThresholds();
      }
      
      this.initialized = true;
      this.logger.info('Motor de políticas NodeGuard listo');
      
    } catch (error) {
      const err = error as Error;
      this.logger.error('Error al inicializar motor de políticas', { 
        error: err.message,
        stack: err.stack 
      });
      throw err;
    }
  }

  /**
   * Evaluación de reglas con análisis multicapa
   */
  public async evaluate(context: PolicyContext): Promise<RuleDecision> {
    const startTime = Date.now();
    const executionContext: RuleExecutionContext = {
      requestId: context.requestId,
      timestamp: context.timestamp,
      clientIp: context.clientIp,
      method: context.method,
      ruleType: 'static',
      cacheHit: false
    };

    try {
      this.stats.totalEvaluations++;
      
      // Comprobar cache de evaluación
      const cacheKey = this.generateCacheKey(context);
      const cached = this.evaluationCache.get(cacheKey);
      
      if (cached && (Date.now() - cached.timestamp) < this.cacheExpiry) {
        cached.hits++;
        this.stats.cacheHits++;
        executionContext.cacheHit = true;
        
        this.logger.debug('Cache hit en evaluación de políticas', {
          requestId: context.requestId,
          cacheKey: cacheKey.substring(0, 16) + '...',
          hits: cached.hits
        });
        
        return cached.decision;
      }

      // Cargar reglas actuales
      let rules: StaticRules;
      try {
        rules = await this.configStore.getRules();
      } catch (error) {
        this.logger.error('Error cargando reglas, modo fail-open', { 
          error: (error as Error).message 
        });
        return { decision: "allow", reason: "rules_unavailable_fail_open" };
      }

      // Evaluación multicapa
      let decision: RuleDecision | null = null;
      
      // Capa 1: Reglas estáticas (ruta rápida)
      executionContext.ruleType = 'static';
      
      // ajgc: log para debuggear evaluación estática  
      this.logger.info('Iniciando evaluación estática', {
        requestId: context.requestId,
        method: context.method,
        clientIp: context.clientIp
      });
      
      decision = await this.evaluateStaticLayer(context, rules, executionContext);
      
      // ajgc: resultado de evaluación estática
      this.logger.info('Resultado evaluación estática', {
        requestId: context.requestId,
        decision: decision ? decision.decision : 'null',
        reason: decision ? decision.reason : 'no_decision'
      });
      
      if (!decision) {
        // Capa 2: Reglas heurísticas (análisis con estado)
        executionContext.ruleType = 'heuristic';
        
        // ajgc: echarle un ojillo a la evaluación heurística
        this.logger.info('Iniciando evaluación heurística', {
          requestId: context.requestId,
          method: context.method,
          clientIp: context.clientIp,
          enableHeuristics: this.config.enableHeuristics
        });
        
        decision = await this.evaluateHeuristicLayer(context, rules, executionContext);
        
        this.logger.info('Resultado evaluación heurística', {
          requestId: context.requestId,
          decision: decision ? decision.decision : 'null',
          reason: decision ? decision.reason : 'no_decision'
        });
      }
      
      if (!decision && this.config.enableMLDetection) {
        // Capa 3: Detección ML (análisis avanzado)
        executionContext.ruleType = 'ml';
        decision = await this.evaluateMLLayer(context, executionContext);
      }
      
      // Por defecto: permitir si ninguna regla se activó
      if (!decision) {
        decision = { 
          decision: "allow", 
          reason: "passed_all_checks",
          confidence: 0.9
        };
      }

      // Aplicar modo de enforcement
      decision = this.applyEnforcementMode(decision, rules);
      
      // Actualizar estadísticas
      this.updateStatistics(decision, executionContext);
      
      // Guardar resultado en cache
      this.evaluationCache.set(cacheKey, {
        decision,
        timestamp: Date.now(),
        hits: 1
      });
      
      // Registrar métricas de rendimiento
      const executionTime = Date.now() - startTime;
      executionContext.executionTime = executionTime;
      this.updatePerformanceMetrics(executionTime);
      
      // Emitir evento de evaluación
      this.emit('evaluated', {
        context: executionContext,
        decision,
        executionTime
      });
      
      this.logger.debug('Evaluación de políticas completada', {
        requestId: context.requestId,
        decision: decision.decision,
        reason: decision.reason,
        ruleType: executionContext.ruleType,
        executionTime: `${executionTime}ms`,
        cacheHit: executionContext.cacheHit
      });

      return decision;

    } catch (error) {
      const err = error as Error;
      const executionTime = Date.now() - startTime;
      
      this.logger.error('Error en evaluación de políticas', {
        error: err.message,
        requestId: context.requestId,
        executionTime: `${executionTime}ms`
      });
      
      // Modo fail-safe: permitir en caso de error (configurable)
      const failSafeMode = process.env.BAF_FAIL_SAFE_MODE || 'allow';
      return {
        decision: failSafeMode as 'allow' | 'block',
        reason: 'evaluation_error',
        metadata: { error: err.message }
      };
    }
  }

  /**
   * Evaluar capa de reglas estáticas
   */
  private async evaluateStaticLayer(
    context: PolicyContext, 
    rules: StaticRules, 
    execContext: RuleExecutionContext
  ): Promise<RuleDecision | null> {
    try {
      // Construir contexto legacy para reglas estáticas
      // ajgc: construir payload JSON-RPC original desde el contexto
      const originalPayload = {
        jsonrpc: "2.0" as const,
        method: context.method,
        params: context.params,
        id: context.requestId  // Usar requestId como ID
      };
      
      const staticContext = {
        payload: originalPayload,  // Usar payload JSON-RPC original
        method: context.method,
        rawTx: context.extracted.data,
        parsedTx: undefined,
        ip: context.clientIp,
        from: context.extracted.from,
        to: context.extracted.to,
        requestId: context.requestId,  // Añadir requestId para logs
        timestamp: context.timestamp   // Añadir timestamp para logs
      };

      const result = evaluateStaticRules(staticContext, rules);
      
      if (result) {
        // ajgc: seguimiento de efectividad de reglas
        this.trackRuleHit('static', result.reason || 'unknown');
        
        return {
          ...result,
          metadata: {
            ...result.metadata,
            layer: 'static',
            executionTime: Date.now() - execContext.timestamp
          }
        };
      }
      
      return null;

    } catch (error) {
      this.logger.warn('Error en evaluación de reglas estáticas', { 
        error: (error as Error).message,
        requestId: context.requestId 
      });
      return null;
    }
  }

  /**
   * Evaluar capa de reglas heurísticas
   */
  private async evaluateHeuristicLayer(
    context: PolicyContext, 
    rules: StaticRules, 
    execContext: RuleExecutionContext
  ): Promise<RuleDecision | null> {
    try {
      // ajgc: log de entrada a capa heurística
      this.logger.info('Entrando en capa heurística', {
        requestId: context.requestId,
        hasHeuristicRules: rules.heuristics ? 'sí' : 'no',
        heuristicKeys: rules.heuristics ? Object.keys(rules.heuristics) : []
      });
      
      // Construir contexto heurístico
      // ajgc: construir el payload original JSON-RPC desde el contexto
      const originalPayload = {
        jsonrpc: "2.0" as const,
        method: context.method,
        params: context.params,
        id: context.requestId  // Usar requestId como ID
      };
      
      const heuristicContext = {
        method: context.method,
        ip: context.clientIp,
        from: context.extracted.from,
        rawTx: context.extracted.data,
        payload: context.params,  // Usar params directamente para compatibilidad con detección
        timestamp: context.timestamp,
        requestId: context.requestId,
        security: context.security,
        analytics: context.analytics
      };

      const result = await evaluateHeuristicRules(heuristicContext, rules);
      
      this.logger.info('Resultado evaluación reglas heurísticas', {
        requestId: context.requestId,
        result: result ? result.decision : 'null',
        reason: result ? result.reason : 'no_decision'
      });
      
      if (result) {
        this.trackRuleHit('heuristic', result.reason || 'unknown');
        
        // Actualizar umbrales adaptativos si están habilitados
        if (this.config.adaptiveThresholds.enabled) {
          await this.updateAdaptiveThreshold(result.reason, context);
        }
        
        return {
          ...result,
          metadata: {
            ...result.metadata,
            layer: 'heuristic',
            executionTime: Date.now() - execContext.timestamp
          }
        };
      }
      
      return null;

    } catch (error) {
      this.logger.warn('Error en evaluación de reglas heurísticas', { 
        error: (error as Error).message,
        requestId: context.requestId 
      });
      return null;
    }
  }

  /**
   * Evaluar capa de detección ML
   */
  private async evaluateMLLayer(
    context: PolicyContext, 
    execContext: RuleExecutionContext
  ): Promise<RuleDecision | null> {
    try {
      // Detección de amenazas mejorada basada en ML
      const mlFeatures = this.extractMLFeatures(context);
      const threatProbability = await this.computeThreatProbability(mlFeatures);
      
      // Umbral ML (configurable)
      const mlThreshold = this.getAdaptiveThreshold('ml_threat_detection') || 0.7;
      
      if (threatProbability > mlThreshold) {
        this.trackRuleHit('ml', 'threat_detected');
        
        return {
          decision: 'block',
          reason: 'ml_threat_detection',
          confidence: threatProbability,
          metadata: {
            layer: 'ml',
            threatProbability,
            threshold: mlThreshold,
            features: mlFeatures,
            executionTime: Date.now() - execContext.timestamp
          }
        };
      }
      
      return null;

    } catch (error) {
      this.logger.warn('Error en evaluación ML', { 
        error: (error as Error).message,
        requestId: context.requestId 
      });
      return null;
    }
  }

  /**
   * Extraer características para análisis ML
   * ajgc: modelo simple de features para detección de amenazas
   */
  private extractMLFeatures(context: PolicyContext): number[] {
    const features: number[] = [];
    
    try {
      // Feature 1: Anomalía en precio de gas (0-1)
      const gasPrice = context.extracted.gasPriceWei ? Number(context.extracted.gasPriceWei) : 0;
      const avgGasPrice = Number(process.env.BAF_AVG_GAS_PRICE || 20000000000); // 20 gwei
      features.push(Math.min(gasPrice / (avgGasPrice * 10), 1));
      
      // Feature 2: Complejidad de transacción (0-1)
      features.push(context.analytics.complexity / 3);
      
      // Feature 3: Puntuación nivel de amenaza (0-1)
      const threatLevelMap = { low: 0.1, medium: 0.4, high: 0.7, critical: 1.0 };
      features.push(threatLevelMap[context.security.threatLevel] || 0.1);
      
      // Feature 4: Cantidad de factores de riesgo (0-1)
      const riskCount = Object.values(context.security.riskFactors).filter(Boolean).length;
      features.push(riskCount / 5);
      
      // Feature 5: Patrones sospechosos (0-1)
      features.push(Math.min(context.security.suspiciousPatterns.length / 10, 1));
      
      // Feature 6: Anomalía en tamaño de payload (0-1)
      const payloadSize = JSON.stringify(context).length;
      const maxNormalSize = 10000; // 10KB
      features.push(Math.min(payloadSize / maxNormalSize, 1));
      
      // Feature 7: Anomalía temporal (0-1)
      const hour = new Date(context.timestamp).getHours();
      const isOffHours = hour < 6 || hour > 22; // Fuera de horario comercial
      features.push(isOffHours ? 0.8 : 0.2);
      
      // Feature 8: Rareza del método (0-1)
      const commonMethods = ['eth_call', 'eth_getBalance', 'eth_sendTransaction'];
      const isRareMethod = !commonMethods.includes(context.method);
      features.push(isRareMethod ? 0.9 : 0.1);

    } catch (error) {
      this.logger.warn('Error en extracción de características', { 
        error: (error as Error).message 
      });
      // Devolver características por defecto seguras
      return [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1];
    }
    
    return features;
  }

  /**
   * Calcular probabilidad de amenaza usando modelo ML simple
   */
  private async computeThreatProbability(features: number[]): Promise<number> {
    try {
      // Modelo de suma ponderada simple (en producción, usar modelo ML entrenado)
      const weights = [0.15, 0.20, 0.25, 0.15, 0.10, 0.05, 0.05, 0.05];
      
      let probability = 0;
      for (let i = 0; i < Math.min(features.length, weights.length); i++) {
        probability += features[i] * weights[i];
      }
      
      // Aplicar función sigmoide para mejor distribución de probabilidades
      probability = 1 / (1 + Math.exp(-10 * (probability - 0.5)));
      
      return Math.max(0, Math.min(1, probability));

    } catch (error) {
      this.logger.warn('Error en cálculo de probabilidad de amenaza', { 
        error: (error as Error).message 
      });
      return 0.1; // Por defecto seguro
    }
  }

  /**
   * Aplicar modo de enforcement a la decisión
   */
  private applyEnforcementMode(decision: RuleDecision, rules: StaticRules): RuleDecision {
    const enforcementMode = this.config.enforcementMode || rules.enforcement?.mode || 'block';
    
    if (enforcementMode === 'monitor' || enforcementMode === 'dry-run') {
      if (decision.decision === 'block') {
        return {
          ...decision,
          decision: 'monitor',
          reason: `${enforcementMode}:${decision.reason}`,
          metadata: {
            ...decision.metadata,
            originalDecision: 'block',
            enforcementMode
          }
        };
      }
    }
    
    return decision;
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(executionTime: number): void {
    // Update average execution time
    const alpha = 0.1; // Exponential moving average factor
    this.stats.averageEvaluationTime = 
      this.stats.averageEvaluationTime * (1 - alpha) + executionTime * alpha;
    
    // Record in performance monitor
    if (this.performanceMonitor) {
      this.performanceMonitor.recordRequest({
        processingTime: executionTime,
        requestCount: 1,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Update statistics
   */
  private updateStatistics(decision: RuleDecision, context: RuleExecutionContext): void {
    switch (decision.decision) {
      case 'block':
        this.stats.blockedRequests++;
        break;
      case 'monitor':
        this.stats.monitoredRequests++;
        break;
      case 'allow':
        this.stats.allowedRequests++;
        break;
    }
  }

  /**
   * Track rule hit rates
   */
  private trackRuleHit(layer: string, reason: string): void {
    const key = `${layer}:${reason}`;
    const current = this.stats.ruleHitRate.get(key) || 0;
    this.stats.ruleHitRate.set(key, current + 1);
  }

  /**
   * Generate cache key for evaluation context
   */
  private generateCacheKey(context: PolicyContext): string {
    const keyData = {
      method: context.method,
      from: context.extracted.from,
      to: context.extracted.to,
      payloadHash: context.analytics.payloadHash.substring(0, 16), // First 16 chars
      threatLevel: context.security.threatLevel
    };
    
    return require('crypto')
      .createHash('md5')
      .update(JSON.stringify(keyData))
      .digest('hex');
  }

  /**
   * Initialize adaptive thresholds
   */
  private async initializeAdaptiveThresholds(): Promise<void> {
    try {
      const thresholdKeys = [
        'ml_threat_detection',
        'rate_limit_threshold',
        'gas_price_anomaly',
        'payload_size_threshold'
      ];

      for (const key of thresholdKeys) {
        this.adaptiveThresholds.set(key, {
          value: 0.5, // Default threshold
          confidence: 0.5,
          lastUpdate: Date.now(),
          samples: []
        });
      }

      this.logger.debug('Adaptive thresholds initialized', {
        thresholds: thresholdKeys
      });

    } catch (error) {
      this.logger.error('Failed to initialize adaptive thresholds', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Update adaptive threshold based on feedback
   */
  private async updateAdaptiveThreshold(reason: string, context: PolicyContext): Promise<void> {
    if (!this.config.adaptiveThresholds.enabled) return;

    try {
      const threshold = this.adaptiveThresholds.get(reason);
      if (!threshold) return;

      // Simple adaptive learning (in production, use more sophisticated algorithms)
      const learningRate = this.config.adaptiveThresholds.learningRate;
      const feedback = context.security.threatLevel === 'high' ? 1 : 0;
      
      // Update threshold using exponential moving average
      threshold.value = threshold.value * (1 - learningRate) + feedback * learningRate;
      threshold.confidence = Math.min(threshold.confidence + 0.01, 1);
      threshold.lastUpdate = Date.now();
      threshold.samples.push(feedback);
      
      // Keep only recent samples
      if (threshold.samples.length > 1000) {
        threshold.samples.shift();
      }
      
      this.adaptiveThresholds.set(reason, threshold);

    } catch (error) {
      this.logger.warn('Failed to update adaptive threshold', {
        error: (error as Error).message,
        reason
      });
    }
  }

  /**
   * Get adaptive threshold value
   */
  private getAdaptiveThreshold(key: string): number | null {
    const threshold = this.adaptiveThresholds.get(key);
    return threshold ? threshold.value : null;
  }

  /**
   * Setup cache cleanup
   */
  private setupCacheCleanup(): void {
    const cleanupInterval = Number(process.env.BAF_POLICY_CACHE_CLEANUP_INTERVAL || 300000); // 5 minutes
    
    setInterval(() => {
      const now = Date.now();
      let cleaned = 0;
      
      for (const [key, entry] of this.evaluationCache.entries()) {
        if (now - entry.timestamp > this.cacheExpiry) {
          this.evaluationCache.delete(key);
          cleaned++;
        }
      }
      
      if (cleaned > 0) {
        this.logger.debug('Policy cache cleanup completed', {
          cleaned,
          remaining: this.evaluationCache.size
        });
      }
    }, cleanupInterval);
  }

  /**
   * Setup adaptive threshold updates
   */
  private setupAdaptiveThresholdUpdates(): void {
    if (!this.config.adaptiveThresholds.enabled) return;

    const updateInterval = this.config.adaptiveThresholds.adaptationInterval;
    
    setInterval(() => {
      this.optimizeThresholds();
    }, updateInterval);
  }

  /**
   * Optimize thresholds based on performance data
   */
  private optimizeThresholds(): void {
    try {
      const now = Date.now();
      
      // Simple threshold optimization based on false positive/negative rates
      // In production, use more sophisticated ML-based optimization
      
      for (const [key, threshold] of this.adaptiveThresholds.entries()) {
        if (threshold.samples.length < 10) continue;
        
        const recentSamples = threshold.samples.slice(-100);
        const positiveRate = recentSamples.filter(s => s === 1).length / recentSamples.length;
        
        // Adjust threshold based on positive rate
        if (positiveRate > 0.8) {
          threshold.value = Math.min(threshold.value + 0.05, 0.95);
        } else if (positiveRate < 0.2) {
          threshold.value = Math.max(threshold.value - 0.05, 0.05);
        }
        
        threshold.lastUpdate = now;
      }
      
      this.stats.lastOptimization = now;
      
      this.logger.debug('Threshold optimization completed', {
        thresholds: Array.from(this.adaptiveThresholds.entries()).map(([key, value]) => ({
          key,
          value: value.value,
          confidence: value.confidence,
          samples: value.samples.length
        }))
      });

    } catch (error) {
      this.logger.error('Threshold optimization failed', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Handle rule updates
   */
  public async onRulesUpdated(): Promise<void> {
    try {
      // Clear evaluation cache on rule updates
      this.evaluationCache.clear();
      
      // Reset adaptive thresholds if configured
      if (this.config.adaptiveThresholds.enabled) {
        await this.initializeAdaptiveThresholds();
      }
      
      // Solo hacer log si han pasado al menos 1 segundo desde el último update
      const now = Date.now();
      if (!this.lastRuleUpdateLog || (now - this.lastRuleUpdateLog) > 1000) {
        this.logger.info('Policy engine updated after rule changes');
        this.lastRuleUpdateLog = now;
      }
      
    } catch (error) {
      this.logger.error('Failed to handle rule update', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Public interface methods
   */
  public async updateRules(rules: any): Promise<void> {
    return this.configStore.setRules(rules);
  }

  public async getRules(): Promise<any> {
    return this.configStore.getRules();
  }

  public isHealthy(): boolean {
    return this.initialized && this.configStore.isHealthy();
  }

  public async getMetrics(): Promise<{
    totalEvaluations: number;
    blockedRequests: number;
    averageEvaluationTime: number;
    ruleHitRate: { [ruleName: string]: number };
  }> {
    const ruleHitRate: { [ruleName: string]: number } = {};
    
    for (const [key, value] of this.stats.ruleHitRate.entries()) {
      ruleHitRate[key] = value;
    }
    
    return {
      totalEvaluations: this.stats.totalEvaluations,
      blockedRequests: this.stats.blockedRequests,
      averageEvaluationTime: this.stats.averageEvaluationTime,
      ruleHitRate
    };
  }

  public async cleanup(): Promise<void> {
    this.evaluationCache.clear();
    this.adaptiveThresholds.clear();
    this.stats.ruleHitRate.clear();
    
    this.logger.info('🧹 Policy Engine cleanup completed');
  }
}

export default PolicyEngine;
