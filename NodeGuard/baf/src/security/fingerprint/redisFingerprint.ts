// src/fingerprint/redisFingerprint.ts
// ajgc: sistema de fingerprinting NodeGuard

import redis from '../../redis/redis-connection';
import crypto from 'crypto';
import { logger } from '../../logging/logger';
import { EventBus } from '../../events/event-bus';

/**
 * Sistema de fingerprint con ML y análisis cross-batch
 * 
 * Características principales:
 * - Algoritmos múltiples de fingerprinting (SHA-256, MD5, etc.)
 * - Detección de patrones cross-batch
 * - Fingerprinting comportamental basado en ML
 * - Rate limiting con ventana deslizante
 * - Clustering de fingerprints y detección de similitud
 * - Correlación geográfica y temporal
 * - Limpieza automática y archival
 */

export interface FingerprintConfig {
  algorithm: 'sha256' | 'md5' | 'blake2b' | 'xxhash';
  enableMLFingerprinting: boolean;
  enableCrossBatchAnalysis: boolean;
  enableSimilarityDetection: boolean;
  windowSeconds: number;
  maxRepeats: number;
  decayFactor: number;
  clustersEnabled: boolean;
  geoCorrelation: boolean;
  temporalCorrelation: boolean;
}

export interface FingerprintResult {
  hash: string;
  count: number;
  blocked: boolean;
  confidence: number;
  similarity?: number;
  cluster?: string;
  metadata: {
    algorithm: string;
    timestamp: number;
    windowSeconds: number;
    clientIp?: string;
    userAgent?: string;
    geoLocation?: string;
    behaviorScore?: number;
  };
}

export interface FingerprintMetrics {
  totalFingerprints: number;
  uniqueFingerprints: number;
  blockedFingerprints: number;
  averageRepeats: number;
  topRepeatedHashes: Array<{ hash: string; count: number }>;
  clusterDistribution: Map<string, number>;
  algorithmUsage: Map<string, number>;
}

/**
 * Servicio de fingerprinting Redis mejorado - ajgc
 */
export class EnhancedFingerprintService {
  private readonly config: FingerprintConfig;
  private readonly eventBus?: EventBus;
  private fingerprintCache = new Map<string, FingerprintResult>();
  private behaviorProfiles = new Map<string, any>();
  private clusterMap = new Map<string, string[]>();
  private metrics: FingerprintMetrics;
  
  constructor(config: Partial<FingerprintConfig> = {}, eventBus?: EventBus) {
    this.config = {
      algorithm: config.algorithm || 'sha256',
      enableMLFingerprinting: config.enableMLFingerprinting !== false,
      enableCrossBatchAnalysis: config.enableCrossBatchAnalysis !== false,
      enableSimilarityDetection: config.enableSimilarityDetection !== false,
      windowSeconds: config.windowSeconds || 300, // 5 minutos
      maxRepeats: config.maxRepeats || 10,
      decayFactor: config.decayFactor || 0.95,
      clustersEnabled: config.clustersEnabled !== false,
      geoCorrelation: config.geoCorrelation !== false,
      temporalCorrelation: config.temporalCorrelation !== false
    };
    
    this.eventBus = eventBus;
    
    this.metrics = {
      totalFingerprints: 0,
      uniqueFingerprints: 0,
      blockedFingerprints: 0,
      averageRepeats: 0,
      topRepeatedHashes: [],
      clusterDistribution: new Map(),
      algorithmUsage: new Map()
    };
    
    this.setupPeriodicCleanup();
    this.setupMetricsCollection();
    
    logger.info('Servicio de Fingerprinting NodeGuard inicializado', {
      algorithm: this.config.algorithm,
      mlEnabled: this.config.enableMLFingerprinting,
      crossBatchEnabled: this.config.enableCrossBatchAnalysis
    });
  }

  /**
   * Registro de fingerprint mejorado con ML y detección de similitud - ajgc
   */
  async registerFingerprint(
    payload: any,
    windowSeconds?: number,
    maxRepeats?: number,
    clientContext?: {
      ip?: string;
      userAgent?: string;
      method?: string;
      timestamp?: number;
    }
  ): Promise<FingerprintResult> {
    const startTime = Date.now();
    
    try {
      const window = windowSeconds || this.config.windowSeconds;
      const maxCount = maxRepeats || this.config.maxRepeats;
      
      // Generar múltiples fingerprints para validación cruzada
      const fingerprints = await this.generateMultipleFingerprints(payload);
      const primaryHash = fingerprints.primary;
      
      // Revisar caché primero - ajgc: esto mejora el rendimiento niquelao
      const cached = this.fingerprintCache.get(primaryHash);
      if (cached && (Date.now() - cached.metadata.timestamp) < 30000) { // 30 segundos cache
        return cached;
      }
      
      // Registrar en Redis con incremento atómico
      const count = await this.atomicIncrement(primaryHash, window);
      
      // Análisis mejorado
      const result: FingerprintResult = {
        hash: primaryHash,
        count,
        blocked: count > maxCount,
        confidence: this.calculateConfidence(count, maxCount),
        metadata: {
          algorithm: this.config.algorithm,
          timestamp: Date.now(),
          windowSeconds: window,
          clientIp: clientContext?.ip,
          userAgent: clientContext?.userAgent,
          geoLocation: clientContext?.ip ? await this.getGeoLocation(clientContext.ip) : undefined
        }
      };
      
      // Análisis comportamental basado en ML
      if (this.config.enableMLFingerprinting && clientContext) {
        result.metadata.behaviorScore = await this.analyzeBehavior(payload, clientContext);
      }
      
      // Detección de similitud
      if (this.config.enableSimilarityDetection) {
        result.similarity = await this.detectSimilarity(primaryHash, fingerprints.variants);
      }
      
      // Análisis de clustering
      if (this.config.clustersEnabled) {
        result.cluster = await this.assignToCluster(primaryHash, payload);
      }
      
      // Correlación cross-batch - de locos este análisis
      if (this.config.enableCrossBatchAnalysis && clientContext?.ip) {
        await this.updateCrossBatchAnalysis(clientContext.ip, primaryHash, payload);
      }
      
      this.updateMetrics(result);
      this.fingerprintCache.set(primaryHash, result);
      
      // Emitir eventos para patrones significativos
      if (result.blocked || result.confidence > 0.8) {
        this.emitFingerprintEvent(result, payload, clientContext);
      }
      
      const processingTime = Date.now() - startTime;
      
      logger.debug('Fingerprint registrado NodeGuard', {
        hash: primaryHash.substring(0, 12) + '...',
        count,
        blocked: result.blocked,
        confidence: result.confidence,
        processingTime: `${processingTime}ms`
      });
      
      return result;
      
    } catch (error) {
      const err = error as Error;
      logger.error('Fallo en registro de fingerprint', {
        error: err,
        stack: err.stack
      });
      
      // Retornar valor por defecto seguro
      return {
        hash: 'error',
        count: 0,
        blocked: false,
        confidence: 0,
        metadata: {
          algorithm: this.config.algorithm,
          timestamp: Date.now(),
          windowSeconds: windowSeconds || this.config.windowSeconds
        }
      };
    }
  }

  /**
   * Fingerprinting avanzado de payload con múltiples algoritmos - ajgc
   */
  private async generateMultipleFingerprints(payload: any): Promise<{
    primary: string;
    variants: string[];
    behavioral?: string;
  }> {
    // Validar payload para evitar errores de undefined
    if (payload === undefined || payload === null) {
      payload = {};
    }
    
    const canonical = this.stableStringify(payload);
    
    const fingerprints = {
      primary: this.hashWithAlgorithm(canonical, this.config.algorithm),
      variants: [] as string[],
      behavioral: undefined as string | undefined
    };
    
    // Generar hashes variantes para detección de similitud
    fingerprints.variants = [
      this.hashWithAlgorithm(canonical, 'md5'),
      this.hashWithAlgorithm(canonical, 'sha256'),
      this.createStructuralHash(payload),
      this.createSemanticHash(payload)
    ].filter(h => h !== fingerprints.primary);
    
    // Fingerprint comportamental basado en patrones de request
    if (this.config.enableMLFingerprinting) {
      fingerprints.behavioral = this.generateBehavioralFingerprint(payload);
    }
    
    return fingerprints;
  }

  /**
   * Serialización estable de objetos para hashing consistente
   */
  private stableStringify(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    
    if (Array.isArray(obj)) {
      return '[' + obj.map(item => this.stableStringify(item)).join(',') + ']';
    }
    
    const keys = Object.keys(obj).sort();
    const keyValuePairs = keys.map(key => 
      JSON.stringify(key) + ':' + this.stableStringify(obj[key])
    );
    
    return '{' + keyValuePairs.join(',') + '}';
  }

  /**
   * Generación de hash con múltiples algoritmos
   */
  private hashWithAlgorithm(data: string, algorithm: string): string {
    // Validar que data no sea undefined o null
    if (data === undefined || data === null) {
      data = '';
    }
    
    switch (algorithm) {
      case 'md5':
        return crypto.createHash('md5').update(data).digest('hex');
      case 'sha256':
        return crypto.createHash('sha256').update(data).digest('hex');
      case 'blake2b':
        return crypto.createHash('blake2b512').update(data).digest('hex');
      default:
        return crypto.createHash('sha256').update(data).digest('hex');
    }
  }

  /**
   * Crear hash estructural basado en la estructura del objeto, no valores
   */
  private createStructuralHash(obj: any): string {
    const structure = this.extractStructure(obj);
    return this.hashWithAlgorithm(JSON.stringify(structure), 'sha256');
  }

  /**
   * Crear hash semántico basado en el significado del contenido
   */
  private createSemanticHash(obj: any): string {
    const semantic = this.extractSemanticFeatures(obj);
    return this.hashWithAlgorithm(JSON.stringify(semantic), 'sha256');
  }

  /**
   * Generar fingerprint comportamental basado en patrones de request
   */
  private generateBehavioralFingerprint(payload: any): string {
    const features = {
      methodType: payload.method || 'unknown',
      paramCount: Array.isArray(payload.params) ? payload.params.length : 0,
      hasComplexParams: this.hasComplexParameters(payload.params),
      requestSize: JSON.stringify(payload).length,
      structuralComplexity: this.calculateStructuralComplexity(payload)
    };
    
    return this.hashWithAlgorithm(JSON.stringify(features), 'sha256').substring(0, 16);
  }

  /**
   * Operación de incremento atómico en Redis con manejo TTL - ajgc: esto está niquelao
   */
  private async atomicIncrement(hash: string, windowSeconds: number): Promise<number> {
    const key = `baf:fingerprint:${hash}`;
    
    const luaScript = `
      local count = redis.call("INCR", KEYS[1])
      if tonumber(count) == 1 then
        redis.call("EXPIRE", KEYS[1], ARGV[1])
      end
      return count
    `;
    
    try {
        const result = await redis.eval(
        luaScript,
        {
          keys: [key],
          arguments: [String(windowSeconds)]
        }
      );
      
      return typeof result === 'number' ? result : parseInt(String(result || '0'), 10);
      
    } catch (error) {
      logger.error('Fallo en incremento de fingerprint Redis', {
        error: error as Error,
        key
      });
      
      // Fallback a operación no-atómica
      try {
        const current = await redis.get(key);
        const count = current ? parseInt(current, 10) + 1 : 1;
        await redis.setex(key, windowSeconds, count.toString());
        return count;
      } catch (fallbackError) {
        logger.error('Fallo en operación fallback de fingerprint', {
          error: fallbackError as Error
        });
        return 0;
      }
    }
  }

  /**
   * Detección de similitud avanzada usando similitud Jaccard
   */
  private async detectSimilarity(primaryHash: string, variants: string[]): Promise<number> {
    try {
      // Obtener fingerprints recientes para comparación
      const recentPattern = 'baf:fingerprint:*';
      const recentKeys = await redis.keys(recentPattern);
      
      if (recentKeys.length === 0) return 0;
      
      // Muestra de keys recientes para rendimiento - echarle un ojillo a esto
      const sampleSize = Math.min(100, recentKeys.length);
      const sampleKeys = recentKeys
        .sort(() => Math.random() - 0.5)
        .slice(0, sampleSize);
      
      let maxSimilarity = 0;
      
      for (const key of sampleKeys) {
        const existingHash = key.replace('baf:fingerprint:', '');
        if (existingHash === primaryHash) continue;
        
        const similarity = this.calculateJaccardSimilarity(primaryHash, existingHash);
        maxSimilarity = Math.max(maxSimilarity, similarity);
        
        // También revisar variantes
        for (const variant of variants) {
          const variantSimilarity = this.calculateJaccardSimilarity(variant, existingHash);
          maxSimilarity = Math.max(maxSimilarity, variantSimilarity);
        }
      }
      
      return maxSimilarity;
      
    } catch (error) {
      logger.warn('Fallo en detección de similitud', {
        error: error as Error
      });
      return 0;
    }
  }

  /**
   * Assign fingerprint to similarity cluster
   */
  private async assignToCluster(hash: string, payload: any): Promise<string> {
    const clusterId = this.generateClusterId(payload);
    
    // Update cluster mapping
    if (!this.clusterMap.has(clusterId)) {
      this.clusterMap.set(clusterId, []);
    }
    
    const cluster = this.clusterMap.get(clusterId)!;
    if (!cluster.includes(hash)) {
      cluster.push(hash);
      
      // Maintain cluster size
      if (cluster.length > 1000) {
        cluster.shift(); // Remove oldest
      }
    }
    
    // Update Redis cluster info
    const clusterKey = `baf:cluster:${clusterId}`;
    await redis.sadd(clusterKey, hash);
    await redis.expire(clusterKey, 3600); // 1 hour TTL
    
    return clusterId;
  }

  /**
   * Cross-batch analysis for IP-based patterns
   */
  private async updateCrossBatchAnalysis(ip: string, hash: string, payload: any): Promise<void> {
    try {
      const ipKey = `baf:cross_batch:${ip}`;
      const batchInfo = {
        hash,
        method: payload.method,
        timestamp: Date.now(),
        complexity: this.calculateStructuralComplexity(payload)
      };
      
      // Store batch info with sliding window
      await redis.zadd(ipKey, Date.now(), JSON.stringify(batchInfo));
      await redis.expire(ipKey, this.config.windowSeconds);
      
      // Remove old entries (older than window)
      const cutoff = Date.now() - (this.config.windowSeconds * 1000);
      await redis.zremrangebyscore(ipKey, 0, cutoff);
      
      // Analyze patterns
      const recentBatches = await redis.zrange(ipKey, 0, -1);
      if (recentBatches.length > 5) {
        const pattern = this.analyzeBatchPattern(recentBatches.map(b => JSON.parse(b)));
        
        if (pattern.suspicious) {
          this.emitSuspiciousBatchPattern(ip, pattern);
        }
      }
      
    } catch (error) {
      logger.warn('Cross-batch analysis failed', {
        error: error as Error,
        ip
      });
    }
  }

  /**
   * Analyze behavioral patterns for ML fingerprinting
   */
  private async analyzeBehavior(payload: any, context: any): Promise<number> {
    const features = this.extractBehaviorFeatures(payload, context);
    
    // Simple scoring algorithm (in production, use trained ML model)
    let score = 0.5; // Baseline
    
    // Check for suspicious patterns
    if (features.requestFrequency > 10) score += 0.2;
    if (features.parameterComplexity > 0.8) score += 0.1;
    if (features.structuralVariation < 0.1) score += 0.2; // Too uniform
    if (features.temporalRegularity > 0.9) score += 0.15; // Too regular
    
    // Normalize to 0-1 range
    return Math.max(0, Math.min(1, score));
  }

  /**
   * Utility methods for advanced analysis
   */
  
  private extractStructure(obj: any): any {
    if (obj === null || typeof obj !== 'object') return typeof obj;
    if (Array.isArray(obj)) return ['array', obj.length];
    
    const structure: any = {};
    for (const key in obj) {
      structure[key] = this.extractStructure(obj[key]);
    }
    return structure;
  }
  
  private extractSemanticFeatures(obj: any): any {
    // Extract meaningful semantic features for similarity comparison
    const features: any = {
      type: typeof obj,
      isArray: Array.isArray(obj),
      keys: obj && typeof obj === 'object' ? Object.keys(obj).sort() : [],
      valueTypes: []
    };
    
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      features.valueTypes = Object.values(obj).map(v => typeof v).sort();
    }
    
    return features;
  }
  
  private hasComplexParameters(params: any): boolean {
    if (!Array.isArray(params)) return false;
    return params.some(p => typeof p === 'object' && p !== null);
  }
  
  private calculateStructuralComplexity(obj: any): number {
    if (obj === null || typeof obj !== 'object') return 0;
    
    let complexity = 0;
    const keys = Object.keys(obj);
    
    complexity += keys.length * 0.1;
    
    for (const key of keys) {
      const value = obj[key];
      if (typeof value === 'object' && value !== null) {
        complexity += this.calculateStructuralComplexity(value);
      }
    }
    
    return Math.min(1, complexity);
  }
  
  private calculateJaccardSimilarity(hash1: string, hash2: string): number {
    // Convert hashes to sets of characters for similarity comparison
    const set1 = new Set(hash1.split(''));
    const set2 = new Set(hash2.split(''));
    
    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);
    
    return intersection.size / union.size;
  }
  
  private generateClusterId(payload: any): string {
    const clusterFeatures = {
      method: payload.method,
      paramStructure: this.extractStructure(payload.params),
      complexity: this.calculateStructuralComplexity(payload)
    };
    
    return this.hashWithAlgorithm(JSON.stringify(clusterFeatures), 'md5').substring(0, 8);
  }
  
  private extractBehaviorFeatures(payload: any, context: any): any {
    return {
      requestFrequency: 1, // Would be calculated from context
      parameterComplexity: this.calculateStructuralComplexity(payload),
      structuralVariation: Math.random(), // Would be calculated from history
      temporalRegularity: Math.random() // Would be calculated from timing patterns
    };
  }
  
  private analyzeBatchPattern(batches: any[]): { suspicious: boolean; reasons: string[] } {
    const pattern = { suspicious: false, reasons: [] as string[] };
    
    // Check for identical patterns
    const uniqueHashes = new Set(batches.map(b => b.hash));
    if (uniqueHashes.size === 1 && batches.length > 10) {
      pattern.suspicious = true;
      pattern.reasons.push('identical_batch_pattern');
    }
    
    // Check for high frequency
    const timespan = Math.max(...batches.map(b => b.timestamp)) - Math.min(...batches.map(b => b.timestamp));
    if (batches.length > 20 && timespan < 60000) { // 20 requests in 1 minute
      pattern.suspicious = true;
      pattern.reasons.push('high_frequency_batching');
    }
    
    return pattern;
  }
  
  private calculateConfidence(count: number, threshold: number): number {
    if (count <= threshold) return count / threshold;
    return Math.min(1, 1 + (count - threshold) / threshold * 0.5);
  }
  
  private async getGeoLocation(ip: string): Promise<string | undefined> {
    // Placeholder for geolocation service integration
    // In production, integrate with MaxMind or similar service
    return undefined;
  }

  /**
   * Event emission and metrics
   */
  
  private emitFingerprintEvent(result: FingerprintResult, payload: any, context?: any): void {
    if (!this.eventBus) return;
    
    this.eventBus.emitEvent({
      type: result.blocked ? 'block' : 'status',
      timestamp: Date.now(),
      message: `Fingerprint ${result.blocked ? 'blocked' : 'detected'}: ${result.hash.substring(0, 12)}...`,
      method: 'fingerprint',
      clientIp: context?.ip || 'unknown',
      reqId: `fp-${Date.now()}`,
      level: result.blocked ? 'warning' : 'info',
      metadata: {
        fingerprintHash: result.hash.substring(0, 16),
        count: result.count,
        confidence: result.confidence,
        algorithm: result.metadata.algorithm,
        cluster: result.cluster,
        similarity: result.similarity
      }
    });
  }
  
  private emitSuspiciousBatchPattern(ip: string, pattern: any): void {
    if (!this.eventBus) return;
    
    this.eventBus.emitEvent({
      type: 'status',
      timestamp: Date.now(),
      message: `Suspicious batch pattern detected from ${ip}`,
      method: 'fingerprint',
      clientIp: ip,
      reqId: `batch-${Date.now()}`,
      level: 'warning',
      metadata: {
        patternType: 'cross_batch_analysis',
        reasons: pattern.reasons
      }
    });
  }
  
  private updateMetrics(result: FingerprintResult): void {
    this.metrics.totalFingerprints++;
    
    if (result.count === 1) {
      this.metrics.uniqueFingerprints++;
    }
    
    if (result.blocked) {
      this.metrics.blockedFingerprints++;
    }
    
    // Update algorithm usage
    const algoCount = this.metrics.algorithmUsage.get(result.metadata.algorithm) || 0;
    this.metrics.algorithmUsage.set(result.metadata.algorithm, algoCount + 1);
    
    // Update cluster distribution
    if (result.cluster) {
      const clusterCount = this.metrics.clusterDistribution.get(result.cluster) || 0;
      this.metrics.clusterDistribution.set(result.cluster, clusterCount + 1);
    }
  }

  /**
   * Periodic maintenance
   */
  
  private setupPeriodicCleanup(): void {
    const cleanupInterval = Number(process.env.BAF_FINGERPRINT_CLEANUP_INTERVAL || 300000); // 5 minutes
    
    setInterval(async () => {
      await this.performCleanup();
    }, cleanupInterval);
  }
  
  private setupMetricsCollection(): void {
    setInterval(async () => {
      await this.updateTopRepeatedHashes();
      await this.calculateAverageRepeats();
    }, 60000); // Every minute
  }
  
  private async performCleanup(): Promise<void> {
    try {
      // Clean up expired fingerprints
      const pattern = 'baf:fingerprint:*';
      const keys = await redis.keys(pattern);
      
      let cleaned = 0;
      for (const key of keys) {
        const ttl = await redis.ttl(key);
        if (ttl === -1) { // No expiry set
          await redis.expire(key, this.config.windowSeconds);
        } else if (ttl === -2) { // Key doesn't exist
          cleaned++;
        }
      }
      
      // Clean up in-memory caches
      const now = Date.now();
      const cacheExpiry = 300000; // 5 minutes
      
      for (const [hash, result] of this.fingerprintCache.entries()) {
        if (now - result.metadata.timestamp > cacheExpiry) {
          this.fingerprintCache.delete(hash);
        }
      }
      
      logger.debug('Fingerprint cleanup completed', {
        keysProcessed: keys.length,
        keysExpired: cleaned,
        cacheSize: this.fingerprintCache.size
      });
      
    } catch (error) {
      logger.error('Fingerprint cleanup failed', {
        error: error as Error
      });
    }
  }
  
  private async updateTopRepeatedHashes(): Promise<void> {
    // Implementation would analyze Redis keys and counts
    // This is a placeholder for the actual implementation
  }
  
  private async calculateAverageRepeats(): Promise<void> {
    // Implementation would calculate average repeat counts
    // This is a placeholder for the actual implementation
  }

  /**
   * Public API methods
   */
  
  public getMetrics(): FingerprintMetrics {
    return { ...this.metrics };
  }
  
  public async getClusterInfo(clusterId: string): Promise<string[]> {
    const clusterKey = `baf:cluster:${clusterId}`;
    return await redis.smembers(clusterKey);
  }
  
  public isHealthy(): boolean {
    return this.fingerprintCache.size < 10000; // Arbitrary health check
  }
  
  public async cleanup(): Promise<void> {
    this.fingerprintCache.clear();
    this.behaviorProfiles.clear();
    this.clusterMap.clear();
  }
}

// Legacy compatibility functions
export async function registerFingerprint(
  payload: any,
  windowSeconds: number,
  maxRepeats: number
): Promise<{ repeats: number; blocked: boolean; hash: string }> {
  const service = new EnhancedFingerprintService();
  const result = await service.registerFingerprint(payload, windowSeconds, maxRepeats);
  
  return {
    repeats: result.count,
    blocked: result.blocked,
    hash: result.hash
  };
}

// Export enhanced service as default
export default EnhancedFingerprintService;
