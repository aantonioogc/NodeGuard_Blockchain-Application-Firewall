// src/rateLimiting/rate-limiter.ts
// Rate Limiter Unificado - NodeGuard TFG BAF
// ajgc: interfaz única para todos los algoritmos de rate limiting
import { EventEmitter } from 'events';
import { SlidingWindowLimiter } from './algorithms/slidingWindow';
import { TokenBucketLimiter } from './algorithms/tokenBucket';
import { FixedWindowLimiter } from './algorithms/fixedWindow';
import { 
  RateLimitResult, 
  RateLimitConfig, 
  RateLimitOptions, 
  RateLimitAlgorithmType 
} from './types';
import { logger } from '../logging/logger';

/**
 * Rate Limiter unificado NodeGuard
 * Selección automática del mejor algoritmo según la config
 */
export class RateLimiter extends EventEmitter {
  private slidingWindow: SlidingWindowLimiter;
  private tokenBucket: TokenBucketLimiter;
  private fixedWindow: FixedWindowLimiter;
  
  // ajgc: métricas básicas para el dashboard
  private metrics = {
    totalChecks: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    algorithmUsage: new Map<RateLimitAlgorithmType, number>(),
    averageLatency: 0,
    errors: 0
  };

  constructor() {
    super();
    
    this.slidingWindow = new SlidingWindowLimiter();
    this.tokenBucket = new TokenBucketLimiter();
    this.fixedWindow = new FixedWindowLimiter();
    
    this.setupEventHandlers();
    
    logger.info('Rate Limiter NodeGuard inicializado');
  }

  /**
   * Chequear rate limit con algoritmo especificado o auto-seleccionado
   */
  async checkLimit(
    key: string,
    config: RateLimitConfig,
    options?: RateLimitOptions
  ): Promise<RateLimitResult> {
    const startTime = Date.now();
    
    try {
      this.metrics.totalChecks++;
      
      // Auto-seleccionar algoritmo si no se especifica
      const algorithm = options?.algorithm || this.selectAlgorithm(config, options);
      
      let result: RateLimitResult;
      
      switch (algorithm) {
        case RateLimitAlgorithmType.SLIDING_WINDOW:
          result = await this.slidingWindow.checkLimit(key, config, options);
          break;
          
        case RateLimitAlgorithmType.TOKEN_BUCKET:
          result = await this.tokenBucket.checkLimit(key, config, options);
          break;
          
        case RateLimitAlgorithmType.FIXED_WINDOW:
          result = await this.fixedWindow.checkLimit(key, config, options);
          break;
          
        default:
          throw new Error(`Algoritmo desconocido: ${algorithm}`);
      }
      
      this.updateMetrics(result, algorithm, Date.now() - startTime);
      this.emit(result.allowed ? 'allowed' : 'blocked', result);
      
      return result;
      
    } catch (error) {
      this.metrics.errors++;
      const err = error as Error;
      
      logger.error('Error en rate limit check', {
        error: err,
        metadata: { key, config, options }
      });
      
      this.emit('error', error, { key, config, options });
      
      // ajgc: fail-open, mejor permitir que bloquear mal
      return {
        allowed: true,
        count: 0,
        remaining: config.maxRequests,
        resetTime: Date.now() + config.windowMs,
        windowStart: Date.now() - config.windowMs,
        windowEnd: Date.now() + config.windowMs,
        algorithm: RateLimitAlgorithmType.FIXED_WINDOW,
        key
      };
    }
  }

  // ajgc: métodos de conveniencia para usar cada algoritmo directamente
  async slidingWindowLimit(
    key: string,
    windowMs: number,
    maxRequests: number,
    options?: Partial<RateLimitOptions>
  ): Promise<RateLimitResult> {
    return this.checkLimit(key, { windowMs, maxRequests }, {
      ...options,
      algorithm: RateLimitAlgorithmType.SLIDING_WINDOW
    });
  }

  async tokenBucketLimit(
    key: string,
    capacity: number,
    refillRate: number,
    tokensRequested: number = 1,
    options?: Partial<RateLimitOptions>
  ): Promise<RateLimitResult> {
    return this.checkLimit(key, { windowMs: 60000, maxRequests: capacity }, {
      ...options,
      algorithm: RateLimitAlgorithmType.TOKEN_BUCKET,
      capacity,
      refillRate
    });
  }

  async fixedWindowLimit(
    key: string,
    windowMs: number,
    maxRequests: number,
    options?: Partial<RateLimitOptions>
  ): Promise<RateLimitResult> {
    return this.checkLimit(key, { windowMs, maxRequests }, {
      ...options,
      algorithm: RateLimitAlgorithmType.FIXED_WINDOW
    });
  }

  async reset(key: string, algorithm?: RateLimitAlgorithmType): Promise<void> {
    if (algorithm) {
      switch (algorithm) {
        case RateLimitAlgorithmType.SLIDING_WINDOW:
          await this.slidingWindow.reset(key);
          break;
        case RateLimitAlgorithmType.TOKEN_BUCKET:
          await this.tokenBucket.reset(key);
          break;
        case RateLimitAlgorithmType.FIXED_WINDOW:
          await this.fixedWindow.reset(key);
          break;
      }
    } else {
      // Reset todos los algoritmos
      await Promise.all([
        this.slidingWindow.reset(key),
        this.tokenBucket.reset(key),
        this.fixedWindow.reset(key)
      ]);
    }
  }

  async getStatus(key: string, algorithm: RateLimitAlgorithmType): Promise<any> {
    switch (algorithm) {
      case RateLimitAlgorithmType.SLIDING_WINDOW:
        return this.slidingWindow.getStatus(key);
      case RateLimitAlgorithmType.TOKEN_BUCKET:
        return this.tokenBucket.getStatus(key);
      case RateLimitAlgorithmType.FIXED_WINDOW:
        return this.fixedWindow.getStatus(key);
      default:
        throw new Error(`Algoritmo desconocido: ${algorithm}`);
    }
  }

  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }

  getAlgorithms() {
    return {
      slidingWindow: this.slidingWindow,
      tokenBucket: this.tokenBucket,
      fixedWindow: this.fixedWindow
    };
  }

  // ajgc: health check para verificar que todo funciona
  async healthCheck(): Promise<boolean> {
    try {
      const testKey = 'rate_limiter_health_check';
      const testConfig = { windowMs: 60000, maxRequests: 1000 };
      
      const result = await this.checkLimit(testKey, testConfig);
      await this.reset(testKey);
      
      return result.allowed;
    } catch {
      return false;
    }
  }

  // Métodos privados
  
  private selectAlgorithm(
    config: RateLimitConfig, 
    options?: RateLimitOptions
  ): RateLimitAlgorithmType {
    // ajgc: auto-seleccionar mejor algoritmo según requirements
    
    if (options?.capacity && options?.refillRate) {
      return RateLimitAlgorithmType.TOKEN_BUCKET;
    }
    
    if (config.windowMs <= 60000 && config.maxRequests <= 100) {
      // Ventana pequeña y límites bajos - usar sliding window por precisión
      return RateLimitAlgorithmType.SLIDING_WINDOW;
    }
    
    if (config.windowMs >= 300000) {
      // Ventanas grandes - usar fixed window por rendimiento
      return RateLimitAlgorithmType.FIXED_WINDOW;
    }
    
    // Por defecto sliding window (balance precisión/rendimiento)
    return RateLimitAlgorithmType.SLIDING_WINDOW;
  }

  private updateMetrics(
    result: RateLimitResult, 
    algorithm: RateLimitAlgorithmType, 
    latency: number
  ): void {
    if (result.allowed) {
      this.metrics.allowedRequests++;
    } else {
      this.metrics.blockedRequests++;
    }
    
    // Actualizar uso de algoritmos
    const usage = this.metrics.algorithmUsage.get(algorithm) || 0;
    this.metrics.algorithmUsage.set(algorithm, usage + 1);
    
    // Actualizar latencia promedio (ewma)
    const alpha = 0.1;
    this.metrics.averageLatency = 
      this.metrics.averageLatency * (1 - alpha) + latency * alpha;
  }

  private setupEventHandlers(): void {
    // Reenviar eventos de los algoritmos individuales
    [this.slidingWindow, this.tokenBucket, this.fixedWindow].forEach(algorithm => {
      algorithm.on('blocked', (data: any) => this.emit('algorithmBlocked', data));
      algorithm.on('allowed', (data: any) => this.emit('algorithmAllowed', data));
      algorithm.on('error', (error: any) => this.emit('algorithmError', error));
    });
  }
}

// Export singleton instance NodeGuard
const rateLimiter = new RateLimiter();
export default rateLimiter;
