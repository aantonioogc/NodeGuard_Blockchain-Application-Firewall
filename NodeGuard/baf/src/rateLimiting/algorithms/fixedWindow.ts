// src/rate-limiting/algorithms/fixed-window.ts
// Algoritmo Sliding Window - NodeGuard TFG BAF
// ajgc: más preciso que fixed window pero consume más recursos
import { EventEmitter } from 'events';
import redis from '../../redis/redis-connection';
import { 
  RateLimitResult, 
  RateLimitConfig, 
  RateLimitOptions, 
  RateLimitAlgorithm,
  RateLimitAlgorithmType 
} from '../types';
import { logger } from '../../logging/logger';

/**
 * Rate Limiter de ventana fija
 * Menos preciso que sliding window pero mucho más rápido
 */
export class FixedWindowLimiter extends EventEmitter implements RateLimitAlgorithm {

  constructor() {
    super();
  }

  async checkLimit(
    key: string,
    config: RateLimitConfig,
    options?: RateLimitOptions
  ): Promise<RateLimitResult> {
    try {
      const fullKey = this.formatKey(key, config.keyPrefix);
      const now = Date.now();
      // ajgc: calcular ventana actual dividiendo timestamp
      const windowStart = Math.floor(now / config.windowMs) * config.windowMs;
      const windowEnd = windowStart + config.windowMs;
      const windowKey = `${fullKey}:${windowStart}`;
      
      const count = await redis.incr(windowKey);
      
      // Solo setear TTL en la primera request de la ventana
      if (count === 1) {
        await redis.expire(windowKey, Math.ceil(config.windowMs / 1000));
      }

      const allowed = count <= config.maxRequests;
      const remaining = Math.max(0, config.maxRequests - count);

      const result: RateLimitResult = {
        allowed,
        count,
        remaining,
        resetTime: windowEnd,
        windowStart,
        windowEnd,
        algorithm: RateLimitAlgorithmType.FIXED_WINDOW,
        key: fullKey
      };

      if (!allowed) {
        result.retryAfter = windowEnd - now;
        this.emit('blocked', { 
          key: fullKey, 
          count, 
          limit: config.maxRequests,
          windowStart,
          windowEnd
        });
      } else {
        this.emit('allowed', { key: fullKey, count, remaining });
      }

      return result;

    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  async reset(key: string): Promise<void> {
    try {
      // Buscar y borrar todas las ventanas de esta key
      const pattern = this.formatKey(key) + ':*';
      const keys = await redis.keys(pattern);
      
      if (keys.length > 0) {
        await redis.del(...keys);
      }
      
      logger.debug('Reset ventana fija NodeGuard', { key });
    } catch (error) {
      logger.error('Error reseteando ventana fija', {
        error: error as Error,
        key
      });
      throw error;
    }
  }

  async getStatus(key: string): Promise<{
    count: number;
    windowStart: number;
    windowEnd: number;
    remaining: number;
  }> {
    try {
      const now = Date.now();
      const windowMs = 60000; // ajgc: ventana por defecto de 1 min
      const windowStart = Math.floor(now / windowMs) * windowMs;
      const windowEnd = windowStart + windowMs;
      const windowKey = `${this.formatKey(key)}:${windowStart}`;
      
      const count = await redis.get(windowKey);
      const currentCount = count ? parseInt(count, 10) : 0;
      
      return {
        count: currentCount,
        windowStart,
        windowEnd,
        remaining: Math.max(0, 100 - currentCount)
      };
    } catch (error) {
      // Fallback niquelao si falla Redis
      const now = Date.now();
      const windowMs = 60000;
      const windowStart = Math.floor(now / windowMs) * windowMs;
      
      return {
        count: 0,
        windowStart,
        windowEnd: windowStart + windowMs,
        remaining: 100
      };
    }
  }

  private formatKey(key: string, prefix?: string): string {
    const effectivePrefix = prefix || 'baf:fixed_window';
    return `${effectivePrefix}:${key}`;
  }
}

export default FixedWindowLimiter;
