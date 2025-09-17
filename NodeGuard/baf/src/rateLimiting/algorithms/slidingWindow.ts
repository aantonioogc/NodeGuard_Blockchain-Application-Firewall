// src/rate-limiting/algorithms/slidingWindow.ts
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
import fs from 'fs';
import path from 'path';

/**
 * Rate Limiter de ventana deslizante
 * Usa Redis sorted sets para implementar ventanas precisas
 */
export class SlidingWindowLimiter extends EventEmitter implements RateLimitAlgorithm {
  private readonly luaScript: string;
  private scriptSha?: string;

  constructor() {
    super();
    
    // Cargar script Lua para operaciones atómicas
    this.luaScript = fs.readFileSync(
      path.join(__dirname, '../lua-scripts/sliding_window.lua'),
      'utf8'
    );
    
    // ajgc: solo init Redis si no estamos en tests
    if (!process.env.NODE_ENV?.includes('test') && !process.env.JEST_WORKER_ID) {
      this.ensureScriptLoaded();
    }
  }

  async checkLimit(
    key: string,
    config: RateLimitConfig,
    options?: RateLimitOptions
  ): Promise<RateLimitResult> {
    try {
      const fullKey = this.formatKey(key, config.keyPrefix);
      const now = Date.now();
      const windowStart = now - config.windowMs;
      const identifier = `${now}-${Math.random()}`; // ajgc: ID único para cada request
      
      const result = await this.executeScript(
        fullKey,
        config.windowMs,
        config.maxRequests,
        now,
        options?.burstAllowance || 0,
        identifier
      );

      const [allowed, count, remaining, resetTime] = result as number[];
      
      const rateLimitResult: RateLimitResult = {
        allowed: allowed === 1,
        count,
        remaining,
        resetTime,
        windowStart,
        windowEnd: now + config.windowMs,
        algorithm: RateLimitAlgorithmType.SLIDING_WINDOW,
        key: fullKey
      };

      if (!rateLimitResult.allowed) {
        rateLimitResult.retryAfter = Math.max(0, resetTime - now);
        this.emit('blocked', { key: fullKey, count, limit: config.maxRequests });
      } else {
        this.emit('allowed', { key: fullKey, count, remaining });
      }

      return rateLimitResult;

    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  async reset(key: string): Promise<void> {
    try {
      await redis.del(key);
      logger.debug('Reset sliding window NodeGuard', { key });
    } catch (error) {
      logger.error('Error reseteando sliding window', {
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
  }> {
    try {
      const now = Date.now();
      const windowMs = 60000;
      const windowStart = now - windowMs;
      
      // Limpiar entries expiradas primero
      await redis.zremrangebyscore(key, 0, windowStart);
      const count = await redis.zcard(key);
      
      return {
        count,
        windowStart,
        windowEnd: now + windowMs
      };
    } catch (error) {
      // ajgc: fallback si Redis está jodido
      return {
        count: 0,
        windowStart: Date.now(),
        windowEnd: Date.now() + 60000
      };
    }
  }

  private async executeScript(
    key: string,
    windowMs: number,
    maxRequests: number,
    now: number,
    burstAllowance: number,
    identifier: string
  ): Promise<unknown[]> {
    try {
      if (this.scriptSha) {
        return await redis.evalsha(
          this.scriptSha,
          1,
          key,
          windowMs.toString(),
          maxRequests.toString(),
          now.toString(),
          burstAllowance.toString(),
          identifier
        ) as unknown[];
      } else {
        return await redis.eval(this.luaScript, {
          keys: [key],
          arguments: [
            windowMs.toString(),
            maxRequests.toString(),
            now.toString(),
            burstAllowance.toString(),
            identifier
          ]
        }) as unknown[];
      }
    } catch (error) {
      logger.error('Error ejecutando script sliding window', {
        error: error as Error
      });
      throw error;
    }
  }

  private async ensureScriptLoaded(): Promise<void> {
    try {
      this.scriptSha = await redis.loadScript('sliding_window', this.luaScript);
    } catch (error) {
      logger.warn('No se pudo cargar script sliding window', {
        error: error as Error
      });
    }
  }

  private formatKey(key: string, prefix?: string): string {
    const effectivePrefix = prefix || 'baf:sliding_window';
    return `${effectivePrefix}:${key}`;
  }
}

export default SlidingWindowLimiter;
