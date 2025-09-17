// src/rate-limiting/algorithms/token-bucket.ts
// Algoritmo Token Bucket - NodeGuard TFG BAF
// ajgc: permite ráfagas controladas, ideal para tráfico irregular
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
 * Rate Limiter tipo Token Bucket
 * Permite ráfagas hasta la capacidad del bucket manteniendo tasa promedio
 */
export class TokenBucketLimiter extends EventEmitter implements RateLimitAlgorithm {
  private readonly luaScript: string;
  private scriptSha?: string;

  constructor() {
    super();
    
    // Cargar script Lua para operaciones atómicas
    this.luaScript = fs.readFileSync(
      path.join(__dirname, '../lua-scripts/token_bucket.lua'),
      'utf8'
    );
    
    // ajgc: solo init Redis si no estamos en testing
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
      const capacity = options?.capacity || config.maxRequests;
      const refillRate = options?.refillRate || (capacity / (config.windowMs / 1000));
      const tokensRequested = (options as any)?.tokensRequested || 1;
      const now = Date.now();

      const result = await this.executeScript(
        fullKey,
        capacity,
        refillRate,
        now,
        tokensRequested
      );

      const [allowed, tokensGranted, remainingTokens, nextRefillTime] = result as number[];
      
      const rateLimitResult: RateLimitResult = {
        allowed: allowed === 1,
        count: capacity - remainingTokens,
        remaining: remainingTokens,
        resetTime: nextRefillTime || (now + 1000),
        windowStart: now - config.windowMs,
        windowEnd: now + config.windowMs,
        algorithm: RateLimitAlgorithmType.TOKEN_BUCKET,
        key: fullKey
      };

      if (!rateLimitResult.allowed) {
        rateLimitResult.retryAfter = Math.max(0, nextRefillTime - now);
        this.emit('blocked', { 
          key: fullKey, 
          tokensRequested, 
          remainingTokens,
          capacity 
        });
      } else {
        this.emit('allowed', { key: fullKey, tokensGranted, remainingTokens });
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
      logger.debug('Reset token bucket NodeGuard', { key });
    } catch (error) {
      logger.error('Error reseteando token bucket', {
        error: error as Error,
        key
      });
      throw error;
    }
  }

  async getStatus(key: string): Promise<{
    remainingTokens: number;
    capacity: number;
    refillRate: number;
    lastRefill: number;
  }> {
    try {
      const bucketData = await redis.hgetall(key);
      
      if (!bucketData || Object.keys(bucketData).length === 0) {
        // ajgc: valores por defecto si no hay data
        return {
          remainingTokens: 100,
          capacity: 100,
          refillRate: 50,
          lastRefill: Date.now()
        };
      }

      return {
        remainingTokens: parseFloat(bucketData.tokens || '100'),
        capacity: 100,
        refillRate: 50,
        lastRefill: parseInt(bucketData.last || '0')
      };
    } catch (error) {
      // Fallback de locos si Redis casca
      return {
        remainingTokens: 100,
        capacity: 100,
        refillRate: 50,
        lastRefill: Date.now()
      };
    }
  }

  private async executeScript(
    key: string,
    capacity: number,
    refillRate: number,
    now: number,
    tokensRequested: number
  ): Promise<unknown[]> {
    try {
      const refillPerMs = refillRate / 1000; // ajgc: convertir a tokens por ms
      
      if (this.scriptSha) {
        return await redis.evalsha(
          this.scriptSha,
          1,
          key,
          capacity.toString(),
          refillPerMs.toString(),
          now.toString(),
          tokensRequested.toString()
        ) as unknown[];
      } else {
        return await redis.eval(this.luaScript, {
          keys: [key],
          arguments: [
            capacity.toString(),
            refillPerMs.toString(),
            now.toString(),
            tokensRequested.toString()
          ]
        }) as unknown[];
      }
    } catch (error) {
      logger.error('Error ejecutando script token bucket', {
        error: error as Error
      });
      throw error;
    }
  }

  private async ensureScriptLoaded(): Promise<void> {
    try {
      this.scriptSha = await redis.loadScript('token_bucket', this.luaScript);
    } catch (error) {
      logger.warn('No se pudo cargar script token bucket', {
        error: error as Error
      });
    }
  }

  private formatKey(key: string, prefix?: string): string {
    const effectivePrefix = prefix || 'baf:token_bucket';
    return `${effectivePrefix}:${key}`;
  }
}

export default TokenBucketLimiter;
