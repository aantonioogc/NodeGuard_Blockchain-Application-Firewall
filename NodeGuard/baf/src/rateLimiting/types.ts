// src/rateLimiting/types.ts
// Tipos Rate Limiting - NodeGuard TFG BAF
// ajgc: definiciones de interfaces y enums para los algorithms

export interface RateLimitResult {
  allowed: boolean;
  count: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
  windowStart: number;
  windowEnd: number;
  algorithm: RateLimitAlgorithmType;
  key: string;
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
  skipOnError?: boolean;
  skipSuccessfulRequests?: boolean;
}

export interface RateLimitOptions {
  algorithm?: RateLimitAlgorithmType;
  key?: string;
  windowMs?: number;
  maxRequests?: number;
  burstAllowance?: number;
  refillRate?: number;
  capacity?: number;
}

export enum RateLimitAlgorithmType {
  SLIDING_WINDOW = 'sliding_window',
  TOKEN_BUCKET = 'token_bucket',
  FIXED_WINDOW = 'fixed_window'
}

export interface RateLimitAlgorithm {
  checkLimit(
    key: string,
    config: RateLimitConfig,
    options?: RateLimitOptions
  ): Promise<RateLimitResult>;
  
  reset(key: string): Promise<void>;
  getStatus(key: string): Promise<any>;
}

// ajgc: interfaces específicas para cada algoritmo (por si las necesito)
export interface TokenBucketOptions extends RateLimitOptions {
  capacity: number;
  refillRate: number;
  tokensRequested?: number;
}

export interface SlidingWindowOptions extends RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  burstAllowance?: number;
}

export interface FixedWindowOptions extends RateLimitOptions {
  windowMs: number;
  maxRequests: number;
}
