// src/rateLimiting/indexRL.ts
// Módulo Rate Limiting - NodeGuard TFG 2025
// ajgc: exportar todos los limiters y tipos para el BAF
export { default as RateLimiter } from './rate-limiter';
export { default as SlidingWindowLimiter } from './algorithms/slidingWindow';
export { default as TokenBucketLimiter } from './algorithms/tokenBucket';
export { default as FixedWindowLimiter } from './algorithms/fixedWindow';

// Export types necesarios
export type {
  RateLimitResult,
  RateLimitConfig,
  RateLimitAlgorithm,
  RateLimitOptions
} from './types';

export { RateLimitAlgorithmType } from './types';

// Default export - singleton instance NodeGuard
export { default } from './rate-limiter';
