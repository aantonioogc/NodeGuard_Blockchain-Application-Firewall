// src/state/interfaces.ts
// ajgc: interfaces de gestión de estado NodeGuard
import { EventEmitter } from 'events';

/**
 * Interfaces mejoradas de gestión de estado
 * Desarrollado por ajgc para NodeGuard BAF
 * 
 * Características:
 * - Soporte de tipos genéricos para almacenamiento flexible
 * - Operaciones clave-valor avanzadas con TTL y operaciones atómicas
 * - Rate limiting con múltiples algoritmos
 * - Operaciones por lotes para rendimiento
 * - Cambios de estado dirigidos por eventos
 * - Monitoreo de salud y métricas
 * - Soporte de transacciones
 * - Operaciones basadas en patrones
 */

export interface StoreMetrics {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  averageLatency: number;
  cacheHitRate?: number;
  memoryUsage?: number;
  connectionStatus: 'connected' | 'disconnected' | 'connecting' | 'error';
  lastError?: string;
}

export interface StoreOptions {
  keyPrefix?: string;
  defaultTtl?: number;
  enableMetrics?: boolean;
  enableEvents?: boolean;
  maxRetries?: number;
  retryDelay?: number;
}

/**
 * Enhanced Key-Value Store Interface
 */
export interface KeyValueStore<T = unknown> extends EventEmitter {
  // Basic operations
  get(key: string): Promise<T | undefined>;
  set(key: string, value: T, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  
  // Advanced operations
  mget(keys: string[]): Promise<(T | undefined)[]>;
  mset(entries: Array<{ key: string; value: T; ttlMs?: number }>): Promise<void>;
  mdelete(keys: string[]): Promise<number>;
  
  // Atomic operations
  increment(key: string, delta?: number): Promise<number>;
  decrement(key: string, delta?: number): Promise<number>;
  append(key: string, value: string): Promise<number>;
  
  // TTL operations
  expire(key: string, ttlMs: number): Promise<boolean>;
  ttl(key: string): Promise<number>;
  persist(key: string): Promise<boolean>;
  
  // Pattern operations
  keys(pattern: string): Promise<string[]>;
  scan(cursor: string, pattern?: string, count?: number): Promise<{ cursor: string; keys: string[] }>;
  deleteByPattern(pattern: string): Promise<number>;
  
  // Conditional operations
  setIfNotExists(key: string, value: T, ttlMs?: number): Promise<boolean>;
  setIfExists(key: string, value: T, ttlMs?: number): Promise<boolean>;
  compareAndSwap(key: string, expectedValue: T, newValue: T): Promise<boolean>;
  
  // Utility operations
  size(): Promise<number>;
  clear(): Promise<void>;
  flush(): Promise<void>;
  
  // Health and monitoring
  ping(): Promise<boolean>;
  getMetrics(): StoreMetrics;
  isHealthy(): boolean;
  
  // Lifecycle
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  destroy(): Promise<void>;
}

/**
 * Enhanced Rate Limiter Store Interface
 */
export interface RateLimiterStore extends EventEmitter {
  // Basic rate limiting
  incrementAndGetCount(key: string, windowMs: number): Promise<number>;
  getCurrentCount(key: string): Promise<number>;
  resetCount(key: string): Promise<void>;
  
  // Advanced rate limiting
  slidingWindowIncrement(key: string, windowMs: number, maxCount: number): Promise<{
    allowed: boolean;
    count: number;
    remaining: number;
    resetTime: number;
  }>;
  
  tokenBucketConsume(key: string, capacity: number, refillRate: number, tokens?: number): Promise<{
    allowed: boolean;
    remainingTokens: number;
    retryAfter?: number;
  }>;
  
  fixedWindowIncrement(key: string, windowMs: number): Promise<{
    count: number;
    windowStart: number;
    windowEnd: number;
  }>;
  
  // Batch operations
  multiIncrement(requests: Array<{ key: string; windowMs: number }>): Promise<Array<{
    key: string;
    count: number;
    success: boolean;
  }>>;
  
  // Configuration and status
  setRateLimit(key: string, maxCount: number, windowMs: number): Promise<void>;
  getRateLimit(key: string): Promise<{ maxCount: number; windowMs: number } | undefined>;
  
  // Cleanup and maintenance
  cleanup(olderThanMs?: number): Promise<number>;
  getActiveKeys(): Promise<string[]>;
  
  // Health monitoring
  getMetrics(): StoreMetrics & {
    totalRateLimitChecks: number;
    blockedRequests: number;
    allowedRequests: number;
  };
  
  isHealthy(): boolean;
}

/**
 * Transaction Interface for Atomic Operations
 */
export interface Transaction<T = unknown> {
  get(key: string): Transaction<T>;
  set(key: string, value: T, ttlMs?: number): Transaction<T>;
  delete(key: string): Transaction<T>;
  increment(key: string, delta?: number): Transaction<T>;
  expire(key: string, ttlMs: number): Transaction<T>;
  
  exec(): Promise<unknown[]>;
  discard(): Promise<void>;
}

/**
 * Batch Operation Interface
 */
export interface BatchOperation<T = unknown> {
  operations: Array<{
    type: 'get' | 'set' | 'delete' | 'increment' | 'expire';
    key: string;
    value?: T;
    ttlMs?: number;
    delta?: number;
  }>;
  
  execute(): Promise<Array<{
    success: boolean;
    result?: unknown;
    error?: string;
  }>>;
}

/**
 * Store Factory Interface
 */
export interface StoreFactory {
  createKeyValueStore<T = unknown>(options?: StoreOptions): Promise<KeyValueStore<T>>;
  createRateLimiterStore(options?: StoreOptions): Promise<RateLimiterStore>;
  createTransaction<T = unknown>(): Transaction<T>;
  createBatch<T = unknown>(): BatchOperation<T>;
  
  // Health and lifecycle
  healthCheck(): Promise<boolean>;
  shutdown(): Promise<void>;
}

/**
 * Store Configuration Interface
 */
export interface StoreConfig {
  type: 'memory' | 'redis' | 'hybrid';
  connectionString?: string;
  options?: {
    host?: string;
    port?: number;
    password?: string;
    db?: number;
    keyPrefix?: string;
    
    // Connection pool settings
    maxConnections?: number;
    minConnections?: number;
    idleTimeoutMs?: number;
    
    // Retry settings
    maxRetries?: number;
    retryDelayMs?: number;
    
    // Performance settings
    enablePipelining?: boolean;
    enableCompression?: boolean;
    
    // Memory settings (for in-memory store)
    maxMemoryMb?: number;
    evictionPolicy?: 'lru' | 'lfu' | 'ttl';
    
    // Monitoring
    enableMetrics?: boolean;
    metricsInterval?: number;
    
    // Security
    enableTls?: boolean;
    tlsOptions?: any;
  };
}

/**
 * Store Events
 */
export interface StoreEvents {
  'connected': () => void;
  'disconnected': () => void;
  'error': (error: Error) => void;
  'set': (key: string, value: unknown) => void;
  'get': (key: string, value: unknown) => void;
  'delete': (key: string) => void;
  'expired': (key: string) => void;
  'rateLimit': (key: string, count: number, limit: number) => void;
  'metrics': (metrics: StoreMetrics) => void;
}

/**
 * Store State Interface
 */
export interface StoreState {
  status: 'initializing' | 'connected' | 'disconnected' | 'error' | 'destroyed';
  connections: number;
  lastOperation: number;
  startTime: number;
  errorCount: number;
  lastError?: Error;
}

// Export utility types
export type StoreValue = string | number | boolean | object | null;
export type StoreKey = string;
export type StoreTtl = number;
export type StorePattern = string;