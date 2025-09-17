// src/redis/redis-types.ts
// Tipos Redis - NodeGuard TFG 2025
// ajgc: definiciones de interfaces para el sistema Redis
import { Redis, Cluster, RedisOptions } from 'ioredis';

/**
 * Interfaces Redis para NodeGuard BAF
 */

export interface RedisManagerConfig {
  // Configuración conexión
  connection: {
    host: string;
    port: number;
    password?: string;
    db: number;
    username?: string;
  };
  
  // Pool de conexiones
  pool: {
    maxConnections: number;
    minConnections: number;
    acquireTimeoutMillis: number;
    idleTimeoutMillis: number;
    reapIntervalMillis: number;
  };
  
  // Configuración performance
  performance: {
    enablePipelining: boolean;
    enableKeepAlive: boolean;
    commandTimeout: number;
    connectTimeout: number;
    lazyConnect: boolean;
    maxRetriesPerRequest: number;
    retryDelayOnFailover: number;
  };
  
  // Configuración seguridad
  security: {
    enableTLS: boolean;
    tlsOptions?: any;
    enableCompression: boolean;
  };
  
  // Configuración cluster
  cluster: {
    enabled: boolean;
    nodes?: Array<{ host: string; port: number }>;
    options?: any;
  };
  
  // Monitorización
  monitoring: {
    enableMetrics: boolean;
    enableHealthCheck: boolean;
    healthCheckInterval: number;
    metricsInterval: number;
  };
  
  // ajgc: configuración keyspace para el BAF
  keyspace: {
    defaultPrefix: string;
    enableKeyEvents: boolean;
    maxKeyLength: number;
  };
}

export interface RedisConnectionInfo {
  id: string;
  type: 'primary' | 'replica' | 'cluster';
  status: 'connecting' | 'connected' | 'disconnecting' | 'disconnected' | 'error';
  host: string;
  port: number;
  database: number;
  connectedAt?: number;
  lastActivity?: number;
  errorCount: number;
  totalCommands: number;
  failedCommands: number;
}

export interface RedisMetrics {
  connections: {
    total: number;
    active: number;
    idle: number;
    failed: number;
  };
  
  performance: {
    totalCommands: number;
    successfulCommands: number;
    failedCommands: number;
    averageLatency: number;
    peakLatency: number;
    commandsPerSecond: number;
  };
  
  memory: {
    usedMemory: number;
    peakMemory: number;
    memoryFragmentation: number;
    keyspaceHits: number;
    keyspaceMisses: number;
  };
  
  health: {
    isHealthy: boolean;
    lastHealthCheck: number;
    consecutiveFailures: number;
    uptime: number;
  };
  
  keyspace: {
    totalKeys: number;
    expiredKeys: number;
    evictedKeys: number;
    averageKeySize: number;
  };
}

export interface RedisOperationOptions {
  timeout?: number;
  retries?: number;
  priority?: 'low' | 'normal' | 'high';
  pipeline?: boolean;
  transaction?: boolean;
  keyPrefix?: string;
}

export interface RedisTransaction {
  multi(): RedisTransaction;
  exec(): Promise<any[]>;
  discard(): Promise<void>;
  watch(...keys: string[]): Promise<void>;
  unwatch(): Promise<void>;
  
  // Operaciones básicas
  get(key: string): RedisTransaction;
  set(key: string, value: string | number | Buffer, ...args: any[]): RedisTransaction;
  del(...keys: string[]): RedisTransaction;
  exists(...keys: string[]): RedisTransaction;
  expire(key: string, seconds: number): RedisTransaction;
  ttl(key: string): RedisTransaction;
  
  // Operaciones avanzadas
  incr(key: string): RedisTransaction;
  incrby(key: string, increment: number): RedisTransaction;
  decr(key: string): RedisTransaction;
  decrby(key: string, decrement: number): RedisTransaction;
}

export interface RedisPipeline {
  exec(): Promise<Array<[Error | null, any]>>;
  length: number;
  
  // Operaciones básicas
  get(key: string): RedisPipeline;
  set(key: string, value: string | number | Buffer, ...args: any[]): RedisPipeline;
  del(...keys: string[]): RedisPipeline;
  exists(...keys: string[]): RedisPipeline;
  expire(key: string, seconds: number): RedisPipeline;
  ttl(key: string): RedisPipeline;
  
  // Operaciones hash
  hget(key: string, field: string): RedisPipeline;
  hset(key: string, ...args: any[]): RedisPipeline;
  hgetall(key: string): RedisPipeline;
  hdel(key: string, ...fields: string[]): RedisPipeline;
  
  // Operaciones lista
  lpush(key: string, ...elements: any[]): RedisPipeline;
  rpush(key: string, ...elements: any[]): RedisPipeline;
  lpop(key: string): RedisPipeline;
  rpop(key: string): RedisPipeline;
  llen(key: string): RedisPipeline;
  lrange(key: string, start: number, stop: number): RedisPipeline;
  
  // Operaciones set
  sadd(key: string, ...members: any[]): RedisPipeline;
  srem(key: string, ...members: any[]): RedisPipeline;
  smembers(key: string): RedisPipeline;
  scard(key: string): RedisPipeline;
  
  // Operaciones sorted set
  zadd(key: string, ...args: any[]): RedisPipeline;
  zrange(key: string, start: number, stop: number, ...args: any[]): RedisPipeline;
  zrangebyscore(key: string, min: string | number, max: string | number, ...args: any[]): RedisPipeline;
  zcard(key: string): RedisPipeline;
}

export interface RedisLuaScript {
  sha: string;
  script: string;
  loaded: boolean;
  
  execute(keys: string[], args: string[]): Promise<any>;
  executeWithFallback(keys: string[], args: string[]): Promise<any>;
  reload(): Promise<string>;
}

export interface RedisPoolConnection {
  id: string;
  client: Redis | Cluster;
  isActive: boolean;
  createdAt: number;
  lastUsed: number;
  usageCount: number;
  errorCount: number;
}

export interface RedisEventData {
  type: 'connected' | 'disconnected' | 'error' | 'ready' | 'command' | 'metrics';
  connectionId: string;
  timestamp: number;
  data?: any;
  error?: Error;
}

// Types para comandos Redis
export type RedisValue = string | number | Buffer | null;
export type RedisKey = string;
export type RedisTTL = number;
export type RedisScore = number;

export interface RedisHash {
  [field: string]: string;
}

export interface RedisZSetMember {
  member: string;
  score: number;
}

export interface RedisHealthCheck {
  isHealthy: boolean;
  responseTime: number;
  memoryUsage: number;
  connectionCount: number;
  keyspaceInfo: {
    db: number;
    keys: number;
    expires: number;
  }[];
  lastError?: string;
  timestamp: number;
}

// ajgc: eventos para el Redis manager
export interface RedisManagerEvents {
  'connected': (connectionInfo: RedisConnectionInfo) => void;
  'disconnected': (connectionInfo: RedisConnectionInfo) => void;
  'error': (error: Error, connectionInfo: RedisConnectionInfo) => void;
  'ready': (connectionInfo: RedisConnectionInfo) => void;
  'metrics': (metrics: RedisMetrics) => void;
  'healthCheck': (result: RedisHealthCheck) => void;
  'command': (command: string, args: any[], result: any) => void;
  'slowCommand': (command: string, args: any[], duration: number) => void;
}

// Export additional types from ioredis
export type {
  Redis as RedisClient,
  Cluster as RedisCluster,
  RedisOptions
};

// Configuración por defecto NodeGuard
export const DEFAULT_REDIS_CONFIG: RedisManagerConfig = {
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0')
  },
  
  pool: {
    maxConnections: parseInt(process.env.REDIS_MAX_CONNECTIONS || '10'),
    minConnections: parseInt(process.env.REDIS_MIN_CONNECTIONS || '2'),
    acquireTimeoutMillis: 30000,
    idleTimeoutMillis: 300000,
    reapIntervalMillis: 60000
  },
  
  performance: {
    enablePipelining: process.env.REDIS_ENABLE_PIPELINING !== 'false',
    enableKeepAlive: true,
    commandTimeout: 5000,
    connectTimeout: 10000,
    lazyConnect: true,
    maxRetriesPerRequest: 3,
    retryDelayOnFailover: 100
  },
  
  security: {
    enableTLS: process.env.REDIS_ENABLE_TLS === 'true',
    enableCompression: process.env.REDIS_ENABLE_COMPRESSION === 'true'
  },
  
  cluster: {
    enabled: process.env.REDIS_CLUSTER_ENABLED === 'true',
    nodes: process.env.REDIS_CLUSTER_NODES 
      ? JSON.parse(process.env.REDIS_CLUSTER_NODES) 
      : undefined
  },
  
  monitoring: {
    enableMetrics: process.env.REDIS_ENABLE_METRICS !== 'false',
    enableHealthCheck: process.env.REDIS_ENABLE_HEALTH_CHECK !== 'false',
    healthCheckInterval: 30000,
    metricsInterval: 60000
  },
  
  keyspace: {
    defaultPrefix: process.env.REDIS_DEFAULT_PREFIX || 'baf',
    enableKeyEvents: false,
    maxKeyLength: 512
  }
};
