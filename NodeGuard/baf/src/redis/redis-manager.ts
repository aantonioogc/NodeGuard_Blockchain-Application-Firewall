// Redis Manager - NodeGuard TFG 2025
// ajgc: singleton pattern para todas las conexiones Redis del BAF
import { EventEmitter } from 'events';
import IORedis, { Redis, Cluster } from 'ioredis';
import { 
  RedisManagerConfig, 
  RedisConnectionInfo, 
  RedisMetrics, 
  RedisOperationOptions,
  RedisTransaction,
  RedisPipeline,
  RedisLuaScript,
  RedisHealthCheck,
  RedisManagerEvents,
  DEFAULT_REDIS_CONFIG,
  RedisPoolConnection
} from './redis-types';
import { logger } from '../logging/logger';

/**
 * Gestor Redis - Patrón Singleton
 * 
 * Centraliza todas las conexiones y operaciones Redis en el sistema BAF.
 * Ofrece pool de conexiones, monitorización de salud, métricas,
 * y una API unificada para todas las operaciones Redis.
 * 
 * Características principales:
 * - Patrón singleton con inicialización perezosa (lazy)
 * - Pool de conexiones con failover automático
 * - Monitorización de salud y recolección de métricas
 * - Gestión y caché de scripts Lua
 * - Soporte para pipelines y transacciones
 * - Arquitectura orientada a eventos
 * - Manejo de errores robusto
 * - Optimización de rendimiento
 * 
 * Este gestor está pensado para que no tengas que preocuparte por los detalles de Redis:
 * simplemente lo usas y él se encarga de todo lo demás.
 */

export class RedisManager extends EventEmitter {
  private static instance: RedisManager;
  private static creating: Promise<RedisManager> | null = null;
  private static instanceCounter = 0;
  private readonly config: RedisManagerConfig;
  private initializingPromise: Promise<void> | null = null;
  private primaryConnection?: Redis | Cluster;
  private connectionPool: Map<string, RedisPoolConnection> = new Map();
  private luaScripts: Map<string, RedisLuaScript> = new Map();
  
  // ajgc: tracking del estado
  private isInitialized = false;
  private isDestroyed = false;
  private connectionInfo: RedisConnectionInfo;
  private metrics: RedisMetrics;
  
  // Timers para monitorización
  private healthCheckTimer?: NodeJS.Timeout;
  private metricsTimer?: NodeJS.Timeout;
  private poolCleanupTimer?: NodeJS.Timeout;
  
  // Performance tracking
  private commandStartTimes = new Map<string, number>();
  private slowCommandThreshold = 100; // ms

  private constructor(config?: Partial<RedisManagerConfig>) {
    super();

    this.config = {
      ...DEFAULT_REDIS_CONFIG,
      ...config
    };

    this.connectionInfo = {
      id: this.generateConnectionId(),
      type: this.config.cluster.enabled ? 'cluster' : 'primary',
      status: 'disconnected',
      host: this.config.connection.host,
      port: this.config.connection.port,
      database: this.config.connection.db,
      errorCount: 0,
      totalCommands: 0,
      failedCommands: 0
    };

    this.metrics = {
      connections: {
        total: 0,
        active: 0,
        idle: 0,
        failed: 0
      },
      performance: {
        totalCommands: 0,
        successfulCommands: 0,
        failedCommands: 0,
        averageLatency: 0,
        peakLatency: 0,
        commandsPerSecond: 0
      },
      memory: {
        usedMemory: 0,
        peakMemory: 0,
        memoryFragmentation: 0,
        keyspaceHits: 0,
        keyspaceMisses: 0
      },
      health: {
        isHealthy: false,
        lastHealthCheck: 0,
        consecutiveFailures: 0,
        uptime: Date.now()
      },
      keyspace: {
        totalKeys: 0,
        expiredKeys: 0,
        evictedKeys: 0,
        averageKeySize: 0
      }
    };

        // Constructor completed - logging moved to getInstance for singleton pattern
    logger.debug('Redis Manager constructor completado');
  }

  /**
   * Obtener instancia singleton (thread-safe)
   */
  public static getInstance(config?: Partial<RedisManagerConfig>): RedisManager {
    // Return inmediato si la instancia ya existe
    if (RedisManager.instance) {
      return RedisManager.instance;
    }
    
    // Prevenir múltiples creaciones simultáneas
    if (RedisManager.creating) {
      throw new Error('Redis Manager ya se está creando');
    }
    
    // Crear instancia única
    RedisManager.instance = new RedisManager(config);
    logger.info('Redis Manager singleton creado NodeGuard', {
      cluster: RedisManager.instance.config.cluster.enabled,
      host: RedisManager.instance.config.connection.host,
      port: RedisManager.instance.config.connection.port,
      metadata: {
        poolSize: RedisManager.instance.config.pool.maxConnections
      }
    });
    
    return RedisManager.instance;
  }

  /**
   * Inicializar Redis Manager (thread-safe)
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Redis Manager ya inicializado');
      return;
    }

    // Si ya se está inicializando, esperar a que termine
    if (this.initializingPromise) {
      logger.debug('Redis Manager ya inicializándose, esperando...');
      await this.initializingPromise;
      return;
    }

    if (this.isDestroyed) {
      throw new Error('Redis Manager ha sido destruido');
    }

    // Crear promise de inicialización para prevenir concurrencia
    this.initializingPromise = this.doInitialize();
    
    try {
      await this.initializingPromise;
    } finally {
      this.initializingPromise = null;
    }
  }

  /**
   * Actual initialization logic
   */
  private async doInitialize(): Promise<void> {
    try {
      logger.info('🔗 Inicializando Redis Manager...');

      // Create primary connection
      await this.createPrimaryConnection();

      // Initialize connection pool
      await this.initializeConnectionPool();

      // Start monitoring
      this.startHealthMonitoring();
      this.startMetricsCollection();
      this.startPoolCleanup();

      this.isInitialized = true;
      this.connectionInfo.status = 'connected';
      this.metrics.health.isHealthy = true;

      this.emit('ready', this.connectionInfo);
      logger.info('✅ Redis Manager initialized successfully');

    } catch (error) {
      this.connectionInfo.status = 'error';
      this.connectionInfo.errorCount++;
      this.metrics.health.isHealthy = false;
      
      const err = error as Error;
      logger.error('❌ Redis Manager initialization failed', {
        error: err,
        metadata: {
          stack: err.stack
        }
      });
      
      this.emit('error', err, this.connectionInfo);
      throw error;
    }
  }

  /**
   * Basic Redis Operations
   */
  
  public async get(key: string, options?: RedisOperationOptions): Promise<string | null> {
    return this.executeCommand('get', [this.formatKey(key, options)], options);
  }

  public async set(
    key: string, 
    value: string | number | Buffer, 
    options?: RedisOperationOptions & { ttl?: number; mode?: 'NX' | 'XX' }
  ): Promise<'OK' | null> {
    const args: any[] = [this.formatKey(key, options), value];
    
    if (options?.ttl) {
      args.push('PX', options.ttl);
    }
    
    if (options?.mode) {
      args.push(options.mode);
    }
    
    return this.executeCommand('set', args, options);
  }

  public async del(...keys: string[]): Promise<number> {
    const formattedKeys = keys.map(key => this.formatKey(key));
    return this.executeCommand('del', formattedKeys);
  }

  public async exists(...keys: string[]): Promise<number> {
    const formattedKeys = keys.map(key => this.formatKey(key));
    return this.executeCommand('exists', formattedKeys);
  }

  public async expire(key: string, seconds: number): Promise<number> {
    return this.executeCommand('expire', [this.formatKey(key), seconds]);
  }

  public async ttl(key: string): Promise<number> {
    return this.executeCommand('ttl', [this.formatKey(key)]);
  }

  public async incr(key: string): Promise<number> {
    return this.executeCommand('incr', [this.formatKey(key)]);
  }

  public async incrby(key: string, increment: number): Promise<number> {
    return this.executeCommand('incrby', [this.formatKey(key), increment]);
  }

  public async decr(key: string): Promise<number> {
    return this.executeCommand('decr', [this.formatKey(key)]);
  }

  public async decrby(key: string, decrement: number): Promise<number> {
    return this.executeCommand('decrby', [this.formatKey(key), decrement]);
  }

  // Hash operations
  public async hget(key: string, field: string): Promise<string | null> {
    return this.executeCommand('hget', [this.formatKey(key), field]);
  }

  public async hset(key: string, ...args: any[]): Promise<number> {
    return this.executeCommand('hset', [this.formatKey(key), ...args]);
  }

  public async hgetall(key: string): Promise<Record<string, string>> {
    return this.executeCommand('hgetall', [this.formatKey(key)]);
  }

  public async hdel(key: string, ...fields: string[]): Promise<number> {
    return this.executeCommand('hdel', [this.formatKey(key), ...fields]);
  }

  public async hincrby(key: string, field: string, increment: number): Promise<number> {
    return this.executeCommand('hincrby', [this.formatKey(key), field, increment]);
  }

  // List operations
  public async lpush(key: string, ...elements: any[]): Promise<number> {
    return this.executeCommand('lpush', [this.formatKey(key), ...elements]);
  }

  public async rpush(key: string, ...elements: any[]): Promise<number> {
    return this.executeCommand('rpush', [this.formatKey(key), ...elements]);
  }

  public async lpop(key: string): Promise<string | null> {
    return this.executeCommand('lpop', [this.formatKey(key)]);
  }

  public async rpop(key: string): Promise<string | null> {
    return this.executeCommand('rpop', [this.formatKey(key)]);
  }

  public async llen(key: string): Promise<number> {
    return this.executeCommand('llen', [this.formatKey(key)]);
  }

  public async lrange(key: string, start: number, stop: number): Promise<string[]> {
    return this.executeCommand('lrange', [this.formatKey(key), start, stop]);
  }

  public async ltrim(key: string, start: number, stop: number): Promise<'OK'> {
    return this.executeCommand('ltrim', [this.formatKey(key), start, stop]);
  }

  public async lindex(key: string, index: number): Promise<string | null> {
    return this.executeCommand('lindex', [this.formatKey(key), index]);
  }

  // Set operations
  public async sadd(key: string, ...members: any[]): Promise<number> {
    return this.executeCommand('sadd', [this.formatKey(key), ...members]);
  }

  public async srem(key: string, ...members: any[]): Promise<number> {
    return this.executeCommand('srem', [this.formatKey(key), ...members]);
  }

  public async smembers(key: string): Promise<string[]> {
    return this.executeCommand('smembers', [this.formatKey(key)]);
  }

  public async scard(key: string): Promise<number> {
    return this.executeCommand('scard', [this.formatKey(key)]);
  }

  // Sorted set operations
  public async zadd(key: string, ...args: any[]): Promise<number> {
    return this.executeCommand('zadd', [this.formatKey(key), ...args]);
  }

  public async zrange(key: string, start: number, stop: number, ...args: any[]): Promise<string[]> {
    return this.executeCommand('zrange', [this.formatKey(key), start, stop, ...args]);
  }

  public async zrangebyscore(key: string, min: string | number, max: string | number, ...args: any[]): Promise<string[]> {
    return this.executeCommand('zrangebyscore', [this.formatKey(key), min, max, ...args]);
  }

  public async zremrangebyscore(key: string, min: string | number, max: string | number): Promise<number> {
    return this.executeCommand('zremrangebyscore', [this.formatKey(key), min, max]);
  }

  public async zremrangebyrank(key: string, start: number, stop: number): Promise<number> {
    return this.executeCommand('zremrangebyrank', [this.formatKey(key), start, stop]);
  }

  public async zcard(key: string): Promise<number> {
    return this.executeCommand('zcard', [this.formatKey(key)]);
  }

  // Advanced operations
  public async keys(pattern: string): Promise<string[]> {
    return this.executeCommand('keys', [this.formatKey(pattern)]);
  }

  public async scan(cursor: number, ...args: any[]): Promise<[string, string[]]> {
    return this.executeCommand('scan', [cursor, ...args]);
  }

  public async ping(): Promise<'PONG'> {
    return this.executeCommand('ping', []);
  }

  public async flushdb(): Promise<'OK'> {
    return this.executeCommand('flushdb', []);
  }

  public async info(section?: string): Promise<string> {
    const args = section ? [section] : [];
    return this.executeCommand('info', args);
  }

  /**
   * Lua Script Operations
   */
  
  public async loadScript(name: string, script: string): Promise<string> {
    try {
      const sha = await this.executeCommand('script', ['load', script]);
      
      const luaScript: RedisLuaScript = {
        sha,
        script,
        loaded: true,
        execute: async (keys: string[], args: string[]) => {
          return this.evalsha(sha, keys, args);
        },
        executeWithFallback: async (keys: string[], args: string[]) => {
          try {
            return await this.evalsha(sha, keys, args);
          } catch (error) {
            // Script not loaded, fallback to eval
            return this.eval(script, keys, args);
          }
        },
        reload: async () => {
          const newSha = await this.executeCommand('script', ['load', script]);
          luaScript.sha = newSha;
          luaScript.loaded = true;
          return newSha;
        }
      };
      
      this.luaScripts.set(name, luaScript);
      
      logger.debug('Lua script loaded', { 
        name,
        metadata: {
          sha: sha.substring(0, 8)
        }
      });
      return sha;
      
    } catch (error) {
      logger.error('Failed to load Lua script', {
        name,
        error: error as Error
      });
      throw error;
    }
  }

  public getScript(name: string): RedisLuaScript | undefined {
    return this.luaScripts.get(name);
  }

  public async eval(script: string, keys: string[], args: string[]): Promise<any> {
    const formattedKeys = keys.map(key => this.formatKey(key));
    return this.executeCommand('eval', [script, keys.length, ...formattedKeys, ...args]);
  }

  public async evalsha(sha: string, keys: string[], args: string[]): Promise<any> {
    const formattedKeys = keys.map(key => this.formatKey(key));
    return this.executeCommand('evalsha', [sha, keys.length, ...formattedKeys, ...args]);
  }

  /**
   * Pipeline Operations
   */
  
  public pipeline(): RedisPipeline {
    const connection = this.getConnection();
    const redisPipeline = connection.pipeline();
    
    // Wrap the pipeline with our interface
    const pipeline = redisPipeline as RedisPipeline;
    
    // Override exec to track metrics
    const originalExec = pipeline.exec.bind(pipeline);
    pipeline.exec = async () => {
      const startTime = Date.now();
      try {
        const results = await originalExec();
        this.trackCommandExecution('pipeline', [], Date.now() - startTime, true);
        return results;
      } catch (error) {
        this.trackCommandExecution('pipeline', [], Date.now() - startTime, false);
        throw error;
      }
    };
    
    return pipeline;
  }

  /**
   * Transaction Operations
   */
  
  public multi(): RedisTransaction {
    const connection = this.getConnection();
    const redisMulti = connection.multi();
    
    // Wrap the multi with our interface
    const transaction = redisMulti as unknown as RedisTransaction;
    
    // Override exec to track metrics
    const originalExec = transaction.exec.bind(transaction);
    transaction.exec = async () => {
      const startTime = Date.now();
      try {
        const results = await originalExec();
        this.trackCommandExecution('multi', [], Date.now() - startTime, true);
        return results;
      } catch (error) {
        this.trackCommandExecution('multi', [], Date.now() - startTime, false);
        throw error;
      }
    };
    
    return transaction;
  }

  /**
   * Health and Monitoring
   */
  
  public async healthCheck(): Promise<RedisHealthCheck> {
    const startTime = Date.now();
    
    try {
      // Basic connectivity test
      await this.ping();
      
      // Get Redis info
      const info = await this.info();
      const infoLines = info.split('\r\n');
      
      let memoryUsage = 0;
      let keyspaceInfo: any[] = [];
      
      for (const line of infoLines) {
        if (line.startsWith('used_memory:')) {
          memoryUsage = parseInt(line.split(':')[1]) || 0;
        } else if (line.startsWith('db')) {
          const dbMatch = line.match(/db(\d+):keys=(\d+),expires=(\d+)/);
          if (dbMatch) {
            keyspaceInfo.push({
              db: parseInt(dbMatch[1]),
              keys: parseInt(dbMatch[2]),
              expires: parseInt(dbMatch[3])
            });
          }
        }
      }
      
      const responseTime = Date.now() - startTime;
      const connectionCount = this.connectionPool.size + 1; // +1 for primary
      
      const healthCheck: RedisHealthCheck = {
        isHealthy: true,
        responseTime,
        memoryUsage,
        connectionCount,
        keyspaceInfo,
        timestamp: Date.now()
      };
      
      this.metrics.health.lastHealthCheck = Date.now();
      this.metrics.health.consecutiveFailures = 0;
      this.metrics.health.isHealthy = true;
      
      return healthCheck;
      
    } catch (error) {
      const healthCheck: RedisHealthCheck = {
        isHealthy: false,
        responseTime: Date.now() - startTime,
        memoryUsage: 0,
        connectionCount: 0,
        keyspaceInfo: [],
        lastError: (error as Error).message,
        timestamp: Date.now()
      };
      
      this.metrics.health.consecutiveFailures++;
      this.metrics.health.isHealthy = false;
      
      return healthCheck;
    }
  }

  public getMetrics(): RedisMetrics {
    return { ...this.metrics };
  }

  public getConnectionInfo(): RedisConnectionInfo {
    return { ...this.connectionInfo };
  }

  public isHealthy(): boolean {
    return this.metrics.health.isHealthy && this.connectionInfo.status === 'connected';
  }

  public getPoolStatus(): Array<{ id: string; isActive: boolean; usageCount: number; errorCount: number }> {
    return Array.from(this.connectionPool.values()).map(conn => ({
      id: conn.id,
      isActive: conn.isActive,
      usageCount: conn.usageCount,
      errorCount: conn.errorCount
    }));
  }

  /**
   * Connection Management
   */
  
  public async connect(): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }
  }

  public async disconnect(): Promise<void> {
    logger.info('Disconnecting Redis Manager...');
    
    this.connectionInfo.status = 'disconnecting';
    
    // Stop timers
    this.stopTimers();
    
    // Close connection pool
    for (const [id, connection] of this.connectionPool) {
      try {
        await connection.client.disconnect();
        logger.debug('Pool connection closed', { 
          metadata: { id }
        });
      } catch (error) {
        logger.warn('Error closing pool connection', {
          metadata: { id },
          error: error as Error
        });
      }
    }
    
    // Close primary connection
    if (this.primaryConnection) {
      try {
        await this.primaryConnection.disconnect();
        logger.debug('Primary connection closed');
      } catch (error) {
        logger.warn('Error closing primary connection', {
          error: error as Error
        });
      }
    }
    
    this.connectionPool.clear();
    this.luaScripts.clear();
    
    this.connectionInfo.status = 'disconnected';
    this.metrics.health.isHealthy = false;
    
    this.emit('disconnected', this.connectionInfo);
    logger.info('Redis Manager disconnected');
  }

  public async destroy(): Promise<void> {
    if (this.isDestroyed) return;
    
    await this.disconnect();
    
    this.removeAllListeners();
    this.isDestroyed = true;
    this.isInitialized = false;
    
    // Reset singleton
    RedisManager.instance = undefined as any;
    
    logger.info('Redis Manager destroyed');
  }

  /**
   * Private Helper Methods
   */
  
  private async createPrimaryConnection(): Promise<void> {
    const options = this.buildRedisOptions();
    
    if (this.config.cluster.enabled && this.config.cluster.nodes) {
      this.primaryConnection = new IORedis.Cluster(this.config.cluster.nodes, {
        redisOptions: options,
        ...this.config.cluster.options
      });
    } else {
      this.primaryConnection = new IORedis(options);
    }
    
    this.setupConnectionEventHandlers(this.primaryConnection, 'primary');
    
    // Test connection
    await this.primaryConnection.ping();
    
    this.connectionInfo.connectedAt = Date.now();
    this.metrics.connections.total++;
    this.metrics.connections.active++;
    
    logger.info('Primary Redis connection established', {
      type: this.config.cluster.enabled ? 'cluster' : 'single',
      host: this.config.connection.host,
      port: this.config.connection.port
    });
  }

  private async initializeConnectionPool(): Promise<void> {
    const { minConnections } = this.config.pool;
    
    for (let i = 0; i < minConnections; i++) {
      await this.createPoolConnection();
    }
    
    logger.info('Connection pool initialized', {
      metadata: {
        size: this.connectionPool.size,
        minConnections
      }
    });
  }

  private async createPoolConnection(): Promise<RedisPoolConnection> {
    const id = this.generateConnectionId();
    const options = this.buildRedisOptions();
    
    let client: Redis | Cluster;
    
    if (this.config.cluster.enabled && this.config.cluster.nodes) {
      client = new IORedis.Cluster(this.config.cluster.nodes, {
        redisOptions: options,
        ...this.config.cluster.options
      });
    } else {
      client = new IORedis(options);
    }
    
    this.setupConnectionEventHandlers(client, id);
    
    const connection: RedisPoolConnection = {
      id,
      client,
      isActive: false,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      usageCount: 0,
      errorCount: 0
    };
    
    this.connectionPool.set(id, connection);
    this.metrics.connections.total++;
    this.metrics.connections.idle++;
    
    return connection;
  }

  private buildRedisOptions(): any {
    return {
      host: this.config.connection.host,
      port: this.config.connection.port,
      password: this.config.connection.password,
      username: this.config.connection.username,
      db: this.config.connection.db,
      
      connectTimeout: this.config.performance.connectTimeout,
      commandTimeout: this.config.performance.commandTimeout,
      lazyConnect: this.config.performance.lazyConnect,
      keepAlive: this.config.performance.enableKeepAlive,
      maxRetriesPerRequest: this.config.performance.maxRetriesPerRequest,
      retryDelayOnFailover: this.config.performance.retryDelayOnFailover,
      
      enableOfflineQueue: true,
      
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      
      reconnectOnError: (err: Error) => {
        const targetError = 'READONLY';
        return err.message.includes(targetError);
      },
      
      ...(this.config.security.enableTLS && {
        tls: this.config.security.tlsOptions || {}
      })
    };
  }

  private setupConnectionEventHandlers(client: Redis | Cluster, connectionId: string): void {
    client.on('connect', () => {
      logger.debug('Redis connection established', { 
        metadata: { connectionId }
      });
      this.emit('connected', { ...this.connectionInfo, id: connectionId });
    });
    
    client.on('ready', () => {
      logger.debug('Redis connection ready', { 
        metadata: { connectionId }
      });
    });
    
    client.on('error', (error) => {
      this.connectionInfo.errorCount++;
      this.metrics.connections.failed++;
      
      logger.error('Redis connection error', {
        error,
        metadata: {
          connectionId
        }
      });
      
      this.emit('error', error, { ...this.connectionInfo, id: connectionId });
    });
    
    client.on('close', () => {
      logger.debug('Redis connection closed', { 
        metadata: { connectionId }
      });
      this.emit('disconnected', { ...this.connectionInfo, id: connectionId });
    });
    
    client.on('reconnecting', (ms) => {
      logger.info('Redis reconnecting', { 
        metadata: {
          connectionId,
          delay: `${ms}ms`
        }
      });
    });
  }

  private getConnection(): Redis | Cluster {
    // For now, always use primary connection
    // In the future, implement load balancing across pool
    if (!this.primaryConnection) {
      throw new Error('Redis connection not available');
    }
    
    return this.primaryConnection;
  }

  private async executeCommand(
    command: string, 
    args: any[], 
    options?: RedisOperationOptions
  ): Promise<any> {
    const startTime = Date.now();
    const commandId = `${command}-${Date.now()}-${Math.random()}`;
    
    this.commandStartTimes.set(commandId, startTime);
    this.metrics.performance.totalCommands++;
    this.connectionInfo.totalCommands++;
    
    try {
      const connection = this.getConnection();
      const result = await (connection as any)[command](...args);
      
      const duration = Date.now() - startTime;
      this.trackCommandExecution(command, args, duration, true);
      
      return result;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.trackCommandExecution(command, args, duration, false);
      
      this.metrics.performance.failedCommands++;
      this.connectionInfo.failedCommands++;
      
      logger.error('Redis command failed', {
        error: error as Error,
        metadata: {
          command,
          args: this.sanitizeArgs(args),
          duration
        }
      });
      
      throw error;
      
    } finally {
      this.commandStartTimes.delete(commandId);
    }
  }

  private trackCommandExecution(
    command: string, 
    args: any[], 
    duration: number, 
    success: boolean
  ): void {
    if (success) {
      this.metrics.performance.successfulCommands++;
    }
    
    // Update average latency
    const alpha = 0.1;
    this.metrics.performance.averageLatency = 
      this.metrics.performance.averageLatency * (1 - alpha) + duration * alpha;
    
    // Update peak latency
    this.metrics.performance.peakLatency = Math.max(
      this.metrics.performance.peakLatency, 
      duration
    );
    
    // Emit slow command events
    if (duration > this.slowCommandThreshold) {
      this.emit('slowCommand', command, this.sanitizeArgs(args), duration);
    }
    
    // Emit command event
    this.emit('command', command, this.sanitizeArgs(args), { success, duration });
  }

  private formatKey(key: string, options?: RedisOperationOptions): string {
    const prefix = options?.keyPrefix || this.config.keyspace.defaultPrefix;
    
    if (prefix && !key.startsWith(prefix)) {
      return `${prefix}:${key}`;
    }
    
    return key;
  }

  private sanitizeArgs(args: any[]): any[] {
    return args.map(arg => {
      if (typeof arg === 'string' && arg.length > 100) {
        return arg.substring(0, 100) + '...';
      }
      return arg;
    });
  }

  private generateConnectionId(): string {
    return `redis-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private startHealthMonitoring(): void {
    if (!this.config.monitoring.enableHealthCheck) return;
    
    this.healthCheckTimer = setInterval(async () => {
      try {
        const healthCheck = await this.healthCheck();
        this.emit('healthCheck', healthCheck);
      } catch (error) {
        logger.error('Health check failed', {
          error: error as Error
        });
      }
    }, this.config.monitoring.healthCheckInterval);
  }

  private startMetricsCollection(): void {
    if (!this.config.monitoring.enableMetrics) return;
    
    this.metricsTimer = setInterval(() => {
      this.updateMetrics();
      this.emit('metrics', this.metrics);
    }, this.config.monitoring.metricsInterval);
  }

  private startPoolCleanup(): void {
    this.poolCleanupTimer = setInterval(() => {
      this.cleanupConnectionPool();
    }, this.config.pool.reapIntervalMillis);
  }

  private updateMetrics(): void {
    // Update commands per second
    const timeWindow = this.config.monitoring.metricsInterval / 1000;
    this.metrics.performance.commandsPerSecond = 
      this.metrics.performance.totalCommands / timeWindow;
    
    // Update connection metrics
    this.metrics.connections.active = 
      Array.from(this.connectionPool.values()).filter(c => c.isActive).length + 1;
    this.metrics.connections.idle = 
      this.connectionPool.size - this.metrics.connections.active + 1;
  }

  private cleanupConnectionPool(): void {
    const now = Date.now();
    const { idleTimeoutMillis, minConnections } = this.config.pool;
    
    for (const [id, connection] of this.connectionPool) {
      const idleTime = now - connection.lastUsed;
      
      if (!connection.isActive && 
          idleTime > idleTimeoutMillis && 
          this.connectionPool.size > minConnections) {
        
        connection.client.disconnect();
        this.connectionPool.delete(id);
        this.metrics.connections.total--;
        
        logger.debug('Removed idle connection from pool', {
          metadata: {
            connectionId: id,
            idleTime: `${idleTime}ms`
          }
        });
      }
    }
  }

  private stopTimers(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
    }
    
    if (this.metricsTimer) {
      clearInterval(this.metricsTimer);
      this.metricsTimer = undefined;
    }
    
    if (this.poolCleanupTimer) {
      clearInterval(this.poolCleanupTimer);
      this.poolCleanupTimer = undefined;
    }
  }
}

// Export singleton instance getter
export const getRedisManager = (config?: Partial<RedisManagerConfig>): RedisManager => {
  return RedisManager.getInstance(config);
};

// Default export
export default RedisManager;
