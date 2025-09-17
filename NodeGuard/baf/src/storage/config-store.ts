// src/rules/config-store.ts
// ajgc: Store de configuración NodeGuard


import fs from "fs";
import path from "path";
import { EventEmitter } from "events";
import { StaticRulesSchema, StaticRules } from "../rules/types";
import redis from "../redis/redis-connection";
import { logger } from "../logging/logger";
import { z } from "zod";


/**
 * Constantes de configuración mejoradas
 */
const CONFIG = {
  RULES_REDIS_KEY: process.env.BAF_RULES_REDIS_KEY || "baf:rules:static",
  RULES_BACKUP_LIST_KEY: process.env.BAF_RULES_BACKUP_LIST_KEY || "baf:rules:backups",
  LOCAL_RULES_PATH: process.env.BAF_LOCAL_RULES_PATH || path.join(process.cwd(), "rules.json"),
  RULES_CACHE_TTL_MS: Number(process.env.BAF_RULES_CACHE_TTL_MS || 300000), // 5 min
  RULES_MAX_JSON_SIZE_BYTES: Number(process.env.BAF_RULES_MAX_SIZE || 10 * 1024 * 1024), // 10MB
  KEYSPACE_NOTIFICATIONS: process.env.BAF_KEYSPACE_NOTIFICATIONS !== 'false',
  POLLING_INTERVAL_MS: Number(process.env.BAF_RULES_POLLING_MS || 300000), // 5 min
  MAX_BACKUPS: Number(process.env.BAF_MAX_RULE_BACKUPS || 100),
  SYNC_TIMEOUT_MS: Number(process.env.BAF_SYNC_TIMEOUT_MS || 30000), // 30 segundos
};

/**
 * Eventos del almacén de configuración
 */
type ConfigEvents = "updated" | "error" | "redis_connected" | "redis_disconnected" | "sync_completed";

/**
 * Opciones del almacén de configuración
 */
export interface ConfigStoreOptions {
  redisUrl?: string;
  fallbackToFile: boolean;
  hotReloadEnabled: boolean;
  backupEnabled: boolean;
  syncOnStartup?: boolean;
}

/**
 * Resultado de validación de reglas
 */
interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  metrics: {
    ruleCount: number;
    staticRules: number;
    heuristicRules: number;
  };
}

/**
 * Almacén de configuración mejorado con características empresariales - ajgc
 * 
 * Características:
 * - Redis como primario con fallback a sistema de archivos
 * - Hot reload con notificaciones keyspace o polling
 * - Validación automática de reglas y backup
 * - Sincronización entre Redis y archivo local
 * - Monitoreo de salud y resistencia de conexión
 * - Versionado de reglas y soporte de rollback
 */
export class ConfigStore extends EventEmitter {
  private static instance: ConfigStore;
  private static instanceCounter = 0;
  private readonly instanceId: number;
  private isConfigured = false;
  private loadingPromise: Promise<StaticRules | null> | null = null;
  
  private cache: { 
    rules: StaticRules | null; 
    ts: number; 
    version: string;
    hash: string;
  } = { 
    rules: null, 
    ts: 0, 
    version: '1.0.0',
    hash: ''
  };

  private subscriber?: any;
  private polling = false;
  private connected = false;
  private readonly options: Required<ConfigStoreOptions>;
  private healthCheckInterval?: NodeJS.Timeout;
  private syncInProgress = false;
  private reloadingPromise: Promise<StaticRules> | null = null;
  private _reloadInProgress = false;

  // Métricas de rendimiento
  private stats = {
    totalReloads: 0,
    redisReads: 0,
    fileReads: 0,
    validationErrors: 0,
    lastSyncTime: 0,
    avgLoadTime: 0
  };

  constructor(options: ConfigStoreOptions = {
    fallbackToFile: true,
    hotReloadEnabled: true,
    backupEnabled: true
  }) {
    super();
    
    // Rastrear creación de instancia - ajgc: detectar múltiples instancias
    ConfigStore.instanceCounter++;
    this.instanceId = ConfigStore.instanceCounter;
    
    if (ConfigStore.instanceCounter > 1) {
      logger.warn(`Múltiples instancias de ConfigStore detectadas! Instancia #${this.instanceId}`);
    }
    
    this.options = {
      redisUrl: options.redisUrl ?? "",
      fallbackToFile: options.fallbackToFile ?? true,
      hotReloadEnabled: options.hotReloadEnabled ?? true,
      backupEnabled: options.backupEnabled ?? true,
      syncOnStartup: options.syncOnStartup ?? true
    };

    this.setupHealthMonitoring();
    this.initializeStore();
  }

  /**
   * Obtener instancia singleton de ConfigStore
   */
  static getInstance(options?: ConfigStoreOptions): ConfigStore {
    if (!ConfigStore.instance) {
      ConfigStore.instance = new ConfigStore(options);
    }
    return ConfigStore.instance;
  }

  /**
   * Inicializar almacén de configuración - ajgc
   */
  private async initializeStore(): Promise<void> {
    try {
      logger.info('Inicializando almacén de configuración NodeGuard...');
      
      // Probar conexión Redis
      await this.testRedisConnection();
      
      // Configurar mecanismo de hot reload
      if (this.options.hotReloadEnabled) {
        await this.setupHotReload();
      }
      
      // Carga inicial de reglas
      await this.reload();
      
      // Sincronizar Redis y archivo si está habilitado
      if (this.options.syncOnStartup) {
        await this.synchronizeRules();
      }
      
      logger.info('Almacén de configuración NodeGuard inicializado correctamente');
      
    } catch (error) {
      const err = error as Error;
      logger.error('Fallo al inicializar almacén de configuración', { 
        error: err
      });
      
      // Intentar cargar desde archivo como fallback
      if (this.options.fallbackToFile) {
        await this.loadFromFileSystem();
      }
    }
  }

  /**
   * Probar conexión Redis
   */
  private async testRedisConnection(): Promise<void> {
    try {
      await redis.ping();
      this.connected = true;
      this.emit('redis_connected');
      logger.debug('Conexión Redis establecida');
    } catch (error) {
      this.connected = false;
      this.emit('redis_disconnected');
      logger.warn('Conexión Redis falló, usando modo fallback');
      throw error;
    }
  }

  /**
   * Configurar mecanismo de hot reload - ajgc: esto está niquelao
   */
  private async setupHotReload(): Promise<void> {
    try {
      if (CONFIG.KEYSPACE_NOTIFICATIONS && this.connected) {
        await this.setupKeyspaceSubscription();
      } else {
        this.startPolling();
      }
    } catch (error) {
      logger.info('Configuración hot reload no disponible, usando polling como alternativa', { 
        error: error as Error
      });
      this.startPolling();
    }
  }

  /**
   * Setup Redis keyspace notifications
   */
  private async setupKeyspaceSubscription(): Promise<void> {
    try {
      // Since RedisClientManager doesn't support pub/sub, fall back to polling
      logger.info('Redis pub/sub not available, using polling instead');
      throw new Error('Redis duplicate method not available');
      
    } catch (error) {
      logger.info('Suscripción keyspace no disponible, polling activado', { 
        error: error as Error
      });
      throw error;
    }
  }

  /**
   * Iniciar polling para cambios de reglas - echarle un ojillo cada 5 minutos
   */
  private startPolling(): void {
    if (this.polling) return;
    
    this.polling = true;
    logger.info('Iniciando polling de configuración NodeGuard', { 
      metadata: {
        interval: CONFIG.POLLING_INTERVAL_MS
      }
    });

    const poll = async () => {
      try {
        await this.reload();
      } catch (error) {
        logger.warn('Error en polling reload', { 
          error: error as Error
        });
      } finally {
        if (this.polling) {
          setTimeout(poll, CONFIG.POLLING_INTERVAL_MS);
        }
      }
    };

    poll();
  }  /**
   * Load rules from local file system
   */
  private async loadFromFileSystem(): Promise<StaticRules | null> {
    const startTime = Date.now();
    
    try {
      if (!fs.existsSync(CONFIG.LOCAL_RULES_PATH)) {
        logger.warn('Local rules file not found', { 
          metadata: {
            path: CONFIG.LOCAL_RULES_PATH
          }
        });
        return null;
      }

      const stat = fs.statSync(CONFIG.LOCAL_RULES_PATH);
      
      if (stat.size > CONFIG.RULES_MAX_JSON_SIZE_BYTES) {
        throw new Error(`Local rules file too large (${stat.size} > ${CONFIG.RULES_MAX_JSON_SIZE_BYTES} bytes)`);
      }

      const raw = fs.readFileSync(CONFIG.LOCAL_RULES_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      
      // Enhanced validation
      const validation = this.validateRules(parsed);
      if (!validation.isValid) {
        logger.error('Local rules validation failed', { 
          error: new Error(`Validation failed: ${validation.errors.join(', ')}`)
        });
        throw new Error(`Invalid rules: ${validation.errors.join(', ')}`);
      }

      const validated = StaticRulesSchema.parse(parsed);
      
      this.stats.fileReads++;
      this.updateAverageLoadTime(Date.now() - startTime);
      
      logger.info('Reglas cargadas desde sistema de archivos local NodeGuard', {
        metadata: {
          path: CONFIG.LOCAL_RULES_PATH,
          size: stat.size,
          ruleCount: validation.metrics.ruleCount
        }
      });

      return validated;

    } catch (error) {
      const err = error as Error;
      logger.error('Fallo al cargar reglas desde sistema de archivos', { 
        error: err,
        metadata: {
          path: CONFIG.LOCAL_RULES_PATH
        }
      });
      return null;
    }
  }

  /**
   * Load rules from Redis
   */
  private async loadFromRedis(): Promise<StaticRules | null> {
    // If there's already a loading operation in progress, wait for it
    if (this.loadingPromise) {
      logger.debug('⏳ Redis load already in progress, waiting for completion...');
      return this.loadingPromise;
    }

    const startTime = Date.now();
    
    try {
      if (!this.connected) {
        throw new Error('Redis not connected');
      }

      // Check if we have fresh cached rules to avoid duplicate loads during initialization
      const cacheAge = Date.now() - this.cache.ts;
      if (this.cache.rules && cacheAge < 5000) { // 5 second cache during startup
        logger.info('⚡ Usando reglas en caché (evitando carga duplicada)', {
          metadata: { 
            cacheAge: `${cacheAge}ms`,
            ruleCount: Object.keys(this.cache.rules.static || {}).length
          }
        });
        return this.cache.rules;
      }

      // Set loading promise to prevent concurrent loads
      this.loadingPromise = this._performRedisLoad(startTime);
      const result = await this.loadingPromise;
      this.loadingPromise = null;
      return result;

    } catch (error) {
      this.loadingPromise = null;
      throw error;
    }
  }

  private async _performRedisLoad(startTime: number): Promise<StaticRules | null> {
    try {
      const raw = await redis.get(CONFIG.RULES_REDIS_KEY);
      
      if (!raw) {
        logger.debug('No rules found in Redis');
        return null;
      }

      const parsed = JSON.parse(raw);
      
      // Enhanced validation
      const validation = this.validateRules(parsed);
      if (!validation.isValid) {
        logger.error('Redis rules validation failed', { 
          error: new Error(`Validation failed: ${validation.errors.join(', ')}`)
        });
        throw new Error(`Invalid rules in Redis: ${validation.errors.join(', ')}`);
      }

      const validated = StaticRulesSchema.parse(parsed);
      
      this.stats.redisReads++;
      this.updateAverageLoadTime(Date.now() - startTime);
      
      logger.info('Reglas cargadas desde Redis NodeGuard', {
        metadata: {
          ruleCount: validation.metrics.ruleCount,
          version: (typeof (validated as any).version === 'string' ? (validated as any).version : 'unknown')
        }
      });

      return validated;

    } catch (error) {
      const err = error as Error;
      logger.warn('Fallo al cargar reglas desde Redis', { error: err });
      return null;
    }
  }

  /**
   * Enhanced rule validation
   */
  private validateRules(rules: unknown): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      metrics: {
        ruleCount: 0,
        staticRules: 0,
        heuristicRules: 0
      }
    };

    try {
      // Basic structure validation
      if (!rules || typeof rules !== 'object') {
        result.isValid = false;
        result.errors.push('Rules must be an object');
        return result;
      }

      const rulesObj = rules as any;

      // Count and validate rule categories
      if (rulesObj.static) {
        result.metrics.staticRules = Object.keys(rulesObj.static).length;
      }

      if (rulesObj.heuristic) {
        result.metrics.heuristicRules = Object.keys(rulesObj.heuristic).length;
      }

      result.metrics.ruleCount = result.metrics.staticRules + result.metrics.heuristicRules;

      // Validate enforcement mode
      if (rulesObj.enforcement && rulesObj.enforcement.mode) {
        const validModes = ['block', 'monitor', 'dry-run'];
        if (!validModes.includes(rulesObj.enforcement.mode)) {
          result.warnings.push(`Invalid enforcement mode: ${rulesObj.enforcement.mode}`);
        }
      }

      // Validate static rules structure
      if (rulesObj.static) {
        if (rulesObj.static.blockedMethods && !Array.isArray(rulesObj.static.blockedMethods)) {
          result.errors.push('blockedMethods must be an array');
          result.isValid = false;
        }

        if (rulesObj.static.blockedAddresses && !Array.isArray(rulesObj.static.blockedAddresses)) {
          result.errors.push('blockedAddresses must be an array');
          result.isValid = false;
        }
      }

      // Use Zod for final validation
      StaticRulesSchema.parse(rules);

    } catch (error) {
      if (error instanceof z.ZodError) {
        result.isValid = false;
        result.errors = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
      } else {
        result.isValid = false;
        result.errors.push((error as Error).message);
      }
    }

    return result;
  }

  /**
   * Reload rules with enhanced caching
   */
  public async reload(): Promise<StaticRules> {
    // If already reloading, wait for that operation
    if (this._reloadInProgress) {
      logger.debug('⚡ Reload already in progress, waiting...');
      while (this._reloadInProgress) {
        await new Promise(resolve => setTimeout(resolve, 1));
      }
      // After waiting, check if we now have cached results
      if (this.cache.rules && (Date.now() - this.cache.ts) < CONFIG.RULES_CACHE_TTL_MS) {
        return this.cache.rules;
      }
    }

    const startTime = Date.now();
    const now = Date.now();
    
    // Check cache validity again (might have been updated while waiting)
    if (this.cache.rules && (now - this.cache.ts) < CONFIG.RULES_CACHE_TTL_MS) {
      return this.cache.rules;
    }

    // Mark as in progress
    this._reloadInProgress = true;
    
    try {
      this.stats.totalReloads++;
      
      // Try Redis first
      let rules: StaticRules | null = null;
      
      try {
        rules = await this.loadFromRedis();
      } catch (error) {
        logger.warn('Redis load failed, trying file fallback');
      }

      // Fallback to file system
      if (!rules && this.options.fallbackToFile) {
        rules = await this.loadFromFileSystem();
      }

      if (!rules) {
      throw new Error('No valid rules found in Redis or local file');
    }

    // Update cache with metadata
    const rulesJson = JSON.stringify(rules);
    const newHash = this.generateHash(rulesJson);
    
    // Check if rules actually changed
    const rulesChanged = !this.cache || this.cache.hash !== newHash;
    
    this.cache = {
      rules,
      ts: now,
      version: (rules as any).version || 'unknown',
      hash: newHash
    };

    // Only emit update event and log if rules actually changed
    if (rulesChanged) {
      process.nextTick(() => this.emit('updated', rules));
      
      const loadTime = Date.now() - startTime;
      logger.info('🔄 Rules reloaded successfully', {
        resource: this.connected ? 'redis' : 'file',
        metadata: {
          version: this.cache.version,
          loadTime: `${loadTime}ms`,
          cacheExpiry: new Date(now + CONFIG.RULES_CACHE_TTL_MS).toISOString(),
          rulesChanged: true
        }
      });
    } else {
      // Silent reload - no changes detected
      logger.debug('⚡ Rules reloaded (no changes detected)', {
        resource: this.connected ? 'redis' : 'file',
        metadata: {
          version: this.cache.version,
          loadTime: `${Date.now() - startTime}ms`,
          rulesChanged: false
        }
      });
    }

      // Clear the in-progress flag
      this._reloadInProgress = false;
      
      return rules;
    } finally {
      // Always clear the flag, even on error
      this._reloadInProgress = false;
    }
  }

  /**
   * Get current rules
   */
  public async getRules(): Promise<StaticRules> {
    // Check cache first
    if (this.cache.rules && (Date.now() - this.cache.ts) < CONFIG.RULES_CACHE_TTL_MS) {
      return this.cache.rules;
    }

    // If already reloading, wait for that operation to complete
    if (this.reloadingPromise) {
      logger.debug('⚡ Waiting for ongoing reload operation...');
      return await this.reloadingPromise;
    }

    // Start new reload operation
    this.reloadingPromise = this.reload();
    
    try {
      const result = await this.reloadingPromise;
      return result;
    } finally {
      this.reloadingPromise = null;
    }
  }

  /**
   * Set new rules with backup and validation
   */
  public async setRules(newRulesObj: unknown): Promise<void> {
    const startTime = Date.now();
    
    try {
      // Enhanced validation
      const validation = this.validateRules(newRulesObj);
      if (!validation.isValid) {
        this.stats.validationErrors++;
        throw new Error(`Rule validation failed: ${validation.errors.join(', ')}`);
      }

      // Log warnings
      if (validation.warnings.length > 0) {
        logger.warn('Rule validation warnings', { 
          metadata: {
            warnings: validation.warnings
          }
        });
      }

      const parsed = StaticRulesSchema.parse(newRulesObj);
      
      // Create backup if enabled and Redis is available
      if (this.options.backupEnabled && this.connected) {
        await this.createBackup();
      }

      // Save to Redis
      if (this.connected) {
        const rawStr = JSON.stringify(parsed, null, 2);
        await redis.set(CONFIG.RULES_REDIS_KEY, rawStr);
        logger.info('✅ Rules saved to Redis');
      }

      // Save to local file if enabled
      if (this.options.fallbackToFile) {
        await this.saveToFile(parsed);
      }

      // Update cache immediately
      const rulesJson = JSON.stringify(parsed);
      this.cache = {
        rules: parsed,
        ts: Date.now(),
        version: (parsed as any).version || 'unknown',
        hash: this.generateHash(rulesJson)
      };

      // Emit update event
      process.nextTick(() => this.emit('updated', parsed));

      const saveTime = Date.now() - startTime;
      logger.info('💾 New rules applied successfully', {
        metadata: {
          ruleCount: validation.metrics.ruleCount,
          version: this.cache.version,
          saveTime: `${saveTime}ms`
        }
      });

    } catch (error) {
      const err = error as Error;
      logger.error('Failed to set rules', { error: err });
      throw err;
    }
  }

  /**
   * Create backup of current rules
   */
  private async createBackup(): Promise<void> {
    try {
      const currentRaw = await redis.get(CONFIG.RULES_REDIS_KEY);
      
      if (currentRaw) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupKey = `${CONFIG.RULES_REDIS_KEY}:backup:${timestamp}`;
        
        await redis.set(backupKey, currentRaw);
        await redis.lpush(CONFIG.RULES_BACKUP_LIST_KEY, backupKey);
        await redis.ltrim(CONFIG.RULES_BACKUP_LIST_KEY, 0, CONFIG.MAX_BACKUPS - 1);
        
        // Set TTL for backup (30 days)
        await redis.expire(backupKey, 30 * 24 * 60 * 60);
        
        logger.info('📦 Rules backup created', { 
          metadata: {
            backupKey
          }
        });
      }

    } catch (error) {
      logger.warn('Failed to create backup', { error: error as Error });
    }
  }

  /**
   * Save rules to local file
   */
  private async saveToFile(rules: StaticRules): Promise<void> {
    try {
      const rulesJson = JSON.stringify(rules, null, 2);
      const tempPath = CONFIG.LOCAL_RULES_PATH + '.tmp';
      
      // Atomic write
      fs.writeFileSync(tempPath, rulesJson, 'utf8');
      fs.renameSync(tempPath, CONFIG.LOCAL_RULES_PATH);
      
      logger.debug('✅ Rules saved to local file', { 
        metadata: {
          path: CONFIG.LOCAL_RULES_PATH
        }
      });

    } catch (error) {
      logger.error('Failed to save rules to file', { 
        error: error as Error,
        metadata: {
          path: CONFIG.LOCAL_RULES_PATH
        }
      });
      throw error;
    }
  }

  /**
   * Synchronize rules between Redis and file system
   */
  public async synchronizeRules(): Promise<void> {
    if (this.syncInProgress) {
      logger.debug('Sync already in progress, skipping');
      return;
    }

    this.syncInProgress = true;
    const startTime = Date.now();

    try {
      logger.info('🔄 Iniciando sincronización de reglas...');

      const [redisRules, fileRules] = await Promise.all([
        this.loadFromRedis(),
        this.loadFromFileSystem()
      ]);

      let syncRequired = false;
      let syncDirection: 'redis->file' | 'file->redis' | 'none' = 'none';

      if (redisRules && fileRules) {
        // Both exist, compare hashes
        const redisHash = this.generateHash(JSON.stringify(redisRules));
        const fileHash = this.generateHash(JSON.stringify(fileRules));
        
        if (redisHash !== fileHash) {
          // Determine which is newer based on version or timestamp
          const redisVersion = (redisRules as any).version || '0.0.0';
          const fileVersion = (fileRules as any).version || '0.0.0';
          
          if (this.compareVersions(redisVersion, fileVersion) >= 0) {
            syncDirection = 'redis->file';
          } else {
            syncDirection = 'file->redis';
          }
          syncRequired = true;
        }
      } else if (redisRules && !fileRules) {
        syncDirection = 'redis->file';
        syncRequired = true;
      } else if (!redisRules && fileRules) {
        syncDirection = 'file->redis';
        syncRequired = true;
      }

      if (syncRequired) {
        if (syncDirection === 'redis->file' && redisRules) {
          await this.saveToFile(redisRules);
          logger.info('✅ Synced Redis → File');
        } else if (syncDirection === 'file->redis' && fileRules && this.connected) {
          await redis.set(CONFIG.RULES_REDIS_KEY, JSON.stringify(fileRules, null, 2));
          logger.info('✅ Synced File → Redis');
        }
      }

      this.stats.lastSyncTime = Date.now();
      this.emit('sync_completed');

      const syncTime = Date.now() - startTime;
      logger.info('🔄 Rule synchronization completed', {
        metadata: {
          syncRequired,
          syncDirection,
          syncTime: `${syncTime}ms`
        }
      });

    } catch (error) {
      logger.error('Rule synchronization failed', { 
        error: error as Error
      });
    } finally {
      this.syncInProgress = false;
    }
  }

  /**
   * Setup health monitoring
   */
  private setupHealthMonitoring(): void {
    const healthInterval = Number(process.env.BAF_CONFIG_HEALTH_INTERVAL || 60000); // 1 minute
    
    this.healthCheckInterval = setInterval(async () => {
      try {
        // Test Redis connection
        if (this.connected) {
          await redis.ping();
        } else {
          await this.testRedisConnection();
        }
        
        // Check cache validity
        const cacheAge = Date.now() - this.cache.ts;
        if (cacheAge > CONFIG.RULES_CACHE_TTL_MS * 2) {
          logger.warn('Rules cache is stale', { 
            metadata: {
              age: `${cacheAge}ms`
            }
          });
        }
        
      } catch (error) {
        if (this.connected) {
          this.connected = false;
          this.emit('redis_disconnected');
        }
      }
    }, healthInterval);
  }

  /**
   * Utility methods
   */
  private generateHash(data: string): string {
    return require('crypto').createHash('sha256').update(data).digest('hex');
  }

  private compareVersions(a: string, b: string): number {
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);
    
    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
      const partA = partsA[i] || 0;
      const partB = partsB[i] || 0;
      
      if (partA > partB) return 1;
      if (partA < partB) return -1;
    }
    
    return 0;
  }

  private updateAverageLoadTime(time: number): void {
    const alpha = 0.1; // Exponential moving average
    this.stats.avgLoadTime = this.stats.avgLoadTime * (1 - alpha) + time * alpha;
  }

  /**
   * Public status methods
   */
  public isRedisConnected(): boolean {
    return this.connected;
  }

  public isHealthy(): boolean {
    const cacheAge = Date.now() - this.cache.ts;
    return this.cache.rules !== null && cacheAge < CONFIG.RULES_CACHE_TTL_MS * 3;
  }

  public getStats(): typeof this.stats {
    return { ...this.stats };
  }

  /**
   * Cleanup resources
   */
  public async cleanup(): Promise<void> {
    this.polling = false;
    
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    
    if (this.subscriber) {
      try {
        await this.subscriber.unsubscribe();
        await this.subscriber.quit();
      } catch (error) {
        logger.warn('Subscriber cleanup error', { error: error as Error });
      }
    }
    
    logger.info('🧹 Configuration Store cleanup completed');
  }
}

// Export singleton instance
export const configStore = ConfigStore.getInstance();
