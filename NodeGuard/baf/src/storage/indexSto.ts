// src/storage/index.ts
// ajgc: unificación de almacenamiento NodeGuard
import type { Logger } from 'winston';
import redis from '../redis/redis-connection';

import { InMemoryRateLimiterStore } from './memory-store';
import { RedisRateLimiterStore } from './redis-store';
import { ConfigStore } from './config-store';

export * from './interfaces';
export { InMemoryRateLimiterStore } from './memory-store';
export { RedisRateLimiterStore } from './redis-store';
export { ConfigStore } from './config-store';

/**
 * ajgc: configuración de almacenamiento NodeGuard
 */
export interface StorageConfig {
  redis?: {
    enabled?: boolean;
    fallbackToMemory?: boolean;
    connectionTimeout?: number;
  };
  rateLimiter?: {
    preferMemory?: boolean;
    maxMemoryKeys?: number;
  };
  config?: {
    persistentStorage?: boolean;
    backupInterval?: number;
  };
}

/**
 * ajgc: contenedor de servicios de almacenamiento
 */
export interface StorageServices {
  rateStore: InMemoryRateLimiterStore | RedisRateLimiterStore;
  configStore: ConfigStore;
  isRedisAvailable: boolean;
  cleanup: () => Promise<void>;
}

/**
 * StorageFactory - ajgc: selecciona automáticamente Redis o Memory según disponibilidad
 * Este está niquelao para manejar fallbacks y monitoreo
 */
export class StorageFactory {
  private static instance: StorageFactory;
  private logger?: Logger;
  
  constructor(logger?: Logger) {
    this.logger = logger;
  }
  
  /**
   * ajgc: crear servicios con selección automática Redis/Memory
   */
  async createStorageServices(config: StorageConfig = {}): Promise<StorageServices> {
    const isRedisAvailable = await this.checkRedisAvailability();
    const services: StorageServices = {
      rateStore: await this.createRateStore(config, isRedisAvailable),
      configStore: this.createConfigStore(config, isRedisAvailable),
      isRedisAvailable,
      cleanup: async () => {
        await services.rateStore.cleanup?.();
        await services.configStore.cleanup?.();
      }
    };
    
    this.logger?.info('Servicios de almacenamiento NodeGuard creados', {
      rateStore: services.rateStore.constructor.name,
      configStore: services.configStore.constructor.name,
      redisAvailable: isRedisAvailable
    });
    
    return services;
  }
  
  /**
   * ajgc: crear rate store con lógica de fallback
   */
  private async createRateStore(
    config: StorageConfig,
    isRedisAvailable: boolean
  ): Promise<InMemoryRateLimiterStore | RedisRateLimiterStore> {
    // forzar memoria si se pide explícitamente
    if (config.rateLimiter?.preferMemory === true) {
      this.logger?.debug('Creando InMemory rate store (solicitado explícitamente)');
      return new InMemoryRateLimiterStore();
    }
    
    // usar Redis si está disponible
    if (isRedisAvailable && config.redis?.enabled !== false) {
      try {
        const redisStore = new RedisRateLimiterStore();
        await this.testRedisStore(redisStore);
        
        this.logger?.debug('Redis rate store creado y testeado correctamente');
        return redisStore;
        
      } catch (error) {
        this.logger?.warn('Redis rate store falló, cayendo a memoria', {
          error: (error as Error).message
        });
      }
    }
    
    // fallback a memory store
    this.logger?.debug('Creando InMemory rate store (fallback)');
    return new InMemoryRateLimiterStore();
  }
  
  /**
   * ajgc: crear config store con opciones de persistencia
   */
  private createConfigStore(
    config: StorageConfig,
    isRedisAvailable: boolean
  ): ConfigStore {
    // usar instancia singleton en lugar de crear una nueva
    const configStore = ConfigStore.getInstance({
      fallbackToFile: !isRedisAvailable || config.config?.persistentStorage === false,
      hotReloadEnabled: true,
      backupEnabled: true,
      syncOnStartup: isRedisAvailable
    });
    return configStore;
  }
  
  /**
   * ajgc: verificar disponibilidad de Redis
   */
  private async checkRedisAvailability(): Promise<boolean> {
    try {
      if (!redis) {
        this.logger?.debug('Cliente Redis no inicializado');
        return false;
      }
      
      const timeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Redis ping timeout')), 2000)
      );
      
      const ping = redis.ping();
      await Promise.race([ping, timeout]);
      
      this.logger?.debug('Check de disponibilidad Redis pasado');
      return true;
      
    } catch (error) {
      this.logger?.debug('Check de disponibilidad Redis falló', {
        error: (error as Error).message
      });
      return false;
    }
  }
  
  /**
   * ajgc: testear funcionalidad del Redis store
   */
  private async testRedisStore(store: RedisRateLimiterStore): Promise<void> {
    const testKey = 'storage-factory-test';
    const testWindow = 60000;
    
    try {
      const result1 = await store.incrementAndGetCount(testKey, testWindow);
      const result2 = await store.getCurrentCount(testKey);
      await store.resetCount(testKey);
      
      if (result1 === 0 || result2 === null) {
        throw new Error('Operaciones básicas Redis fallaron');
      }
      
      this.logger?.debug('Test Redis store pasado correctamente');
      
    } catch (error) {
      throw new Error(`Test Redis store falló: ${(error as Error).message}`);
    }
  }
  
  /**
   * ajgc: obtener instancia singleton
   */
  static getInstance(logger?: Logger): StorageFactory {
    if (!StorageFactory.instance) {
      StorageFactory.instance = new StorageFactory(logger);
    }
    return StorageFactory.instance;
  }
}

/**
 * ajgc: función de conveniencia para crear servicios de almacenamiento
 */
export async function createStorageServices(
  config: StorageConfig = {},
  logger?: Logger
): Promise<StorageServices> {
  const factory = StorageFactory.getInstance(logger);
  return factory.createStorageServices(config);
}

/**
 * ajgc: función legacy para compatibilidad con código existente
 */
export async function createRateStore(
  preferRedis: boolean = true,
  logger?: Logger
): Promise<InMemoryRateLimiterStore | RedisRateLimiterStore> {
  const factory = StorageFactory.getInstance(logger);
  const services = await factory.createStorageServices({
    redis: { enabled: preferRedis },
    rateLimiter: { preferMemory: !preferRedis }
  });
  
  return services.rateStore;
}

/**
 * ajgc: health check para todos los servicios de almacenamiento - echarle un ojillo a que todo vaya bien
 */
export async function checkStorageHealth(): Promise<{
  healthy: boolean;
  redis: boolean;
  services: string[];
  issues: string[];
}> {
  const issues: string[] = [];
  const services: string[] = [];
  
  try {
    const factory = StorageFactory.getInstance();
    const redisAvailable = await factory['checkRedisAvailability']();
    
    // testear memory store
    const memoryStore = new InMemoryRateLimiterStore();
    const testResult = await memoryStore.incrementAndGetCount('health-check', 60000);
    if (testResult > 0) {
      services.push('memory-store');
    } else {
      issues.push('memory-store-failed');
    }
    
    // testear Redis store si está disponible
    if (redisAvailable) {
      try {
        const redisStore = new RedisRateLimiterStore();
        await factory['testRedisStore'](redisStore);
        services.push('redis-store');
      } catch (error) {
        issues.push('redis-store-failed');
      }
    }
    
    // testear config store
    try {
      const configStore = ConfigStore.getInstance();
      if (configStore.isHealthy()) {
        services.push('config-store');
      } else {
        issues.push('config-store-unhealthy');
      }
    } catch (error) {
      issues.push('config-store-failed');
    }
    
    return {
      healthy: issues.length === 0 && services.length > 0,
      redis: redisAvailable,
      services,
      issues
    };
    
  } catch (error) {
    return {
      healthy: false,
      redis: false,
      services: [],
      issues: [`health-check-failed: ${(error as Error).message}`]
    };
  }
}

/**
 * ajgc: utilidades de almacenamiento NodeGuard
 */
export const StorageUtils = {
  /**
   * generar clave de almacenamiento con prefijo
   */
  key: (prefix: string, ...parts: string[]): string => {
    return `baf:${prefix}:${parts.join(':')}`;
  },
  
  /**
   * parsear clave de almacenamiento
   */
  parseKey: (key: string): { prefix: string; parts: string[] } => {
    const [, prefix, ...parts] = key.split(':');
    return { prefix: prefix || '', parts };
  },
  
  /**
   * generar TTL para operaciones de almacenamiento
   */
  ttl: (seconds: number): number => {
    return Math.floor(Date.now() / 1000) + seconds;
  },
  
  /**
   * verificar si TTL ha expirado
   */
  isExpired: (ttl: number): boolean => {
    return ttl < Math.floor(Date.now() / 1000);
  }
};

/**
 * ajgc: export por defecto para conveniencia
 */
export default {
  StorageFactory,
  createStorageServices,
  createRateStore,
  checkStorageHealth,
  StorageUtils
};
