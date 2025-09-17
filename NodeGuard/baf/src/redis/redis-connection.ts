// src/redis/redis-connection.ts
// Conexión Redis - NodeGuard TFG BAF
// ajgc: cliente unificado para todas las operaciones Redis del BAF
import { getRedisManager, RedisManager } from './redis-manager';
import { RedisManagerConfig } from './redis-types';
import { logger } from '../logging/logger';

/**
 * Conexión Redis - Cliente Unificado
 * 
 * Este módulo garantiza el uso real de un único singleton,
 * utilizando siempre la instancia global de RedisManager y evitando duplicados.
 * 
 * Características:
 * - Singleton real de RedisManager en toda la aplicación
 * - Compatibilidad con código legacy
 * - Inicialización automática y gestión de la conexión
 * - Manejo de errores y comportamiento seguro ante fallos
 * - Operaciones tipadas y acceso completo a la API de Redis
 * 
 */

/**
 * Obtener instancia singleton RedisManager (auto-init si es necesario)
 */
const getRedis = async (): Promise<RedisManager> => {
  // ajgc: siempre usar singleton para evitar múltiples conexiones
  const manager = RedisManager.getInstance();
  
  // Auto-init en primer acceso
  if (!manager.isHealthy()) {
    try {
      await manager.initialize();
    } catch (error) {
      logger.error('Error inicializando Redis Manager singleton', {
        error: error as Error
      });
      throw error;
    }
  }
  
  return manager;
};

/**
 * Proxy Redis Client mejorado
 * Todas las operaciones Redis a través del manager con error handling
 */
class RedisConnectionProxy {
  // Operaciones básicas
  async get(key: string): Promise<string | null> {
    const redis = await getRedis();
    return redis.get(key);
  }

  async set(key: string, value: string | number | Buffer, ...args: any[]): Promise<'OK' | null> {
    const redis = await getRedis();
    
    // Parse args adicionales para TTL y modes
    const options: any = {};
    
    for (let i = 0; i < args.length; i += 2) {
      const arg = args[i];
      const val = args[i + 1];
      
      if (arg === 'EX' && typeof val === 'number') {
        options.ttl = val * 1000; // Convertir a milisegundos
      } else if (arg === 'PX' && typeof val === 'number') {
        options.ttl = val;
      } else if (arg === 'NX') {
        options.mode = 'NX';
      } else if (arg === 'XX') {
        options.mode = 'XX';
      }
    }
    
    return redis.set(key, value, options);
  }

  async setex(key: string, seconds: number, value: string | number | Buffer): Promise<'OK'> {
    const redis = await getRedis();
    return redis.set(key, value, { ttl: seconds * 1000 }) as Promise<'OK'>;
  }

  async del(...keys: string[]): Promise<number> {
    const redis = await getRedis();
    return redis.del(...keys);
  }

  async exists(...keys: string[]): Promise<number> {
    const redis = await getRedis();
    return redis.exists(...keys);
  }

  async expire(key: string, seconds: number): Promise<number> {
    const redis = await getRedis();
    return redis.expire(key, seconds);
  }

  async ttl(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.ttl(key);
  }

  async incr(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.incr(key);
  }

  async incrby(key: string, increment: number): Promise<number> {
    const redis = await getRedis();
    return redis.incrby(key, increment);
  }

  async decr(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.decr(key);
  }

  async decrby(key: string, decrement: number): Promise<number> {
    const redis = await getRedis();
    return redis.decrby(key, decrement);
  }

  // ajgc: operaciones hash
  async hget(key: string, field: string): Promise<string | null> {
    const redis = await getRedis();
    return redis.hget(key, field);
  }

  async hset(key: string, ...args: any[]): Promise<number> {
    const redis = await getRedis();
    return redis.hset(key, ...args);
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const redis = await getRedis();
    return redis.hgetall(key);
  }

  async hdel(key: string, ...fields: string[]): Promise<number> {
    const redis = await getRedis();
    return redis.hdel(key, ...fields);
  }

  async hincrby(key: string, field: string, increment: number): Promise<number> {
    const redis = await getRedis();
    return redis.hincrby(key, field, increment);
  }

  // List operations
  async lpush(key: string, ...elements: (string | number | Buffer)[]): Promise<number> {
    const redis = await getRedis();
    return redis.lpush(key, ...elements);
  }

  async rpush(key: string, ...elements: (string | number | Buffer)[]): Promise<number> {
    const redis = await getRedis();
    return redis.rpush(key, ...elements);
  }

  async lpop(key: string): Promise<string | null> {
    const redis = await getRedis();
    return redis.lpop(key);
  }

  async rpop(key: string): Promise<string | null> {
    const redis = await getRedis();
    return redis.rpop(key);
  }

  async llen(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.llen(key);
  }

  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    const redis = await getRedis();
    return redis.lrange(key, start, stop);
  }

  async ltrim(key: string, start: number, stop: number): Promise<'OK'> {
    const redis = await getRedis();
    return redis.ltrim(key, start, stop);
  }

  async lindex(key: string, index: number): Promise<string | null> {
    const redis = await getRedis();
    return redis.lindex(key, index);
  }

  // Set operations
  async sadd(key: string, ...members: (string | number | Buffer)[]): Promise<number> {
    const redis = await getRedis();
    return redis.sadd(key, ...members);
  }

  async srem(key: string, ...members: (string | number | Buffer)[]): Promise<number> {
    const redis = await getRedis();
    return redis.srem(key, ...members);
  }

  async smembers(key: string): Promise<string[]> {
    const redis = await getRedis();
    return redis.smembers(key);
  }

  async scard(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.scard(key);
  }

  // Operaciones sorted set
  async zadd(key: string, ...args: any[]): Promise<number> {
    const redis = await getRedis();
    return redis.zadd(key, ...args);
  }

  async zrange(key: string, start: number, stop: number, ...args: any[]): Promise<string[]> {
    const redis = await getRedis();
    return redis.zrange(key, start, stop, ...args);
  }

  async zrangebyscore(key: string, min: string | number, max: string | number, ...args: any[]): Promise<string[]> {
    const redis = await getRedis();
    return redis.zrangebyscore(key, min, max, ...args);
  }

  async zremrangebyscore(key: string, min: string | number, max: string | number): Promise<number> {
    const redis = await getRedis();
    return redis.zremrangebyscore(key, min, max);
  }

  async zremrangebyrank(key: string, start: number, stop: number): Promise<number> {
    const redis = await getRedis();
    return redis.zremrangebyrank(key, start, stop);
  }

  async zcard(key: string): Promise<number> {
    const redis = await getRedis();
    return redis.zcard(key);
  }

  // Advanced operations
  async keys(pattern: string): Promise<string[]> {
    const redis = await getRedis();
    return redis.keys(pattern);
  }

  async scan(cursor: number, ...args: any[]): Promise<[string, string[]]> {
    const redis = await getRedis();
    return redis.scan(cursor, ...args);
  }

  async ping(): Promise<'PONG'> {
    const redis = await getRedis();
    return redis.ping();
  }

  // ajgc: métodos adicionales para redis-store
  async mget(...keys: string[]): Promise<(string | null)[]> {
    const redis = await getRedis();
    const results: (string | null)[] = [];
    for (const key of keys) {
      results.push(await redis.get(key));
    }
    return results;
  }

  async persist(key: string): Promise<number> {
    const redis = await getRedis();
    // Redis manager no tiene persist, lo simulamos
    const exists = await redis.exists(key);
    if (exists) {
      const value = await redis.get(key);
      if (value !== null) {
        await redis.set(key, value); // Esto elimina cualquier TTL
        return 1;
      }
    }
    return 0;
  }

  async setnx(key: string, value: string | number | Buffer): Promise<number> {
    const redis = await getRedis();
    const result = await redis.set(key, value, { mode: 'NX' });
    return result === 'OK' ? 1 : 0;
  }

  async flushdb(): Promise<'OK'> {
    const redis = await getRedis();
    return redis.flushdb();
  }

  async info(section?: string): Promise<string> {
    const redis = await getRedis();
    return redis.info(section);
  }

  // Scripts Lua
  async eval(script: string, options: { keys?: string[]; arguments?: string[] }): Promise<any> {
    const redis = await getRedis();
    const keys = options.keys || [];
    const args = options.arguments || [];
    return redis.eval(script, keys, args);
  }

  async evalsha(sha: string, numkeys: number, ...args: any[]): Promise<any> {
    const redis = await getRedis();
    const keys = args.slice(0, numkeys);
    const scriptArgs = args.slice(numkeys);
    return redis.evalsha(sha, keys, scriptArgs);
  }

  async loadScript(name: string, script: string): Promise<string> {
    const redis = await getRedis();
    return redis.loadScript(name, script);
  }

  // Pipeline y transaction support
  pipeline(): any {
    return getRedis().then(redis => redis.pipeline());
  }

  multi(): any {
    return getRedis().then(redis => redis.multi());
  }

  // Gestión conexión
  async connect(): Promise<void> {
    await getRedis();
  }

  async disconnect(): Promise<void> {
    const manager = RedisManager.getInstance();
    if (manager.isHealthy()) {
      await manager.disconnect();
    }
  }

  // ajgc: health y monitoring
  async isReady(): Promise<boolean> {
    try {
      const redis = await getRedis();
      return redis.isHealthy();
    } catch {
      return false;
    }
  }

  async healthCheck(): Promise<any> {
    const manager = RedisManager.getInstance();
    if (manager.isHealthy()) {
      return manager.healthCheck();
    }
    return { isHealthy: false, error: 'Redis no inicializado' };
  }
}

// Crear instancia proxy
const redisProxy = new RedisConnectionProxy();

// Funciones de compatibilidad legacy
export const setValue = async (key: string, value: string): Promise<void> => {
  await redisProxy.set(key, value);
};

export const getValue = async (key: string): Promise<string | null> => {
  return redisProxy.get(key);
};

// Export proxy como default
export default redisProxy;

// Export manager directo para uso avanzado
export { getRedisManager, RedisManager };
export type { RedisManagerConfig } from './redis-types';

// Re-export types para compatibilidad
export type {
  RedisMetrics,
  RedisConnectionInfo,
  RedisHealthCheck,
  RedisTransaction,
  RedisPipeline,
  RedisLuaScript
} from './redis-types';
