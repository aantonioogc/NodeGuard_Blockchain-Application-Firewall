// src/index.ts
// ajgc: punto de entrada principal de NodeGuard Firewall

// Load environment variables first
import * as dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import chalk from 'chalk';
import figlet from 'figlet';
import path from 'path';
import { logger, winstonLogger } from './logging/logger';
import { createServer } from './api/server';
import { createFirewallProvider } from './core/factory';
import { EventBus } from './events/event-bus';
import { ConfigStore } from './storage/config-store';
import { checkSystemHealth, displayStartupBanner } from './utils/startup-utils';
import { registerGracefulShutdown } from './utils/shutdown-utils';

/**
 * NodeGuard Blockchain Application Firewall
 * ajgc: punto de entrada principal del sistema - esto está niquelao
 */

// configuración de entorno con validación
interface BafConfig {
  port: number;
  rpcUrl: string;
  redisUrl?: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  metricsEnabled: boolean;
  adminTokenRequired: boolean;
  enforcementMode: 'block' | 'monitor' | 'dry-run';
  performance: {
    maxConcurrentRequests: number;
    requestTimeoutMs: number;
    circuitBreakerThreshold: number;
  };
}

function validateAndLoadConfig(): BafConfig {
  const config: BafConfig = {
    port: Number(process.env.PORT || 3000),
    rpcUrl: process.env.RPC_URL || process.env.BAF_URL || 'http://127.0.0.1:8545',
    redisUrl: process.env.REDIS_URL,
    logLevel: (process.env.LOG_LEVEL as any) || 'info',
    metricsEnabled: process.env.METRICS_ENABLED !== 'false',
    adminTokenRequired: process.env.ADMIN_TOKEN_REQUIRED !== 'false',
    enforcementMode: (process.env.ENFORCEMENT_MODE as any) || 'block',
    performance: {
      maxConcurrentRequests: Number(process.env.MAX_CONCURRENT_REQUESTS || 1000),
      requestTimeoutMs: Number(process.env.REQUEST_TIMEOUT_MS || 30000),
      circuitBreakerThreshold: Number(process.env.CIRCUIT_BREAKER_THRESHOLD || 10)
    }
  };

  // validación básica - ajgc: echarle un ojillo a estos límites
  if (config.port < 1 || config.port > 65535) {
    throw new Error(`Puerto inválido: ${config.port}. Debe estar entre 1-65535`);
  }

  if (!config.rpcUrl.startsWith('http')) {
    throw new Error(`RPC_URL inválida: ${config.rpcUrl}. Debe empezar con http/https`);
  }

  if (!['block', 'monitor', 'dry-run'].includes(config.enforcementMode)) {
    throw new Error(`ENFORCEMENT_MODE inválido: ${config.enforcementMode}`);
  }

  logger.info('Configuración validada exitosamente', { 
    port: config.port, 
    rpcUrl: config.rpcUrl.replace(/\/\/.*@/, '//***:***@'), // ocultar credenciales
    component: 'config',
    action: 'validate'
  });

  return config;
}

/**
 * Inicialización de la aplicación - ajgc: de locos la cantidad de servicios
 */
async function initializeApplication(config: BafConfig): Promise<{
  app: express.Application;
  firewallProvider: any;
  eventBus: EventBus;
  configStore: ConfigStore;
}> {
  logger.info('Inicializando NodeGuard Blockchain Application Firewall...');

  try {
    // usar instancias singleton para evitar duplicación de servicios
    const { eventBus } = await import('./events/event-bus');
    logger.debug('EventBus singleton obtenido');

    // importar y configurar ConfigStore singleton
    const { ConfigStore } = await import('./storage/config-store');
    const configStore = ConfigStore.getInstance({
      redisUrl: config.redisUrl,
      fallbackToFile: true,
      hotReloadEnabled: true,
      backupEnabled: true,
      syncOnStartup: true
    });
    logger.debug('ConfigStore singleton configurado');

    const { firewallProvider } = await createFirewallProvider({
      rpcUrl: config.rpcUrl,
      configStore,
      eventBus,
      enforcementMode: config.enforcementMode,
      performance: config.performance,
      logger: winstonLogger
    });
    logger.debug('FirewallProvider creado con todos los módulos de seguridad');

    // configuración completa del servidor
    const { app } = await createServer({
      firewallProvider,
      configStore,
      eventBus,
      logger,
      config: {
        adminAuthRequired: config.adminTokenRequired,
        metricsEnabled: config.metricsEnabled,
        corsEnabled: true,
        rateLimitEnabled: true,
        maxRequestSize: '10mb',
        trustProxy: process.env.TRUST_PROXY === 'true',
        compressionEnabled: true
      }
    });
    logger.debug('Servidor Express configurado con todas las rutas');

    return { app, firewallProvider, eventBus, configStore };

  } catch (error: unknown) {
    const err = error as Error;
    logger.error('Error al inicializar aplicación', { 
      component: 'initialization',
      error: err,
      action: 'initialize'
    });
    throw error;
  }
}

/**
 * Verificación de salud del sistema - ajgc: niquelao para monitoreo
 */
async function performSystemCheck(dependencies: {
  firewallProvider: any;
  configStore: ConfigStore;
  eventBus: EventBus;
}): Promise<void> {
  logger.info('Realizando verificación completa de salud del sistema...');
  
  const healthStatus = await checkSystemHealth({
    redis: dependencies.configStore.isRedisConnected(),
    upstream: dependencies.firewallProvider.isUpstreamHealthy(),
    eventBus: dependencies.eventBus.isHealthy(),
    configStore: dependencies.configStore.isHealthy()
  });

  // log del estado detallado - ajgc: sin códigos ANSI en logs estructurados
  Object.entries(healthStatus.services).forEach(([service, status]) => {
    const icon = status ? '[OK]' : '[ERROR]';
    const statusText = status ? 'Saludable' : 'No saludable';
    
    // log estructurado sin colores
    logger.info(`${icon} ${service.toUpperCase()}: ${statusText}`, {
      component: 'health-check',
      metadata: {
        service: service,
        healthy: status
      }
    });
    
    // console con colores si está habilitado
    if (process.env.BAF_CONSOLE_LOGS !== 'false') {
      const color = status ? chalk.green : chalk.red;
      console.log(color(`${icon} ${service.toUpperCase()}: ${statusText}`));
    }
  });

  if (!healthStatus.allHealthy) {
    logger.warn('Algunos servicios no están saludables. BAF operará en modo degradado.');
    
    // emitir evento del sistema
    dependencies.eventBus.emitEvent({
      type: 'status',
      timestamp: Date.now(),
      message: 'Sistema ejecutándose en modo degradado',
      method: 'system',
      clientIp: 'system',
      reqId: 'health-' + Date.now(),
      level: 'warning'
    });
  }
}


/**
 * Monitoreo de rendimiento de peticiones
 */
function setupPerformanceMonitoring(app: express.Application, eventBus: EventBus): void {
  let activeConnections = 0;
  let requestsInFlight = 0;
  
  // monitorear conexiones activas
  app.use((req, res, next) => {
    activeConnections++;
    requestsInFlight++;
    
    const startTime = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      requestsInFlight--;
      
      // emitir métricas de rendimiento
      eventBus.emitEvent({
        type: 'status',
        timestamp: Date.now(),
        message: `Petición procesada: ${req.body?.method || req.method}`,
        method: req.body?.method || req.method,
        clientIp: req.ip || 'unknown',
        reqId: 'perf-' + Date.now()
      });
      
      // log de peticiones lentas - ajgc: echarle un ojillo a esto
      if (duration > 1000) {
        logger.warn('Petición lenta detectada', {
          method: req.body?.method || req.method,
          duration: duration,
          clientIp: req.ip
        });
      }
    });
    
    res.on('close', () => {
      activeConnections--;
    });
    
    next();
  });
}

/**
 * Enhanced Console Logging (keeping original functionality)
 */
function setupEnhancedLogging(): void {
  const enableConsoleOutput = process.env.BAF_CONSOLE_LOGS !== 'false';
  
  if (enableConsoleOutput) {
    logger.info("Enhanced logging system active. All console output will be persisted to 'logs/baf.log'");
  } else {
    // Solo guardar en archivo que los logs de consola están deshabilitados
    logger.info('Console logging disabled - all output redirected to log files only');
    // NO interceptamos console cuando está deshabilitado - dejamos que el banner se muestre normalmente
    return;
  }
  
  const stripAnsi = (input: string): string => {
    return input.replace(/\x1B\[[0-9;]*[mK]/g, '');
  };
  
  // Keep original console interception logic but enhance it
  const origMethods = {
    log: console.log.bind(console),
    info: console.info.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug ? console.debug.bind(console) : console.log.bind(console)
  };

  function formatArgs(...args: any[]): string {
    return args
      .map((a) => {
        if (typeof a === 'string') return a;
        try { return JSON.stringify(a, null, 2); } 
        catch { return String(a); }
      })
      .join(' ');
  }

  // Enhanced console methods with structured logging - solo si está habilitado
  ['log', 'info', 'warn', 'error', 'debug'].forEach(level => {
    (console as any)[level] = (...args: any[]) => {
      const text = formatArgs(...args);
      
      // Mostrar en consola (siempre, ya que solo interceptamos si está habilitado)
      (origMethods as any)[level](...args);
      
      // Enhanced file logging with metadata
      try {
        const logData = {
          level,
          message: stripAnsi(text),
          timestamp: new Date().toISOString(),
          source: 'console'
        };
        
        (logger as any)[level === 'log' ? 'info' : level](logData.message, {
          source: logData.source,
          originalLevel: level
        });
      } catch (e) {
        origMethods.error('[LOGGER ERROR]', e);
      }
    };
  });

  logger.info('Enhanced console interception active with structured logging');
}

/**
 * Punto de entrada principal de la aplicación - ajgc: de locos todo esto junto
 */
async function main(): Promise<void> {
  try {
    // cargar y validar configuración
    const config = validateAndLoadConfig();
    
    // configurar logging mejorado primero
    setupEnhancedLogging();
    
    // inicializar todos los componentes de la aplicación
    const { app, firewallProvider, eventBus, configStore } = await initializeApplication(config);
    
    // configurar monitoreo de rendimiento
    setupPerformanceMonitoring(app, eventBus);
    
    // realizar verificación completa de salud del sistema
    await performSystemCheck({ firewallProvider, configStore, eventBus });
    
    // mostrar banner de inicio mejorado
    const healthStatus = await checkSystemHealth({
      redis: configStore.isRedisConnected(),
      upstream: await firewallProvider.isUpstreamHealthy(),
      configStore: configStore.isHealthy(),
      eventBus: eventBus.isHealthy()
    });
    
    await displayStartupBanner(config, healthStatus);
    
    // iniciar el servidor HTTP
    const server = app.listen(config.port, () => {
      const successMessage = `NodeGuard Firewall v2.0 escuchando en puerto ${config.port}`;
      console.log(chalk.green(`[SERVIDOR] ${successMessage}`));
      console.log(chalk.cyan(`[INFO] Dashboard: http://localhost:${config.port}/dashboard`));
      console.log(chalk.cyan(`[INFO] Eventos: http://localhost:${config.port}/events`));
      console.log(chalk.cyan(`[INFO] Panel Admin: http://localhost:${config.port}/admin`));
      
      logger.info('NodeGuard Firewall iniciado exitosamente', {
        component: 'startup',
        method: 'main',
        metadata: {
          port: config.port,
          version: '2.0.0',
          services: healthStatus
        }
      });
      
      // emitir evento de inicio
      eventBus.emitEvent({
        type: 'status',
        timestamp: Date.now(),
        message: 'NodeGuard Firewall iniciado exitosamente',
        method: 'startup',
        clientIp: 'system',
        reqId: 'startup-' + Date.now()
      });
    });

    // configurar cierre elegante con limpieza
    registerGracefulShutdown({
      server,
      firewallProvider,
      configStore,
      eventBus,
      logger
    });

    // manejar errores del servidor
    server.on('error', (error: Error) => {
      logger.error('Error del servidor', new Error(`Error del servidor: ${error.message}`));
      
      if (process.env.BAF_CONSOLE_LOGS !== 'false') {
        console.error(chalk.red('[SERVIDOR] Error:'), error);
      }
      
      eventBus.emitEvent({
        type: 'status',
        timestamp: Date.now(),
        message: 'Error del servidor',
        method: 'server',
        clientIp: 'system',
        reqId: 'error-' + Date.now()
      });
      
      process.exit(1);
    });

  } catch (error: any) {
    logger.error('Error al iniciar NodeGuard Firewall', { 
      error: error.message, 
      stack: error.stack 
    });
    
    if (process.env.BAF_CONSOLE_LOGS !== 'false') {
      console.error(chalk.red('[INICIO] Error crítico:'), error.message);
    }
    process.exit(1);
  }
}

// Start the application
if (require.main === module) {
  main().catch((error) => {
    // Solo mostrar en consola si está habilitado
    if (process.env.BAF_CONSOLE_LOGS !== 'false') {
      console.error(chalk.red('[FATAL]'), error);
    } else {
      // Asegurar que errores fatales se loggeen al archivo
      logger.error('Fatal error', { error: error.message, stack: error.stack });
    }
    process.exit(1);
  });
}

export { main, validateAndLoadConfig, initializeApplication };
