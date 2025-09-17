// src/utils/startup-utils.ts
// ajgc: arranque NodeGuard

import chalk from 'chalk';
import figlet from 'figlet';
import { logger } from '../logging/logger';

export interface HealthStatus {
  allHealthy: boolean;
  services: {
    server: boolean;
    redis: boolean;
    upstream: boolean;
    configStore: boolean;
    eventBus: boolean;
  };
  timestamp: number;
}

/**
 * ajgc: verificar salud del sistema - echarle un ojillo a todos los servicios
 */
export async function checkSystemHealth(services: {
  redis: boolean;
  upstream: Promise<boolean> | boolean;
  eventBus: boolean;
  configStore: boolean;
}): Promise<HealthStatus> {
  const status: HealthStatus = {
    allHealthy: false,
    services: {
      server: true,
      redis: services.redis,
      upstream: typeof services.upstream === 'boolean' ? services.upstream : await services.upstream,
      configStore: services.configStore,
      eventBus: services.eventBus
    },
    timestamp: Date.now()
  };

  status.allHealthy = Object.values(status.services).every(Boolean);
  return status;
}

/**
 * ajgc: mostrar banner de arranque niquelao
 */
export async function displayStartupBanner(config: any, healthStatus: HealthStatus): Promise<void> {
  console.clear();
  
  const banner = figlet.textSync('NodeGuard', {
    font: 'Big',
    horizontalLayout: 'default',
    verticalLayout: 'default'
  });
  
  console.log(chalk.cyan(banner));
  console.log(chalk.magenta('━'.repeat(80)));
  console.log(chalk.yellow.bold('BLOCKCHAIN APPLICATION FIREWALL v2.0.0 - Desarrollado por ajgc'));
  console.log(chalk.magenta('━'.repeat(80)));

  // estado del sistema
    console.log(chalk.blue.bold('\nESTADO DEL SISTEMA:'));
    console.log(chalk.green('├─ Servidor:'), healthStatus.services.server ? chalk.green('OK Running') : chalk.red('X Failed'));
    console.log(chalk.green('├─ Redis:'), healthStatus.services.redis ? chalk.green('OK Connected') : chalk.red('X Disconnected'));
    console.log(chalk.green('├─ RPC Upstream:'), healthStatus.services.upstream ? chalk.green('OK Available') : chalk.red('X Unavailable'));
    console.log(chalk.green('├─ Config Store:'), healthStatus.services.configStore ? chalk.green('OK Loaded') : chalk.red('X Error'));
    console.log(chalk.green('└─ Event Bus:'), healthStatus.services.eventBus ? chalk.green('OK Active') : chalk.red('X Inactive'));
  
    // servicios activos
    console.log(chalk.blue.bold('\nSERVICIOS ACTIVOS:'));
    console.log(chalk.green('├─ HTTP Server:'), chalk.cyan(`localhost:${config.port}`));
    console.log(chalk.green('├─ Rate Limiting:'), chalk.cyan('Multi-Algoritmo (Sliding Window + Token Bucket)'));
    console.log(chalk.green('├─ Fingerprinting:'), chalk.cyan('Análisis de Payload + Detección ML'));
    console.log(chalk.green('├─ TX Validation:'), chalk.cyan('EIP-155 + EIP-2718 + EIP-1559'));
    console.log(chalk.green('├─ Sistema Reputación:'), chalk.cyan('Scoring Dinámico + Thresholds Adaptativos'));
    console.log(chalk.green('├─ Panel Admin:'), chalk.cyan(`localhost:${config.port}/admin`));
    console.log(chalk.green('├─ Dashboard:'), chalk.cyan(`localhost:${config.port}/dashboard`));
    console.log(chalk.green('└─ Events Stream:'), chalk.cyan(`localhost:${config.port}/events`));
  
    // endpoints disponibles
    console.log(chalk.blue.bold('\nENDPOINTS DISPONIBLES:'));
    console.log(chalk.green('├─ GET'), chalk.cyan('/'), chalk.gray('- Estado del sistema y métricas'));
    console.log(chalk.green('├─ POST'), chalk.cyan('/rpc'), chalk.gray('- Proxy JSON-RPC principal (batch soportado)'));
    console.log(chalk.green('├─ GET'), chalk.cyan('/healthz'), chalk.gray('- Health check detallado'));
    console.log(chalk.green('├─ GET'), chalk.cyan('/dashboard'), chalk.gray('- Dashboard de monitoreo en tiempo real'));
    console.log(chalk.green('├─ GET'), chalk.cyan('/events'), chalk.gray('- Stream de eventos (Server-Sent Events)'));
    console.log(chalk.green('├─ GET'), chalk.cyan('/metrics'), chalk.gray('- Métricas Prometheus'));
    console.log(chalk.green('└─ ALL'), chalk.cyan('/admin/*'), chalk.gray('- API administrativa (protegida JWT)'));
  
    // características de protección
    console.log(chalk.blue.bold('\nCARACTERÍSTICAS DE PROTECCIÓN:'));
    console.log(chalk.green('├─ Modo Enforcement:'), chalk.cyan(config.enforcementMode.toUpperCase()));
    console.log(chalk.green('├─ Rate Limiting Multi-Capa:'), chalk.cyan('IP, Address, Method-específico'));
    console.log(chalk.green('├─ Fingerprinting Avanzado:'), chalk.cyan('Análisis Comportamental + Detección de Patrones'));
    console.log(chalk.green('├─ Protección Smart Contract:'), chalk.cyan('Análisis Function Selector + Validación ABI'));
    console.log(chalk.green('├─ Defensa Ataques Sybil:'), chalk.cyan('Clustering IP + Scoring Reputación'));
    console.log(chalk.green('├─ Protección Replay:'), chalk.cyan('Validación EIP-155 + Tracking Nonce'));
    console.log(chalk.green('├─ Prevención DoS:'), chalk.cyan('Circuit Breaker + Thresholds Adaptativos'));
    console.log(chalk.green('└─ Seguridad Batch:'), chalk.cyan('Análisis Individual + Agregado'));
  
    console.log(chalk.magenta('\n━'.repeat(1)));
    console.log(chalk.green.bold('\nNodeGuard v2.0 protegiendo tu infraestructura blockchain!'));
    console.log(chalk.magenta('━'.repeat(80)));
    console.log(chalk.gray('Presiona Ctrl+C para parar el firewall\n'));
  }