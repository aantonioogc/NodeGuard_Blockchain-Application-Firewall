// src/utils/shutdown-utils.ts
// ajgc: shutdown para NodeGuard

import { Server } from 'http';
import chalk from 'chalk';
import { logger } from '../logging/logger';

export interface ShutdownDependencies {
  server: Server;
  firewallProvider: any;
  configStore: any;
  eventBus: any;
  logger: any;
}

/**
 * ajgc: registrar shutdown graceful - esto está niquelao para limpiar recursos
 */
export function registerGracefulShutdown(deps: ShutdownDependencies): void {
  const shutdown = async (signal: string) => {
    console.log(chalk.yellow(`\nRecibida señal ${signal}, cerrando NodeGuard gracefully...`));
    
    try {
      // parar de aceptar nuevas conexiones
      deps.server.close(() => {
        console.log(chalk.gray('Servidor HTTP cerrado'));
      });

      // limpiar recursos - echarle un ojillo a que todo se cierre bien
      await Promise.all([
        deps.configStore.cleanup(),
        deps.eventBus.cleanup(),
        deps.firewallProvider.cleanup()
      ]);

      console.log(chalk.gray('Todos los recursos limpiados'));
      console.log(chalk.green('NodeGuard cerrado correctamente - desarrollado por ajgc'));
      
      process.exit(0);
    } catch (error) {
      console.error(chalk.red('Error durante el cierre:'), error);
      process.exit(1);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGQUIT', () => shutdown('SIGQUIT'));
}
