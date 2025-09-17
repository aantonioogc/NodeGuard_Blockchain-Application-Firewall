// src/api/routes/adminRoutes.ts - Sistema de rutas administrativas NodeGuard
// Autor: Antonio José González Castillo (ajgc) - TFG BAF
import { Router, Request, Response } from 'express';
import { requireAdminToken, requireReadonlyAdmin, adminInfo, csrfProtection } from '../middleware/adminMiddleware';
import { ConfigStore } from '../../storage/config-store';
import { EventBus } from '../../events/event-bus';
import { AdminAuthService } from '../server';
import { StaticRulesSchema, RuleValidator } from '../../rules/types';
import { generateSecurityReport } from '../../utils/report-generator';
import redis from '../../redis/redis-connection';
import crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { logger } from '../../logging/logger';

/**
 * Clase para crear rutas de administración
 */
export function adminRoutes(
  configStore: ConfigStore,
  eventBus: EventBus,
  authService: AdminAuthService
): Router {
  const router = Router();

  // CORS para el panel admin
  router.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', process.env.ADMIN_CORS_ORIGIN || 'http://localhost:3000');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Admin-Token, X-CSRF-Token');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }
    
    next();
  });

  // Info básica sin auth
  router.get('/', adminInfo);

  // Endpoint para obtener CSRF token (requiere auth)
  router.get('/csrf-token', requireAdminToken, async (req: Request, res: Response) => {
    try {
      const adminSession = (req as any).adminSession;
      if (!adminSession || !adminSession.csrfToken) {
        return res.status(400).json({
          error: 'no_session',
          message: 'No active admin session found'
        });
      }

      res.json({
        success: true,
        csrfToken: adminSession.csrfToken
      });
    } catch (error) {
      res.status(500).json({
        error: 'internal_error',
        message: 'Error retrieving CSRF token'
      });
    }
  });

  // Endpoints de autenticación
  router.post('/auth/login', async (req: Request, res: Response) => {
    try {
      const { username, password, mfaCode } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({
          success: false,
          error: 'missing_credentials',
          message: 'Username and password are required'
        });
      }

      // TODO: revisar la auth cuando tenga tiempo
      const authResult = await authenticateUser(username, password, mfaCode, req.ip);
      
      if (!authResult.success) {
        await logSecurityEvent('login_failed', req, `Failed login attempt for ${username}`);
        return res.status(401).json({
          success: false,
          error: authResult.error,
          message: authResult.message
        });
      }

      const token = authService.generateToken(authResult.user!.id, authResult.user!.role, authResult.user!.permissions);
      const csrfToken = crypto.randomBytes(32).toString('hex');
      await createAdminSession(authResult.user!, token, req, csrfToken);
      
      await logSecurityEvent('login_success', req, `Successful login for ${username}`);
      
      res.json({
        success: true,
        token,
        csrfToken, // Incluir CSRF token en la respuesta
        user: {
          id: authResult.user!.id,
          username: authResult.user!.username,
          role: authResult.user!.role,
          permissions: authResult.user!.permissions
        },
        expiresIn: 3600,
        mfaRequired: authResult.mfaRequired
      });

    } catch (error) {
      logger.error('Login endpoint error', { error: error as Error });
      res.status(500).json({
        success: false,
        error: 'login_error',
        message: 'Internal authentication error'
      });
    }
  });

  router.post('/auth/logout', requireAdminToken, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      await destroyAdminSession(session.userId);
      
      await logSecurityEvent('logout', req, `User ${session.userId} logged out`);
      
      res.json({
        success: true,
        message: 'Successfully logged out'
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'logout_error',
        message: 'Failed to logout'
      });
    }
  });

  // Auth obligatoria para todo lo que viene después
  router.use(requireAdminToken);

  // Health check detallado (requiere autenticación)
  router.get('/health', requireAdminToken, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const startTime = Date.now();
      
      const health = {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        status: 'healthy' as 'healthy' | 'degraded' | 'unhealthy',
        services: {
          redis: false,
          configStore: false,
          eventBus: false,
          upstream: false
        },
        metrics: {
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          activeConnections: 0,
          requestsPerSecond: 0
        },
        security: {
          activeAdminSessions: 0,
          recentSecurityEvents: 0,
          rateLimitStatus: 'normal' as 'normal' | 'elevated' | 'critical'
        },
        version: process.env.npm_package_version || '2.0.0',
        requestedBy: session.userId,
        responseTime: 0
      };

      // Test de servicios
      try {
        await redis.ping();
        health.services.redis = true;
      } catch (error) {
        health.status = 'degraded';
      }

      health.services.configStore = configStore.isHealthy();
      health.services.eventBus = eventBus.isHealthy();

      // Métricas adicionales
      try {
        const activeSessionsCount = await redis.keys('baf:admin:session:*');
        health.security.activeAdminSessions = activeSessionsCount.length;

        const recentEvents = await redis.keys('baf:admin:audit:*');
        health.security.recentSecurityEvents = recentEvents.length;
      } catch (error) {
        // no crítico
      }

      // Estado general basado en servicios caídos
      const unhealthy = Object.values(health.services).filter(s => !s).length;
      if (unhealthy > 2) {
        health.status = 'unhealthy';
      } else if (unhealthy > 0) {
        health.status = 'degraded';
      }

      health.responseTime = Date.now() - startTime;
      const httpStatus = health.status === 'healthy' ? 200 : health.status === 'degraded' ? 200 : 503;
      
      res.status(httpStatus).json({ success: true, health });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'health_check_failed',
        message: (error as Error).message
      });
    }
  });

  // Stats del sistema - ajgc: esto se puede optimizar más
  router.get('/stats', async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      
      const stats = {
        system: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          platform: process.platform,
          nodeVersion: process.version,
          pid: process.pid
        },
        redis: {
          connected: false,
          keyCount: 0,
          memoryUsage: 0
        },
        firewall: {
          totalRequests: 0,
          blockedRequests: 0,
          blockRate: 0
        },
        admin: {
          activeSessions: 0,
          totalUsers: 0,
          securityEvents: 0
        },
        rules: {
          lastUpdated: null as string | null,
          version: 'unknown',
          totalRules: 0,
          activeBackups: 0
        },
        environment: {
          nodeEnv: process.env.NODE_ENV || 'development',
          rpcUrl: process.env.RPC_URL?.replace(/\/\/.*@/, '//***:***@') || 'not_configured',
          rateLimitEnabled: process.env.BAF_RATE_LIMIT_ENABLED !== 'false'
        },
        timestamp: new Date().toISOString(),
        requestedBy: session.userId
      };

      // Redis stats
      try {
        await redis.ping();
        stats.redis.connected = true;
        
        const keys = await redis.keys('baf:*');
        stats.redis.keyCount = keys.length;
        stats.redis.memoryUsage = keys.length * 1024; // estimación
      } catch (error) {
        // Redis no disponible
      }

      // Stats del firewall
      try {
        const metrics = await redis.hgetall('baf:analytics:metrics');
        stats.firewall.totalRequests = parseInt(metrics.totalRequests || '0');
        stats.firewall.blockedRequests = parseInt(metrics.blockedRequests || '0');
        stats.firewall.blockRate = stats.firewall.totalRequests > 0 
          ? (stats.firewall.blockedRequests / stats.firewall.totalRequests) * 100 
          : 0;
      } catch (error) {
        // no crítico
      }

      // Stats de admin
      try {
        const [sessions, users, events] = await Promise.all([
          redis.keys('baf:admin:session:*'),
          redis.keys('baf:admin:user:*'),
          redis.keys('baf:admin:audit:*')
        ]);
        
        stats.admin.activeSessions = sessions.length;
        stats.admin.totalUsers = users.length;
        stats.admin.securityEvents = events.length;
      } catch (error) {
        // no crítico
      }

      // Stats de reglas
      try {
        const rules = await configStore.getRules();
        stats.rules.version = rules.meta?.version || 'unknown';
        stats.rules.totalRules = Object.keys(rules.static || {}).length + Object.keys(rules.heuristics || {}).length;
        stats.rules.lastUpdated = rules.meta?.updated_at ?? null;

        const backups = await redis.lrange('baf:rules:backups', 0, -1);
        stats.rules.activeBackups = backups.length;
      } catch (error) {
        // no crítico
      }

      res.json({ success: true, stats });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'stats_failed',
        message: (error as Error).message
      });
    }
  });

  // Gestión de reglas del firewall
  router.get('/rules', async (req: Request, res: Response) => {
    try {
      const rules = await configStore.getRules();
      const validation = RuleValidator.validateRules(rules);
      
      // ajgc: calcular métricas básicas si no existen
      const staticRuleCount = Object.keys(rules.static || {}).length;
      const heuristicRuleCount = Object.keys(rules.heuristics || {}).length;
      
      res.json({
        success: true,
        rules,
        validation,
        metadata: {
          lastUpdated: rules.meta?.updated_at,
          version: rules.meta?.version,
          totalRules: staticRuleCount + heuristicRuleCount,
          complexity: staticRuleCount * 2 + heuristicRuleCount * 3 // estimación básica
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'failed_to_fetch_rules',
        message: (error as Error).message
      });
    }
  });

  router.post('/rules', csrfProtection, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const newRules = req.body;

      // Validar reglas
      const validation = RuleValidator.validateRules(newRules);
      if (!validation.success) {
        return res.status(400).json({
          success: false,
          error: 'invalid_rules',
          validation,
          message: 'Rule validation failed'
        });
      }

      // Metadata de actualización
      const enhancedRules = {
        ...newRules,
        meta: {
          ...newRules.meta,
          updated_at: new Date().toISOString(),
          updated_by: session.userId,
          version: newRules.meta?.version || '2.0.0'
        }
      };

      const parsedRules = StaticRulesSchema.parse(enhancedRules);
      await configStore.setRules(parsedRules);

      // Notificar cambio
      eventBus.emitEvent({
        type: 'status',
        timestamp: Date.now(),
        message: 'Rules updated by admin',
        method: 'admin',
        clientIp: req.ip || 'unknown',
        reqId: `admin-${Date.now()}`
      });

      await logSecurityEvent('rules_updated', req, `Rules updated by ${session.userId}`);

      res.json({
        success: true,
        message: 'Rules updated successfully',
        rules: parsedRules,
        validation,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Rules update failed', { error: error as Error });
      res.status(500).json({
        success: false,
        error: 'failed_to_update_rules',
        message: (error as Error).message
      });
    }
  });

  // Gestión de backups de reglas
  router.get('/rules/backups', async (req: Request, res: Response) => {
    try {
      const backups = await redis.lrange('baf:rules:backups', 0, -1);
      
      const details = await Promise.all(
        backups.map(async (backupKey) => {
          try {
            const data = await redis.get(backupKey);
            if (data) {
              const rules = JSON.parse(data);
              return {
                key: backupKey,
                timestamp: rules.meta?.created_at || rules.meta?.updated_at,
                version: rules.meta?.version,
                size: data.length,
                ruleCount: Object.keys(rules.static || {}).length + Object.keys(rules.heuristics || {}).length
              };
            }
          } catch (error) {
            return { key: backupKey, error: 'Failed to parse backup' };
          }
        })
      );

      res.json({
        success: true,
        backups: details,
        count: backups.length,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'failed_to_list_backups',
        message: (error as Error).message
      });
    }
  });

  router.post('/rules/rollback', csrfProtection, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const { backupKey } = req.body;

      let targetKey = backupKey;
      if (!targetKey) {
        const latest = await redis.lindex('baf:rules:backups', 0);
        if (!latest) {
          return res.status(404).json({
            success: false,
            error: 'no_backups_available',
            message: 'No backups available for rollback'
          });
        }
        targetKey = latest;
      }

      const backupData = await redis.get(targetKey);
      if (!backupData) {
        return res.status(404).json({
          success: false,
          error: 'backup_not_found',
          message: `Backup ${targetKey} not found`
        });
      }

      const backupRules = JSON.parse(backupData);
      const validation = RuleValidator.validateRules(backupRules);
      
      if (!validation.success) {
        return res.status(400).json({
          success: false,
          error: 'invalid_backup',
          validation,
          message: 'Backup contains invalid rules'
        });
      }

      // Metadata del rollback
      backupRules.meta = {
        ...backupRules.meta,
        rolled_back_at: new Date().toISOString(),
        rolled_back_by: session.userId,
        rolled_back_from: targetKey
      };

      await configStore.setRules(backupRules);
      await logSecurityEvent('rules_rollback', req, `Rules rolled back to ${targetKey} by ${session.userId}`);

      res.json({
        success: true,
        message: 'Rules rolled back successfully',
        rollbackFrom: targetKey,
        rules: backupRules,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'rollback_failed',
        message: (error as Error).message
      });
    }
  });

  // Limpiar cache por tipo
  router.delete('/cache/:type', csrfProtection, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const { type } = req.params;
      const validTypes = ['rate-limits', 'fingerprints', 'fingerprint', 'token-buckets', 'reputation', 'analytics', 'rules', 'all'];

      if (!validTypes.includes(type)) {
        return res.status(400).json({
          success: false,
          error: 'invalid_cache_type',
          validTypes,
          message: `Invalid cache type: ${type}`
        });
      }

      let deletedKeys = 0;
      let patterns: string[] = [];

      switch (type) {
        case 'rate-limits':
          patterns = ['baf:rate:*'];
          break;
        case 'fingerprints':
          patterns = ['baf:fp:*', 'baf:fingerprint:*'];
          break;
        case 'token-buckets':
          patterns = ['baf:tb:*'];
          break;
        case 'reputation':
          patterns = ['baf:reputation:*'];
          break;
        case 'analytics':
          patterns = ['baf:analytics:*'];
          break;
        case 'all':
          patterns = ['baf:rate:*', 'baf:fp:*', 'baf:tb:*', 'baf:reputation:*', 'baf:analytics:*'];
          break;
      }

      for (const pattern of patterns) {
        const keys = await redis.keys(pattern);
        if (keys.length > 0) {
          const deleted = await redis.del(...keys);
          deletedKeys += deleted;
        }
      }

      await logSecurityEvent('cache_cleared', req, `Cache type ${type} cleared by ${session.userId} (${deletedKeys} keys)`);

      res.json({
        success: true,
        message: `Cleared ${type} cache`,
        deletedKeys,
        patterns,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'cache_clear_failed',
        message: (error as Error).message
      });
    }
  });

  // Generar reportes de seguridad - TODO: mejorar el PDF generation
  router.post('/reports/security', async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const { format = 'json', period = '24h', includeDetails = false } = req.body;

      const reportData = await generateReportData(period, includeDetails);
      
      if (format === 'pdf') {
        const pdfBuffer = await generateSecurityReport(reportData);
        
        res.set({
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename=security-report-${Date.now()}.pdf`
        });
        
        res.end(pdfBuffer);
      } else {
        res.json({
          success: true,
          report: reportData,
          generatedBy: session.userId,
          timestamp: new Date().toISOString()
        });
      }

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'report_generation_failed',
        message: (error as Error).message
      });
    }
  });

  // Rotar token admin
  router.post('/rotate-token', csrfProtection, async (req: Request, res: Response) => {
    try {
      const session = (req as any).adminSession;
      const newToken = crypto.randomBytes(32).toString('hex');
      
      await redis.set('baf:admin:token', newToken);
      await logSecurityEvent('token_rotated', req, `Admin token rotated by ${session.userId}`);
      
      res.json({
        success: true,
        message: 'Admin token rotated successfully',
        token: newToken,
        warning: 'Store this token securely. It will not be shown again.',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'token_rotation_failed',
        message: (error as Error).message
      });
    }
  });

  // Logs de auditoría
  router.get('/audit', async (req: Request, res: Response) => {
    try {
      const { limit = 100, offset = 0, event } = req.query;
      
      const auditKeys = await redis.keys('baf:admin:audit:*');
      auditKeys.sort().reverse(); // más recientes primero
      
      const logs = [];
      const start = parseInt(offset as string) || 0;
      const end = start + (parseInt(limit as string) || 100);
      
      for (const key of auditKeys.slice(start, end)) {
        try {
          const logData = await redis.get(key);
          if (logData) {
            const log = JSON.parse(logData);
            if (!event || log.event === event) {
              logs.push(log);
            }
          }
        } catch (error) {
          // skip entradas inválidas
        }
      }

      res.json({
        success: true,
        logs,
        pagination: {
          total: auditKeys.length,
          limit: parseInt(limit as string) || 100,
          offset: start,
          hasMore: end < auditKeys.length
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'audit_fetch_failed',
        message: (error as Error).message
      });
    }
  });

  return router;
}

// Helper functions
async function authenticateUser(username: string, password: string, mfaCode?: string, ip?: string): Promise<{
  success: boolean;
  user?: any;
  error?: string;
  message?: string;
  mfaRequired?: boolean;
}> {
  // Basic auth implementation - ajgc: expandir esto para producción
  if (username === 'admin' && password === process.env.ADMIN_PASSWORD) {
    return {
      success: true,
      user: {
        id: 'admin',
        username: 'admin',
        role: 'admin',
        permissions: ['*']
      }
    };
  }
  
  return {
    success: false,
    error: 'invalid_credentials',
    message: 'Invalid username or password'
  };
}

async function createAdminSession(user: any, token: string, req: Request, csrfToken?: string): Promise<void> {
  try {
    // Decodificar el token para obtener el jti
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    const sessionKey = `baf:admin:session:${decoded.jti || user.id}`;
    
    // Usar CSRF token proporcionado o generar uno nuevo
    const finalCsrfToken = csrfToken || crypto.randomBytes(32).toString('hex');
    
    const sessionData = {
      userId: user.id,
      role: user.role,
      permissions: JSON.stringify(user.permissions),
      createdAt: Date.now().toString(),
      lastActivity: Date.now().toString(),
      ipAddress: req.ip || 'unknown',
      userAgent: req.get('User-Agent') || 'unknown',
      mfaVerified: 'false',
      csrfToken: finalCsrfToken  // Usar el token final
    };
    
    await redis.hset(sessionKey, sessionData);
    await redis.expire(sessionKey, 3600); // 1 hora
  } catch (error) {
    console.error('Error creating admin session:', error);
    throw error;
  }
}

async function destroyAdminSession(userId: string): Promise<void> {
  const sessionKey = `baf:admin:session:${userId}`;
  await redis.del(sessionKey);
}

async function logSecurityEvent(event: string, req: Request, details?: string): Promise<void> {
  const logEntry = {
    event,
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method,
    details
  };

  logger.warn('Admin security event', logEntry);

  const auditKey = `baf:admin:audit:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`;
  await redis.setex(auditKey, 86400 * 30, JSON.stringify(logEntry));
}

async function generateReportData(period: string, includeDetails: boolean): Promise<any> {
  // TODO: implementar reportes más detallados
  const endTime = Date.now();
  const periodMs = period === '1h' ? 3600000 : period === '24h' ? 86400000 : 604800000;
  const startTime = endTime - periodMs;

  return {
    period: { start: new Date(startTime).toISOString(), end: new Date(endTime).toISOString() },
    summary: {
      totalRequests: 0,
      blockedRequests: 0,
      blockRate: 0
    },
    topThreats: [],
    attackTypes: {},
    systemHealth: {},
    includeDetails,
    generatedAt: new Date().toISOString()
  };
}

export default adminRoutes;
