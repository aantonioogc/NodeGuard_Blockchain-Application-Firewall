// src/api/server.ts - Servidor principal NodeGuard BAF
// Antonio José González Castillo (ajgc) - TFG 2025
import express, { Request, Response, NextFunction, Application } from "express";
import path from "path";
import crypto from "crypto";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { FirewallProvider } from "../core/firewall-provider";
import { EventBus } from "../events/event-bus";
import { ConfigStore } from "../storage/config-store";
import { getMetricsRegistry } from "../metrics/prometheus";
import { logger } from "../logging/logger";
import { adminRoutes } from "./routes/adminRoutes";
import { generateSecurityReport } from "../utils/report-generator";
import { ReputationService } from "../security/reputation/reputation-service";
import redis from "../redis/redis-connection";

// Configuración del servidor
export interface ServerConfig {
  adminAuthRequired: boolean;
  metricsEnabled: boolean;
  corsEnabled: boolean;
  rateLimitEnabled: boolean;
  maxRequestSize: string;
  trustProxy: boolean;
  compressionEnabled: boolean;
}

export interface CreateServerDeps {
  firewallProvider: FirewallProvider;
  configStore: ConfigStore;
  eventBus: EventBus;
  logger: any;
  config: ServerConfig;
  reputationService?: ReputationService;
}

// Admin auth service con JWT - ajgc: esto necesita más testing
class AdminAuthService {
  private static instance: AdminAuthService;
  private jwtSecret: string;
  private tokenExpiry: number = 3600 * 1000; // 1 hora

  private constructor() {
    this.jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    if (!process.env.JWT_SECRET) {
      if (process.env.NODE_ENV === 'production') {
        logger.warn('JWT_SECRET no configurado en producción, usando secreto temporal - CONFIGURA UNA CLAVE SEGURA');
      } else {
        logger.info('JWT_SECRET generado automáticamente para desarrollo');
      }
    }
  }

  public static getInstance(): AdminAuthService {
    if (!AdminAuthService.instance) {
      AdminAuthService.instance = new AdminAuthService();
    }
    return AdminAuthService.instance;
  }

  public async verifyToken(req: Request): Promise<boolean> {
    const token = this.extractToken(req);
    if (!token) return false;

    try {
      // Token de entorno para retrocompatibilidad
      const envToken = process.env.ADMIN_TOKEN;
      if (envToken && token === envToken) return true;

      // Tokens en Redis (plain y hash)
      const [plainStored, hashStored] = await Promise.all([
        redis.get(process.env.BAF_ADMIN_TOKEN_REDIS_KEY || "baf:admin:token"),
        redis.get(process.env.BAF_ADMIN_TOKEN_HASH_REDIS_KEY || "baf:admin:token:hash")
      ]);

      if (plainStored && token === plainStored) return true;
      
      if (hashStored) {
        const hash = crypto.createHash("sha256").update(token).digest("hex");
        if (hash === hashStored) return true;
      }

      // JWT validation
      return this.verifyJWT(token);

    } catch (error) {
      logger.error("Token verification failed", { error: error instanceof Error ? error : new Error(String(error)) });
      return false;
    }
  }

  private extractToken(req: Request): string | null {
    const headerToken = req.header("x-admin-token") || req.header("Authorization")?.replace("Bearer ", "");
    return headerToken?.trim() || null;
  }

  private verifyJWT(token: string): boolean {
    try {
      // JWT verification básico - en prod usar jsonwebtoken
      const [header, payload, signature] = token.split('.');
      if (!header || !payload || !signature) return false;

      const expectedSignature = crypto
        .createHmac('sha256', this.jwtSecret)
        .update(`${header}.${payload}`)
        .digest('base64url');

      if (signature !== expectedSignature) return false;

      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
      // Comparar exp (segundos) con tiempo actual (convertido a segundos)
      return decoded.exp > Math.floor(Date.now() / 1000);

    } catch (error) {
      return false;
    }
  }

  public generateToken(userId: string = 'admin', role: string = 'admin', permissions: string[] = ['*']): string {
    const jti = crypto.randomBytes(16).toString('hex'); // JWT ID único
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      sub: userId,
      jti: jti, // ID único para la sesión
      role: role,
      permissions: permissions,
      iat: Math.floor(Date.now() / 1000), // En segundos
      exp: Math.floor((Date.now() + this.tokenExpiry) / 1000) // En segundos
    })).toString('base64url');

    const signature = crypto
      .createHmac('sha256', this.jwtSecret)
      .update(`${header}.${payload}`)
      .digest('base64url');

    return `${header}.${payload}.${signature}`;
  }
}

// Middleware para admin auth
async function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const authService = AdminAuthService.getInstance();
  const isValid = await authService.verifyToken(req);
  
  if (!isValid) {
    return res.status(401).json({ 
      error: "unauthorized", 
      message: "Token de admin requerido",
      timestamp: new Date().toISOString()
    });
  }
  
  next();
}

// Analytics para el dashboard - esto se puede mejorar mucho
class SecurityAnalytics {
  private eventBus: EventBus;
  private reputationService?: ReputationService;

  constructor(eventBus: EventBus, reputationService?: ReputationService) {
    this.eventBus = eventBus;
    this.reputationService = reputationService;
  }

  // Top atacantes con decay temporal
  public async getTopAttackers(limit: number = 5, timeWindow: string = '24h'): Promise<Array<{
    ip: string;
    score: number;
    attacks: number;
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    lastSeen: number;
    attackTypes: string[];
    geolocation?: string;
  }>> {
    try {
      const attackerKeys = await redis.keys('baf:reputation:ip:*');
      if (attackerKeys.length === 0) return [];

      const attackerDataPromises = attackerKeys.map(async (key) => {
        const ip = key.replace('baf:reputation:ip:', '');
        
        const reputationData = await redis.hgetall(key);
        const attackTypesKey = `baf:analytics:ip_attacks:${ip}`;
        const attackTypes = await redis.smembers(attackTypesKey);
        
        const baseScore = parseInt(reputationData.score || '0');
        const attackCount = parseInt(reputationData.attacks || '0');
        const lastSeen = parseInt(reputationData.lastSeen || '0');
        
        // Decay temporal
        const timeSinceLastAttack = Date.now() - lastSeen;
        const decayFactor = this.getDecayFactor(timeSinceLastAttack, timeWindow);
        const adjustedScore = Math.max(0, baseScore * decayFactor);
        
        return {
          ip,
          score: Math.round(adjustedScore),
          attacks: attackCount,
          threatLevel: this.getThreatLevel(adjustedScore),
          lastSeen,
          attackTypes: attackTypes || [],
          geolocation: reputationData.country || undefined
        };
      });

      const attackers = await Promise.all(attackerDataPromises);
      
      const filtered = attackers
        .filter(attacker => {
          if (timeWindow === '1h') return (Date.now() - attacker.lastSeen) < 3600000;
          if (timeWindow === '24h') return (Date.now() - attacker.lastSeen) < 86400000;
          if (timeWindow === '7d') return (Date.now() - attacker.lastSeen) < 604800000;
          return true;
        })
        .filter(attacker => attacker.attacks > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit);

      return filtered;

    } catch (error) {
      logger.error('Error in getTopAttackers', { error: error instanceof Error ? error : new Error(String(error)) });
      throw new Error(`Failed to retrieve top attackers: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private getDecayFactor(timeSinceLastAttack: number, timeWindow: string): number {
    const maxAge = {
      '1h': 3600000,
      '24h': 86400000, 
      '7d': 604800000
    }[timeWindow] || 86400000;

    if (timeSinceLastAttack > maxAge) return 0;
    
    // Decay exponencial
    const tau = maxAge / 3;
    return Math.exp(-timeSinceLastAttack / tau);
  }

  private getThreatLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  public async getAttacksByReason(): Promise<{[reason: string]: number}> {
    try {
      const reasons = await redis.hgetall('baf:analytics:attack_reasons');
      return Object.fromEntries(
        Object.entries(reasons).map(([k, v]) => [k, parseInt(v as string)])
      );
    } catch (error) {
      logger.error('Failed to get attacks by reason', { error: error instanceof Error ? error : new Error(String(error)) });
      return {};
    }
  }

  public async getRecentMetrics(): Promise<{
    totalRequests: number;
    blockedRequests: number;
    allowedRequests: number;
    blockRate: number;
  }> {
    try {
      const metrics = await redis.hgetall('baf:analytics:metrics');
      const total = parseInt(metrics.totalRequests || '0');
      const blocked = parseInt(metrics.blockedRequests || '0');
      const allowed = parseInt(metrics.allowedRequests || '0');
      
      return {
        totalRequests: total,
        blockedRequests: blocked,
        allowedRequests: allowed,
        blockRate: total > 0 ? (blocked / total) * 100 : 0
      };
    } catch (error) {
      return { totalRequests: 0, blockedRequests: 0, allowedRequests: 0, blockRate: 0 };
    }
  }
}

/**
 * Factory principal del servidor NodeGuard
 */
export function createServer(deps: CreateServerDeps): Promise<{ app: Application; metricsPath: string }> {
  return new Promise((resolve, reject) => {
    try {
      const app = express();
      const analytics = new SecurityAnalytics(deps.eventBus, deps.reputationService);
      const authService = AdminAuthService.getInstance();

      // Headers de seguridad
      app.disable("x-powered-by");
      app.use((req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        next();
      });

      // Trust proxy para IPs correctas - crítico para security
      if (deps.config.trustProxy) {
        const trustedProxies = process.env.TRUSTED_PROXIES;
        if (trustedProxies) {
          app.set('trust proxy', trustedProxies.split(',').map(ip => ip.trim()));
        } else {
          app.set('trust proxy', 1);
        }
        logger.info('Trust proxy enabled', { 
          metadata: { trustedProxies: trustedProxies || 'first proxy only' }
        });
      } else {
        logger.info('Trust proxy disabled - usando IPs directas');
      }

      // CORS config
      if (deps.config.corsEnabled) {
        app.use(cors({
          origin: process.env.CORS_ORIGIN || '*',
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
          allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'x-admin-token', 'Authorization'],
          exposedHeaders: ['X-RateLimit-Remaining', 'X-RateLimit-Reset'],
          credentials: false
        }));
      }

      // Rate limiting
      if (deps.config.rateLimitEnabled) {
        const limiter = rateLimit({
          windowMs: 15 * 60 * 1000,
          max: 1000,
          message: { error: 'Too many requests from this IP' },
          standardHeaders: true,
          legacyHeaders: false,
          handler: (req, res) => {
            logger.warn('Rate limit exceeded', { ip: req.ip });
            res.status(429).json({ error: 'Rate limit exceeded' });
          }
        });
        app.use('/admin', limiter);
      }

      // Body parsing con límites y manejo de errores JSON
      app.use(express.json({ 
        limit: deps.config.maxRequestSize || '10mb',
        verify: (req: any, res, buf) => {
          req.rawBody = buf; // para verificación de signature si hace falta
        }
      }));
      
      // Middleware para manejar errores de JSON parsing
      app.use((error: any, req: Request, res: Response, next: NextFunction) => {
        if (error instanceof SyntaxError && error.message.includes('JSON')) {
          return res.status(400).json({
            jsonrpc: '2.0',
            error: { 
              code: -32700, 
              message: 'Parse error: Invalid JSON',
              data: error.message
            },
            id: null
          });
        }
        next();
      });
      
      app.use(express.urlencoded({ extended: true, limit: deps.config.maxRequestSize || '10mb' }));

      // Request logging middleware
      app.use((req, res, next) => {
        const startTime = Date.now();
        const originalSend = res.json.bind(res);

        res.json = function(data) {
          const duration = Date.now() - startTime;
          
          deps.logger.info('HTTP Request', {
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            duration,
            statusCode: res.statusCode,
            contentLength: JSON.stringify(data || {}).length
          });

          return originalSend(data);
        };

        next();
      });

      // Landing page con info del sistema
      app.get('/', async (req: Request, res: Response) => {
        try {
          const uptime = process.uptime();
          const metrics = await analytics.getRecentMetrics();
          const topAttackers = await analytics.getTopAttackers(3);
          
          res.json({
            name: "NodeGuard Blockchain Application Firewall",
            version: "2.0.0",
            status: "active",
            uptime: {
              seconds: Math.floor(uptime),
              formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
            },
            services: {
              redis: await deps.configStore.isRedisConnected(),
              upstream: await deps.firewallProvider.isUpstreamHealthy(),
              eventBus: deps.eventBus.isHealthy()
            },
            metrics: {
              ...metrics,
              blockRate: `${metrics.blockRate.toFixed(2)}%`
            },
            security: {
              topThreats: topAttackers.length,
              enforcement: process.env.ENFORCEMENT_MODE || 'block',
              featuresEnabled: ['rate-limiting', 'fingerprinting', 'reputation', 'ml-detection']
            },
            endpoints: {
              rpc: "/rpc",
              health: "/healthz", 
              dashboard: "/dashboard",
              events: "/events",
              metrics: "/metrics",
              admin: "/admin"
            }
          });
        } catch (error) {
          deps.logger.error('Failed to generate landing page', { error: error instanceof Error ? error.message : String(error) });
          res.status(500).json({ error: 'internal_error' });
        }
      });

      // Health check detallado
      app.get('/healthz', async (req: Request, res: Response) => {
        try {
          const services = {
            server: true,
            redis: await deps.configStore.isRedisConnected(),
            upstream: await deps.firewallProvider.isUpstreamHealthy(),
            configStore: deps.configStore.isHealthy(),
            eventBus: deps.eventBus.isHealthy()
          };

          const allHealthy = Object.values(services).every(Boolean);
          const metrics = await analytics.getRecentMetrics();

          res.status(allHealthy ? 200 : 503).json({
            status: allHealthy ? 'healthy' : 'degraded',
            timestamp: new Date().toISOString(),
            services,
            version: '2.0.0',
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            metrics
          });
        } catch (error) {
          res.status(503).json({
            status: 'error',
            error: error instanceof Error ? error.message : String(error),
            timestamp: new Date().toISOString()
          });
        }
      });

      // Dashboard HTML
      app.get('/dashboard', (req: Request, res: Response) => {
        res.sendFile(path.resolve(process.cwd(), 'src', 'api', 'dashboard.html'));
      });

      // Dashboard Setup Page
      app.get('/setup', (req: Request, res: Response) => {
        res.sendFile(path.resolve(process.cwd(), 'src', 'api', 'dashboard-setup.html'));
      });

      // Debug endpoint para eventos
      app.get('/events-debug', (req: Request, res: Response) => {
        res.json({
          eventBusActive: !!deps.eventBus,
          timestamp: new Date().toISOString(),
          message: "Event bus debug endpoint"
        });
      });

      // Server-Sent Events con filtrado
      app.get('/events', (req: Request, res: Response) => {
        const eventType = req.query.type as string;
        
        logger.info('SSE connection requested', { ip: req.ip, userAgent: req.get('User-Agent') });
        
        // NO configurar headers aquí - dejar que EventBus lo maneje completamente
        const filters = eventType ? [{ type: eventType }] : [];
        const unsubscribe = deps.eventBus.subscribe(res, filters);

        // Cleanup cuando la conexión se cierra
        req.on('close', () => {
          logger.info('SSE connection closed', { ip: req.ip });
          unsubscribe();
        });

        req.on('error', (err) => {
          logger.error('SSE connection error', { ip: req.ip, error: err });
          unsubscribe();
        });
      });

      // API endpoints para analytics
      app.get('/api/analytics/top-attackers', requireAdmin, async (req: Request, res: Response) => {
        try {
          const limit = parseInt(req.query.limit as string) || 5;
          const timeWindow = req.query.timeWindow as string || '24h';
          
          const attackers = await analytics.getTopAttackers(limit, timeWindow);
          
          res.json({
            success: true,
            data: attackers,
            metadata: {
              total: attackers.length,
              timeWindow,
              generatedAt: new Date().toISOString()
            }
          });
          
        } catch (error) {
          deps.logger.error('Failed to get top attackers', { 
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined 
          });
          
          res.status(500).json({
            success: false,
            error: 'Failed to retrieve attacker data',
            message: error instanceof Error ? error.message : String(error)
          });
        }
      });

      // Attack reasons para donut chart
      app.get('/api/analytics/attack-reasons', requireAdmin, async (req: Request, res: Response) => {
        try {
          const reasons = await analytics.getAttacksByReason();
          res.json({ success: true, data: reasons });
        } catch (error) {
          res.status(500).json({ 
            success: false, 
            error: error instanceof Error ? error.message : String(error) 
          });
        }
      });

      // Generar reporte PDF
      app.post('/api/analytics/generate-report', requireAdmin, async (req: Request, res: Response) => {
        try {
          const { startDate, endDate, includeDetails } = req.body;
          
          const reportData = {
            metrics: await analytics.getRecentMetrics(),
            topAttackers: await analytics.getTopAttackers(10),
            attackReasons: await analytics.getAttacksByReason(),
            period: { startDate, endDate },
            includeDetails: includeDetails || false,
            generatedAt: new Date().toISOString(),
            generatedBy: req.header('x-user-id') || 'admin'
          };

          const pdfBuffer = await generateSecurityReport(reportData);
          
          res.set({
            'Content-Type': 'application/pdf',
            'Content-Disposition': `attachment; filename=security-report-${Date.now()}.pdf`,
            'Content-Length': pdfBuffer.length
          });
          
          res.end(pdfBuffer);
        } catch (error) {
          deps.logger.error('Failed to generate PDF report', { error: error instanceof Error ? error.message : String(error) });
          res.status(500).json({ success: false, error: 'Failed to generate report' });
        }
      });

      // Reset analytics data for new dashboard session
      app.post('/api/analytics/reset-session', requireAdmin, async (req: Request, res: Response) => {
        try {
          logger.info('🧹 Dashboard session reset requested');
          
          // Clear analytics metrics
          const metricsKeys = await redis.keys('baf:analytics:*');
          if (metricsKeys.length > 0) {
            await redis.del(...metricsKeys);
            logger.info(`Cleared ${metricsKeys.length} analytics keys`);
          }
          
          // Clear reputation data
          const reputationKeys = await redis.keys('baf:reputation:*');
          if (reputationKeys.length > 0) {
            await redis.del(...reputationKeys);
            logger.info(`Cleared ${reputationKeys.length} reputation keys`);
          }
          
          // Reset metrics to zero
          await redis.hset('baf:analytics:metrics', {
            totalRequests: '0',
            blockedRequests: '0',
            allowedRequests: '0',
            rateLimitedRequests: '0',
            lastReset: Date.now().toString()
          });
          
          logger.info('✅ Dashboard session reset completed');
          
          res.json({ 
            success: true, 
            message: 'Analytics data reset successfully',
            timestamp: new Date().toISOString()
          });
          
        } catch (error) {
          logger.error('Failed to reset analytics data', { 
            error: error instanceof Error ? error : new Error(String(error))
          });
          res.status(500).json({ 
            success: false, 
            error: 'Failed to reset analytics data' 
          });
        }
      });

      // Prometheus metrics
      if (deps.config.metricsEnabled) {
        const registry = getMetricsRegistry();
        app.get('/metrics', async (req: Request, res: Response) => {
          try {
            res.set('Content-Type', registry.contentType);
            const metrics = await registry.metrics();
            res.end(metrics);
          } catch (error) {
            deps.logger.error('Error generating metrics', { error: error instanceof Error ? error.message : String(error) });
            res.status(500).send('Metrics generation failed');
          }
        });
      }

      // Mount admin routes
      app.use('/admin', adminRoutes(deps.configStore, deps.eventBus, authService));

      // Endpoint principal JSON-RPC
      app.post('/rpc', async (req: Request, res: Response) => {
        const startTime = Date.now();
        const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
        
        try {
          // Validación del payload
          if (!req.body) {
            return res.status(400).json({
              jsonrpc: '2.0',
              error: { code: -32700, message: 'Parse error: No request body' },
              id: null
            });
          }

          // Validación de JSON-RPC básica
          if (typeof req.body !== 'object') {
            return res.status(400).json({
              jsonrpc: '2.0',
              error: { code: -32700, message: 'Parse error: Invalid JSON' },
              id: null
            });
          }

          // Para requests batch, validar que es un array
          if (Array.isArray(req.body)) {
            if (req.body.length === 0) {
              return res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid Request: Empty batch' },
                id: null
              });
            }
          } else {
            // Para request individual, validar campos obligatorios
            if (!req.body.jsonrpc || req.body.jsonrpc !== '2.0') {
              return res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid Request: Missing or invalid jsonrpc version' },
                id: req.body.id || null
              });
            }
            
            if (!req.body.method || typeof req.body.method !== 'string') {
              return res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid Request: Missing or invalid method' },
                id: req.body.id || null
              });
            }
          }

          const result = await deps.firewallProvider.handleJsonRpc(req.body, clientIp);

          // Update analytics - ajgc: esto se puede optimizar
          await redis.hincrby('baf:analytics:metrics', 'totalRequests', 1);
          if ((result as any).error) {
            await redis.hincrby('baf:analytics:metrics', 'blockedRequests', 1);
          } else {
            await redis.hincrby('baf:analytics:metrics', 'allowedRequests', 1);
          }

          const duration = Date.now() - startTime;
          res.set('X-Response-Time', `${duration}ms`);
          res.json(result);

        } catch (error) {
          const duration = Date.now() - startTime;
          deps.logger.error('JSON-RPC handler error', {
            error: error instanceof Error ? error.message : String(error),
            duration,
            ip: clientIp,
            method: req.body?.method
          });

          res.status(500).json({
            jsonrpc: '2.0',
            error: { 
              code: -32603, 
              message: 'Internal error',
              data: { duration: `${duration}ms` }
            },
            id: req.body?.id || null
          });
        }
      });

      // Fallback para POST / (backwards compatibility) 
      app.post('/', (req, res) => res.redirect(307, '/rpc'));

      // 404 handler
      app.use('*', (req: Request, res: Response) => {
        res.status(404).json({
          error: 'Not Found',
          message: `Endpoint ${req.method} ${req.originalUrl} not found`,
          availableEndpoints: ['/', '/rpc', '/healthz', '/dashboard', '/events', '/metrics', '/admin']
        });
      });

      // Global error handler
      app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
        deps.logger.error('Unhandled server error', {
          error: error.message,
          stack: error.stack,
          url: req.url,
          method: req.method
        });

        if (res.headersSent) return next(error);

        res.status(500).json({
          error: 'Internal Server Error',
          message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
        });
      });

      resolve({ app, metricsPath: '/metrics' });

    } catch (error) {
      reject(error);
    }
  });
}

// Export utilities
export { AdminAuthService, SecurityAnalytics, requireAdmin };

// Update attacker reputation cuando se bloquea un ataque
export async function updateAttackerReputation(
  ip: string, 
  attackType: string, 
  severity: number = 10
): Promise<void> {
  try {
    // Verificar si Redis está disponible
    if (!redis) {
      logger.debug('Redis not available, skipping reputation update', { ip: ip.substring(0, 12) + '...' });
      return;
    }

    const reputationKey = `baf:reputation:ip:${ip}`;
    const attackTypesKey = `baf:analytics:ip_attacks:${ip}`;
    
    // Pipeline para atomicidad
    const pipeline = redis.pipeline();
    
    pipeline.hincrby(reputationKey, 'score', severity);
    pipeline.hincrby(reputationKey, 'attacks', 1);
    pipeline.hset(reputationKey, 'lastSeen', Date.now());
    pipeline.sadd(attackTypesKey, attackType);
    
    // TTL para limpieza automática (30 días)
    pipeline.expire(reputationKey, 30 * 24 * 60 * 60);
    pipeline.expire(attackTypesKey, 30 * 24 * 60 * 60);
    
    await pipeline.exec();
    
    logger.debug('Updated attacker reputation', {
      ip: ip.substring(0, 12) + '...',
      attackType,
      severity
    });
    
  } catch (error) {
    // No usar logger.error para evitar spam en logs
    logger.debug('Failed to update attacker reputation (non-critical)', { 
      error: error instanceof Error ? error : new Error(String(error)),
      ipAddress: ip.substring(0, 12) + '...',
      metadata: { attackType }
    });
  }
}
