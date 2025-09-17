// src/api/middleware/adminMiddleware.ts - Middleware de seguridad para admin
// Autor: Antonio José González Castillo (ajgc) - TFG BAF
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import redis from '../../redis/redis-connection';
import { logger } from '../../logging/logger';
import { SlidingWindowLimiter } from '../../rateLimiting/algorithms/slidingWindow';

/**
 * Clase para el middleware de seguridad de admin
 * 
 * Incluye autenticación JWT, control de acceso por IP, rate limiting
 * y gestión de sesiones con Redis. TODO: revisar la validación MFA
 */

interface AdminSession {
  userId: string;
  role: 'admin' | 'readonly' | 'operator';
  permissions: string[];
  createdAt: number;
  lastActivity: number;
  ipAddress: string;
  userAgent: string;
  mfaVerified: boolean;
  csrfToken?: string; // Agregar CSRF token opcional
}

interface AdminUser {
  id: string;
  username: string;
  role: 'admin' | 'readonly' | 'operator';
  permissions: string[];
  mfaEnabled: boolean;
  ipWhitelist?: string[];
  lastLogin?: number;
  loginAttempts: number;
  lockedUntil?: number;
}

/**
 * Rate limiter para endpoints de admin - más restrictivo que el normal
 * Inicialización lazy para evitar problemas con Redis en tests
 */
let adminRateLimiter: SlidingWindowLimiter | null = null;

function getAdminRateLimiter(): SlidingWindowLimiter {
  if (!adminRateLimiter) {
    adminRateLimiter = new SlidingWindowLimiter();
  }
  return adminRateLimiter;
}

/**
 * Validación de token de admin con múltiples métodos de auth
 * TODO: mejorar la validación de MFA cuando tengamos tiempo
 */
export async function requireAdminToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const startTime = Date.now();
  
  try {
    // Aplicamos rate limiting primero - que no nos capen
    const rateLimitResult = await getAdminRateLimiter().checkLimit(
      `admin:${req.ip}:${req.path}`, 
      { windowMs: 15 * 60 * 1000, maxRequests: 50, keyPrefix: 'admin-rate-limit' }
    );
    
    if (!rateLimitResult.allowed) {
      logger.warn('Rate limit excedido para admin', { ipAddress: req.ip, metadata: { path: req.path } });
      res.status(429).json({
        error: 'rate_limit_exceeded',
        message: 'Demasiadas peticiones de admin. Inténtalo más tarde.',
        retryAfter: Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000)
      });
      return;
    }

    // Extraemos las credenciales de autenticación
    const authResult = await extractAuthCredentials(req);
    if (!authResult.success) {
      await logSecurityEvent('auth_failed', req, authResult.error);
      res.status(401).json({
        error: 'authentication_required',
        message: authResult.error,
        timestamp: new Date().toISOString()
      });
      return;
    }

    // Validamos sesión y permisos
    const session = await validateAdminSession(authResult.token!, req);
    if (!session) {
      await logSecurityEvent('invalid_session', req, 'Validación de sesión fallida');
      res.status(401).json({
        error: 'invalid_session',
        message: 'Sesión expirada o inválida. Re-autentícate.',
        timestamp: new Date().toISOString()
      });
      return;
    }

    // Verificamos IP y permisos - combo letal
    if (!await isIpAllowed(session.ipAddress, session.userId)) {
      await logSecurityEvent('ip_not_allowed', req, `IP ${session.ipAddress} no está en la whitelist`);
      res.status(403).json({
        error: 'ip_not_allowed',
        message: 'Acceso denegado desde esta IP',
        timestamp: new Date().toISOString()
      });
      return;
    }

    if (!await checkEndpointPermission(req.path, req.method, session)) {
      await logSecurityEvent('insufficient_permissions', req, `Faltan permisos para ${req.method} ${req.path}`);
      res.status(403).json({
        error: 'insufficient_permissions',
        message: 'No tienes permisos para acceder a este endpoint',
        timestamp: new Date().toISOString()
      });
      return;
    }

    // Todo OK, actualizamos sesión y seguimos
    await updateSessionActivity(authResult.token!, req);
    (req as any).adminSession = session;
    (req as any).adminUser = await getAdminUser(session.userId);

    logger.debug('Autenticación admin exitosa', {
      userId: session.userId,
      metadata: { method: req.method, duration: Date.now() - startTime }
    });

    next();

  } catch (error) {
    const err = error as Error;
    logger.error('Error en autenticación admin', { error: err, ipAddress: req.ip });
    await logSecurityEvent('auth_error', req, err.message);

    res.status(500).json({
      error: 'authentication_error',
      message: 'Error interno de autenticación',
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Extrae credenciales de autenticación del request
 * Varios métodos que van desde Bearer hasta query params (que es una chapuza pero a veces hace falta)
 */
async function extractAuthCredentials(req: Request): Promise<{
  success: boolean;
  token?: string;
  error?: string;
}> {
  // JWT Bearer - lo más pro
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (token) return { success: true, token };
  }

  // Header custom para APIs
  const adminToken = req.headers['x-admin-token'] as string;
  if (adminToken) return { success: true, token: adminToken };

  // Query param - no muy seguro pero útil para testing
  const queryToken = req.query.token as string;
  if (queryToken) {
    logger.warn('Token via query param - cuidao que se ve en logs', {
      ipAddress: req.ip,
      metadata: { path: req.path }
    });
    return { success: true, token: queryToken };
  }

  // Cookie de sesión
  const sessionCookie = req.cookies?.adminSession;
  if (sessionCookie) return { success: true, token: sessionCookie };

  return {
    success: false,
    error: 'Falta token de auth. Usa Authorization header, X-Admin-Token, o cookie.'
  };
}

/**
 * Validación de sesión - primero JWT, luego token simple
 */
async function validateAdminSession(token: string, req: Request): Promise<AdminSession | null> {
  try {
    // Si tiene puntos es JWT
    if (token.includes('.')) {
      return await validateJWTSession(token, req);
    }
    // Si no, token simple
    return await validateSimpleToken(token, req);
  } catch (error) {
    logger.warn('Validación falló', { error: error as Error, ipAddress: req.ip });
    return null;
  }
}

/**
 * JWT validation - el rollito estándar
 */
async function validateJWTSession(token: string, req: Request): Promise<AdminSession | null> {
  try {
    const jwtSecret = process.env.JWT_SECRET || process.env.ADMIN_JWT_SECRET;
    if (!jwtSecret) throw new Error('JWT secret no configurado - revisa el .env');

    const decoded = jwt.verify(token, jwtSecret) as any;
    
    // Validar que el JWT tenga todo lo que necesitamos
    if (!decoded.sub || !decoded.role || !decoded.permissions) {
      throw new Error('JWT malformado');
    }

    // Buscar sesión en Redis
    const sessionKey = `baf:admin:session:${decoded.jti || decoded.sub}`;
    const sessionData = await redis.hgetall(sessionKey);
    
    if (!sessionData || Object.keys(sessionData).length === 0) {
      throw new Error('Sesión no existe en Redis');
    }

    const session: AdminSession = {
      userId: decoded.sub,
      role: decoded.role,
      permissions: Array.isArray(decoded.permissions) ? decoded.permissions : JSON.parse(decoded.permissions),
      createdAt: parseInt(sessionData.createdAt || '0'),
      lastActivity: parseInt(sessionData.lastActivity || '0'),
      ipAddress: sessionData.ipAddress || req.ip || 'unknown',
      userAgent: sessionData.userAgent || req.get('User-Agent') || 'unknown',
      mfaVerified: sessionData.mfaVerified === 'true',
      csrfToken: sessionData.csrfToken // Incluir CSRF token de Redis
    };

    // Check timeout
    const timeout = Number(process.env.ADMIN_SESSION_TIMEOUT || 3600000); // 1h
    if (Date.now() - session.lastActivity > timeout) {
      await redis.del(sessionKey);
      throw new Error('Sesión caducada');
    }

    // Validar IP si está configurado (paranoico mode)
    if (process.env.ADMIN_STRICT_IP_VALIDATION === 'true' && session.ipAddress !== req.ip) {
      throw new Error('IP cambió durante la sesión');
    }

    return session;

  } catch (error) {
    logger.warn('JWT validation failed', { error: error as Error, ipAddress: req.ip });
    return null;
  }
}

/**
 * Token simple validation - legacy pero útil para desarrollo
 */
async function validateSimpleToken(token: string, req: Request): Promise<AdminSession | null> {
  try {
    // Token hardcoded de desarrollo
    const envToken = process.env.ADMIN_TOKEN;
    if (envToken && token === envToken) {
      return {
        userId: 'admin',
        role: 'admin',
        permissions: ['*'],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        mfaVerified: false // No MFA para token simple
      };
    }

    // Tokens almacenados en Redis - más flexibilidad
    const [plainStored, hashStored] = await Promise.all([
      redis.get(process.env.BAF_ADMIN_TOKEN_REDIS_KEY || "baf:admin:token"),
      redis.get(process.env.BAF_ADMIN_TOKEN_HASH_REDIS_KEY || "baf:admin:token:hash")
    ]);

    let valid = false;

    // Plain token check
    if (plainStored && token === plainStored) {
      valid = true;
    } 
    // Hash check
    else if (hashStored) {
      const hash = crypto.createHash("sha256").update(token).digest("hex");
      valid = hash === hashStored;
    }

    if (valid) {
      return {
        userId: 'admin',
        role: 'admin', 
        permissions: ['*'],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        ipAddress: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        mfaVerified: false
      };
    }

    return null;

  } catch (error) {
    logger.warn('Token simple validation failed', { error: error as Error, ipAddress: req.ip });
    return null;
  }
}

/**
 * Check de whitelist de IPs
 */
async function isIpAllowed(ip: string, userId: string): Promise<boolean> {
  try {
    // Global whitelist check
    const globalWhitelist = process.env.ADMIN_IP_WHITELIST;
    if (globalWhitelist) {
      const allowed = globalWhitelist.split(',').map(ip => ip.trim());
      if (allowed.includes(ip) || allowed.includes('*')) return true;
    }

    // User-specific whitelist
    const userKey = `baf:admin:user:${userId}`;
    const userData = await redis.hgetall(userKey);
    
    if (userData.ipWhitelist) {
      const userAllowed = JSON.parse(userData.ipWhitelist);
      if (userAllowed.includes(ip) || userAllowed.includes('*')) return true;
    }

    // Development mode - todo permitido (cuidao con esto en prod)
    if (!globalWhitelist && !userData.ipWhitelist && process.env.NODE_ENV === 'development') {
      return true;
    }

    return false;

  } catch (error) {
    logger.error('Error checking IP whitelist', { error: error as Error, userId, metadata: { ip } });
    return false; // Fail safe
  }
}

/**
 * Verificar permisos para el endpoint - modo jeraquico
 */
async function checkEndpointPermission(path: string, method: string, session: AdminSession): Promise<boolean> {
  // Admin total - puede hacer todo
  if (session.permissions.includes('*')) return true;

  const required = getRequiredPermission(path, method);
  
  // Exact match
  if (session.permissions.includes(required)) return true;

  // Wildcard permissions check
  const parts = path.split('/');
  for (let i = parts.length; i > 0; i--) {
    const wildcard = parts.slice(0, i).join('/') + '/*';
    if (session.permissions.includes(wildcard)) return true;
  }

  return false;
}

/**
 * Map de permisos por endpoint
 */
function getRequiredPermission(path: string, method: string): string {
  const perms: { [key: string]: string } = {
    'GET /admin': 'admin:info:read',
    'GET /admin/health': 'admin:health:read', 
    'GET /admin/stats': 'admin:stats:read',
    'GET /admin/rules': 'admin:rules:read',
    'POST /admin/rules': 'admin:rules:write',
    'PUT /admin/rules': 'admin:rules:write',
    'DELETE /admin/rules': 'admin:rules:delete',
    'GET /admin/rules/backups': 'admin:rules:read',
    'POST /admin/rules/rollback': 'admin:rules:write',
    'DELETE /admin/cache/*': 'admin:cache:delete',
    'POST /admin/rotate-token': 'admin:tokens:write',
    'GET /admin/users': 'admin:users:read',
    'POST /admin/users': 'admin:users:write',
    'PUT /admin/users/*': 'admin:users:write',
    'DELETE /admin/users/*': 'admin:users:delete'
  };

  const key = `${method} ${path}`;
  return perms[key] || `admin:${path.split('/')[2] || 'unknown'}:${method.toLowerCase()}`;
}

/**
 * Update session activity - keep alive
 */
async function updateSessionActivity(token: string, req: Request): Promise<void> {
  try {
    if (token.includes('.')) {
      // JWT token - update Redis session
      const decoded = jwt.decode(token) as any;
      if (decoded?.jti || decoded?.sub) {
        const key = `baf:admin:session:${decoded.jti || decoded.sub}`;
        await redis.hset(key, {
          lastActivity: Date.now(),
          ipAddress: req.ip,
          userAgent: req.get('User-Agent') || 'unknown'
        });
      }
    }
  } catch (error) {
    logger.warn('Error updating session activity', { error: error as Error, ipAddress: req.ip });
  }
}

/**
 * Get admin user details from Redis
 */
async function getAdminUser(userId: string): Promise<AdminUser | null> {
  try {
    const userKey = `baf:admin:user:${userId}`;
    const data = await redis.hgetall(userKey);
    
    if (!data || Object.keys(data).length === 0) return null;

    return {
      id: userId,
      username: data.username || userId,
      role: data.role as 'admin' | 'readonly' | 'operator' || 'readonly',
      permissions: data.permissions ? JSON.parse(data.permissions) : [],
      mfaEnabled: data.mfaEnabled === 'true',
      ipWhitelist: data.ipWhitelist ? JSON.parse(data.ipWhitelist) : undefined,
      lastLogin: data.lastLogin ? parseInt(data.lastLogin) : undefined,
      loginAttempts: parseInt(data.loginAttempts || '0'),
      lockedUntil: data.lockedUntil ? parseInt(data.lockedUntil) : undefined
    };

  } catch (error) {
    logger.error('Error getting admin user', { error: error as Error, userId });
    return null;
  }
}

/**
 * Log security events - auditoría
 */
async function logSecurityEvent(event: string, req: Request, details?: string): Promise<void> {
  try {
    const logEntry = {
      event,
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      details
    };

    // Winston log
    logger.warn('Admin security event', logEntry);

    // Redis storage para auditoría (30 días)
    const key = `baf:admin:audit:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`;
    await redis.setex(key, 86400 * 30, JSON.stringify(logEntry));

  } catch (error) {
    logger.error('Error al registrar evento de seguridad', {
      error: error as Error
    });
  }
}

/**
 * Endpoint de información del admin con detalles de seguridad
 */
export function adminInfo(req: Request, res: Response): void {
  const session = (req as any).adminSession as AdminSession;
  
  res.json({
    message: 'Panel de Administración NodeGuard v2.0',
    version: process.env.npm_package_version || '2.0.0',
    user: session ? {
      userId: session.userId,
      role: session.role,
      permissions: session.permissions,
      mfaVerified: session.mfaVerified,
      sessionAge: Math.floor((Date.now() - session.createdAt) / 1000)
    } : null,
    endpoints: {
      '/admin': 'Información del panel de admin',
      '/admin/health': 'Chequeo detallado de salud del sistema',
      '/admin/stats': 'Estadísticas y métricas del sistema',
      '/admin/rules': 'GET/POST/PUT/DELETE - Gestión de reglas del firewall',
      '/admin/rules/backups': 'GET - Listar backups de reglas',
      '/admin/rules/rollback': 'POST - Rollback a reglas anteriores',
      '/admin/cache/{type}': 'DELETE - Limpiar tipos específicos de cache',
      '/admin/rotate-token': 'POST - Rotar token de autenticación admin',
      '/admin/users': 'GET/POST - Gestión de usuarios (solo admin)',
      '/admin/audit': 'GET - Logs de auditoría de seguridad'
    },
    authentication: {
      methods: ['JWT Bearer Token', 'X-Admin-Token Header', 'Cookie de Sesión'],
      mfaSupported: true,
      sessionTimeout: `${Number(process.env.ADMIN_SESSION_TIMEOUT || 3600000) / 1000}s`,
      ipWhitelistEnabled: !!process.env.ADMIN_IP_WHITELIST
    },
    security: {
      rateLimitEnabled: true,
      auditLoggingEnabled: true,
      ipValidationEnabled: process.env.ADMIN_STRICT_IP_VALIDATION === 'true',
      encryptionEnabled: !!process.env.JWT_SECRET
    },
    examples: {
      jwtAuth: 'curl -H "Authorization: Bearer <jwt_token>" http://localhost:3000/admin/health',
      tokenAuth: 'curl -H "X-Admin-Token: <admin_token>" http://localhost:3000/admin/health',
      cookieAuth: 'curl -b "adminSession=<session_cookie>" http://localhost:3000/admin/health'
    },
    timestamp: new Date().toISOString()
  });
}

/**
 * Middleware para operaciones de solo lectura
 * Los usuarios readonly no pueden hacer POST/PUT/DELETE
 */
export function requireReadonlyAdmin(req: Request, res: Response, next: NextFunction): void {
  requireAdminToken(req, res, (err) => {
    if (err) return next(err);
    
    const session = (req as any).adminSession as AdminSession;
    if (session.role === 'readonly' && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      res.status(403).json({
        error: 'readonly_access',
        message: 'Los usuarios readonly no pueden realizar operaciones de escritura',
        allowedMethods: ['GET', 'HEAD', 'OPTIONS']
      });
      return;
    }
    
    next();
  });
}

/**
 * CSRF protection - evita cross-site request forgery
 * Por ahora básico, luego lo puedo mejorar
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfToken = req.headers['x-csrf-token'] as string;
    const sessionToken = (req as any).adminSession?.csrfToken;
    
    if (!csrfToken || csrfToken !== sessionToken) {
      res.status(403).json({
        error: 'csrf_token_mismatch',
        message: 'CSRF token inválido - possible attack attempt'
      });
      return;
    }
  }
  
  next();
}

// Export principal
export default {
  requireAdminToken,
  requireReadonlyAdmin,
  adminInfo,
  csrfProtection
};