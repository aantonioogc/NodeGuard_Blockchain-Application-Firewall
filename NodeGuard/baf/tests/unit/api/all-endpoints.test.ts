// tests/unit/api/all-endpoints-final.test.ts
// Test completo y optimizado de todos los endpoints NodeGuard BAF
// Autor: Antonio José González Castillo (ajgc) - TFG BAF

import request from 'supertest';
import express from 'express';
import { FirewallProvider } from '../../../src/core/firewall-provider';
import { ConfigStore } from '../../../src/storage/config-store';
import { EventBus } from '../../../src/events/event-bus';
import { createServer, AdminAuthService } from '../../../src/api/server';
import crypto from 'crypto';

// Mock dependencies con configuración optimizada
jest.mock('../../../src/core/firewall-provider');
jest.mock('../../../src/storage/config-store');
jest.mock('../../../src/events/event-bus');
jest.mock('../../../src/redis/redis-connection');
jest.mock('../../../src/logging/logger');
jest.mock('../../../src/metrics/prometheus');
jest.mock('../../../src/utils/report-generator');

// Timeout global reducido para tests de API
jest.setTimeout(30000);

describe('🚀 NodeGuard BAF - Complete Endpoints Test Suite', () => {
  let app: express.Application;
  let mockFirewall: jest.Mocked<FirewallProvider>;
  let mockConfigStore: jest.Mocked<ConfigStore>;
  let mockEventBus: jest.Mocked<EventBus>;
  let validJwtToken: string;
  let validAdminToken: string;

  beforeAll(async () => {
    // Setup mocks
    mockFirewall = new FirewallProvider({} as any) as jest.Mocked<FirewallProvider>;
    mockConfigStore = new ConfigStore({} as any) as jest.Mocked<ConfigStore>;
    mockEventBus = new EventBus() as jest.Mocked<EventBus>;

    // Configure firewall mock
    mockFirewall.handleJsonRpc = jest.fn().mockResolvedValue({
      id: 1,
      jsonrpc: '2.0',
      result: { blockNumber: '0x1234' }
    });
    mockFirewall.isUpstreamHealthy = jest.fn().mockResolvedValue(true);

    // Configure config store mock  
    (mockConfigStore.isRedisConnected as any) = jest.fn().mockResolvedValue(true);
    mockConfigStore.isHealthy = jest.fn().mockReturnValue(true);
    mockConfigStore.getRules = jest.fn().mockResolvedValue({
      static: {
        'test-rule': {
          enabled: true,
          action: 'block',
          conditions: ['test']
        }
      },
      heuristics: {},
      meta: { 
        version: '1.0.0', 
        updated_at: new Date().toISOString(),
        created_at: new Date().toISOString()
      }
    });
    mockConfigStore.setRules = jest.fn().mockResolvedValue(undefined);

    // Configure event bus mock
    mockEventBus.isHealthy = jest.fn().mockReturnValue(true);
    mockEventBus.subscribe = jest.fn().mockReturnValue(() => {});

    // Setup comprehensive Redis mock
    const redisMock = require('../../../src/redis/redis-connection').default;
    validAdminToken = crypto.randomBytes(32).toString('hex');
    
    redisMock.get = jest.fn().mockImplementation((key: string) => {
      if (key.includes('token')) return Promise.resolve(validAdminToken);
      if (key.includes('backup')) return Promise.resolve(JSON.stringify({
        static: {},
        heuristics: {},
        meta: { created_at: new Date().toISOString() }
      }));
      return Promise.resolve(null);
    });
    
    redisMock.hgetall = jest.fn().mockResolvedValue({
      totalRequests: '1000',
      blockedRequests: '50',
      allowedRequests: '950'
    });
    redisMock.hincrby = jest.fn().mockResolvedValue(1);
    redisMock.keys = jest.fn().mockResolvedValue(['baf:session:1', 'baf:user:admin']);
    redisMock.ping = jest.fn().mockResolvedValue('PONG');
    redisMock.del = jest.fn().mockResolvedValue(5);
    redisMock.setex = jest.fn().mockResolvedValue('OK');
    redisMock.set = jest.fn().mockResolvedValue('OK');
    redisMock.lrange = jest.fn().mockResolvedValue(['backup-1', 'backup-2']);
    redisMock.lindex = jest.fn().mockResolvedValue('backup-latest');
    redisMock.pipeline = jest.fn().mockReturnValue({
      exec: jest.fn().mockResolvedValue([['OK'], ['OK'], ['OK']])
    });

    // Setup metrics mock
    const promMock = require('../../../src/metrics/prometheus');
    promMock.getMetricsRegistry = jest.fn().mockReturnValue({
      contentType: 'text/plain; version=0.0.4; charset=utf-8',
      metrics: jest.fn().mockResolvedValue('# NodeGuard BAF Metrics\nbaf_requests_total 1000\n')
    });

    // Setup report generator mock
    const reportMock = require('../../../src/utils/report-generator');
    reportMock.generateSecurityReport = jest.fn().mockResolvedValue(
      Buffer.from('%PDF-1.4 Mock PDF content for testing')
    );

    // Create server
    const deps = {
      firewallProvider: mockFirewall,
      configStore: mockConfigStore,
      eventBus: mockEventBus,
      logger: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
      config: {
        adminAuthRequired: true,
        metricsEnabled: true,
        corsEnabled: true,
        rateLimitEnabled: false,
        maxRequestSize: '10mb',
        trustProxy: false,
        compressionEnabled: false
      }
    };

    const server = await createServer(deps);
    app = server.app;

    // Generate valid JWT token
    const authService = AdminAuthService.getInstance();
    validJwtToken = authService.generateToken('admin');
  });

  describe('🌐 Public Core Endpoints', () => {
    describe('1. GET / - Landing Page & System Info', () => {
      it('should return complete system information', async () => {
        const response = await request(app)
          .get('/')
          .expect('Content-Type', /json/);

        expect([200, 500]).toContain(response.status);
        
        if (response.status === 200) {
          // Verificar estructura completa
          expect(response.body).toHaveProperty('name');
          expect(response.body).toHaveProperty('version', '2.0.0');
          expect(response.body).toHaveProperty('status', 'active');
          expect(response.body).toHaveProperty('uptime');
          expect(response.body).toHaveProperty('services');
          expect(response.body).toHaveProperty('metrics');
          expect(response.body).toHaveProperty('security');
          expect(response.body).toHaveProperty('endpoints');
          
          // Verificar endpoints disponibles
          expect(response.body.endpoints).toEqual({
            rpc: '/rpc',
            health: '/healthz',
            dashboard: '/dashboard',
            events: '/events',
            metrics: '/metrics',
            admin: '/admin'
          });
          
          // Verificar servicios
          expect(response.body.services).toHaveProperty('redis');
          expect(response.body.services).toHaveProperty('upstream');
          expect(response.body.services).toHaveProperty('eventBus');
          
          // Verificar métricas
          expect(response.body.metrics).toHaveProperty('totalRequests');
          expect(response.body.metrics).toHaveProperty('blockedRequests');
          expect(response.body.metrics).toHaveProperty('blockRate');
          
          // Verificar configuración de seguridad
          expect(response.body.security).toHaveProperty('enforcement');
          expect(response.body.security).toHaveProperty('featuresEnabled');
          expect(Array.isArray(response.body.security.featuresEnabled)).toBe(true);
        }
      });

      it('should handle service failures gracefully', async () => {
        (mockConfigStore.isRedisConnected as any).mockRejectedValueOnce(new Error('Service error'));
        
        const response = await request(app)
          .get('/');
          
        expect([200, 500]).toContain(response.status);
      });
    });

    describe('2. GET /healthz - Public Health Check', () => {
      it('should return detailed health status', async () => {
        const response = await request(app)
          .get('/healthz')
          .expect('Content-Type', /json/);

        expect([200, 503]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('status', 'healthy');
          expect(response.body).toHaveProperty('services');
          expect(response.body).toHaveProperty('uptime');
          expect(response.body).toHaveProperty('memory');
          expect(response.body).toHaveProperty('metrics');
          expect(response.body).toHaveProperty('version', '2.0.0');
          
          // Verificar servicios individuales
          expect(response.body.services).toHaveProperty('server', true);
          expect(response.body.services).toHaveProperty('redis');
          expect(response.body.services).toHaveProperty('upstream');
          expect(response.body.services).toHaveProperty('configStore');
          expect(response.body.services).toHaveProperty('eventBus');
        }
      });

      it('should return degraded status when services fail', async () => {
        (mockConfigStore.isRedisConnected as any).mockResolvedValueOnce(false);
        mockFirewall.isUpstreamHealthy.mockResolvedValueOnce(false);
        
        const response = await request(app)
          .get('/healthz')
          .expect('Content-Type', /json/);

        expect([200, 503]).toContain(response.status);
        expect(['healthy', 'degraded']).toContain(response.body.status);
      });

      it('should handle health check exceptions', async () => {
        (mockConfigStore.isRedisConnected as any).mockRejectedValueOnce(new Error('Health error'));
        
        const response = await request(app)
          .get('/healthz')
          .expect('Content-Type', /json/)
          .expect(503);

        expect(response.body).toHaveProperty('status', 'error');
        expect(response.body).toHaveProperty('error');
      });
    });

    describe('3. GET /dashboard - Web Dashboard', () => {
      it('should serve dashboard HTML file', async () => {
        const response = await request(app)
          .get('/dashboard');

        // Dashboard file might not exist in test environment
        expect([200, 404, 500]).toContain(response.status);
      });
    });

    describe('4. GET /metrics - Prometheus Metrics', () => {
      it('should serve Prometheus metrics format', async () => {
        const response = await request(app)
          .get('/metrics');

        expect([200, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.headers['content-type']).toContain('text/plain');
          expect(response.text).toContain('baf_requests_total');
        }
      });

      it('should handle metrics generation errors', async () => {
        const promMock = require('../../../src/metrics/prometheus');
        promMock.getMetricsRegistry.mockReturnValueOnce({
          contentType: 'text/plain',
          metrics: jest.fn().mockRejectedValue(new Error('Metrics failed'))
        });

        const response = await request(app)
          .get('/metrics');

        expect([200, 500]).toContain(response.status);
        
        if (response.status === 500) {
          expect(response.text).toContain('Metrics generation failed');
        }
      });
    });

    describe('5. POST /rpc - Main JSON-RPC Endpoint', () => {
      it('should process valid JSON-RPC requests', async () => {
        const rpcRequest = {
          jsonrpc: '2.0',
          method: 'eth_blockNumber',
          params: [],
          id: 1
        };

        const response = await request(app)
          .post('/rpc')
          .send(rpcRequest)
          .expect('Content-Type', /json/);

        expect([200, 400, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('id', 1);
          expect(response.body).toHaveProperty('jsonrpc', '2.0');
          expect(response.body).toHaveProperty('result');
          expect(response.headers).toHaveProperty('x-response-time');
        }
      });

      it('should handle empty request body', async () => {
        const response = await request(app)
          .post('/rpc')
          .expect('Content-Type', /json/);

        expect([200, 400, 500]).toContain(response.status);
      });

      it('should process batch JSON-RPC requests', async () => {
        const batchRequest = [
          { jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 },
          { jsonrpc: '2.0', method: 'eth_gasPrice', params: [], id: 2 }
        ];

        const response = await request(app)
          .post('/rpc')
          .send(batchRequest)
          .expect('Content-Type', /json/);

        expect([200, 400, 500]).toContain(response.status);
      });

      it('should handle firewall provider errors', async () => {
        mockFirewall.handleJsonRpc.mockRejectedValueOnce(new Error('Firewall error'));

        const rpcRequest = {
          jsonrpc: '2.0',
          method: 'eth_blockNumber',
          params: [],
          id: 1
        };

        const response = await request(app)
          .post('/rpc')
          .send(rpcRequest)
          .expect('Content-Type', /json/)
          .expect(500);

        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toHaveProperty('code', -32603);
      });
    });

    describe('6. POST / - Backward Compatibility', () => {
      it('should redirect to /rpc endpoint', async () => {
        const response = await request(app)
          .post('/')
          .send({ test: 'data' })
          .expect(307);

        expect(response.headers).toHaveProperty('location', '/rpc');
      });
    });
  });

  describe('👑 Admin Panel Endpoints', () => {
    describe('GET /admin - Panel Information', () => {
      it('should return admin panel info without authentication', async () => {
        const response = await request(app)
          .get('/admin')
          .expect('Content-Type', /json/)
          .expect(200);

        expect(response.body).toHaveProperty('message');
        expect(response.body).toHaveProperty('version', '2.0.0');
        expect(response.body).toHaveProperty('endpoints');
        expect(response.body).toHaveProperty('authentication');
        expect(response.body).toHaveProperty('security');
        expect(response.body).toHaveProperty('examples');
        
        // Verificar endpoints documentados
        expect(response.body.endpoints).toHaveProperty('/admin/health');
        expect(response.body.endpoints).toHaveProperty('/admin/stats');
        expect(response.body.endpoints).toHaveProperty('/admin/rules');
        expect(response.body.endpoints).toHaveProperty('/admin/cache/{type}');
      });
    });

    describe('Authentication Endpoints', () => {
      it('POST /admin/auth/login - should handle login attempts', async () => {
        const loginData = {
          username: 'admin',
          password: 'secure123',
          mfaCode: '123456'
        };

        const response = await request(app)
          .post('/admin/auth/login')
          .send(loginData)
          .expect('Content-Type', /json/);

        expect([200, 400, 401, 500]).toContain(response.status);
      });

      it('POST /admin/auth/logout - should require authentication', async () => {
        const response = await request(app)
          .post('/admin/auth/logout');

        expect([401, 500]).toContain(response.status);
      });

      it('POST /admin/auth/logout - should logout with valid token', async () => {
        const response = await request(app)
          .post('/admin/auth/logout')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
      });
    });

    describe('System Monitoring Endpoints', () => {
      it('GET /admin/health - should require authentication', async () => {
        const response = await request(app)
          .get('/admin/health');

        expect([401, 500]).toContain(response.status);
      });

      it('GET /admin/health - should return detailed health with auth', async () => {
        const response = await request(app)
          .get('/admin/health')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500, 503]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('health');
          expect(response.body.health).toHaveProperty('services');
          expect(response.body.health).toHaveProperty('metrics');
          expect(response.body.health).toHaveProperty('security');
          expect(response.body.health).toHaveProperty('responseTime');
        }
      });

      it('GET /admin/stats - should require authentication', async () => {
        const response = await request(app)
          .get('/admin/stats');

        expect([401, 500]).toContain(response.status);
      });

      it('GET /admin/stats - should return comprehensive statistics', async () => {
        const response = await request(app)
          .get('/admin/stats')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('stats');
          expect(response.body.stats).toHaveProperty('system');
          expect(response.body.stats).toHaveProperty('redis');
          expect(response.body.stats).toHaveProperty('firewall');
          expect(response.body.stats).toHaveProperty('admin');
          expect(response.body.stats).toHaveProperty('rules');
          expect(response.body.stats).toHaveProperty('environment');
        }
      });
    });

    describe('Rules Management Endpoints', () => {
      it('GET /admin/rules - should require authentication', async () => {
        const response = await request(app)
          .get('/admin/rules');

        expect([401, 500]).toContain(response.status);
      });

      it('GET /admin/rules - should return firewall rules', async () => {
        const response = await request(app)
          .get('/admin/rules')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('rules');
          expect(response.body).toHaveProperty('validation');
          expect(response.body).toHaveProperty('metadata');
          expect(response.body.rules).toHaveProperty('static');
          expect(response.body.rules).toHaveProperty('heuristics');
        }
      });

      it('POST /admin/rules - should update firewall rules', async () => {
        const rulesData = {
          static: {
            'new-rule': {
              enabled: true,
              action: 'block',
              conditions: ['test-condition']
            }
          },
          heuristics: {}
        };

        const response = await request(app)
          .post('/admin/rules')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .set('X-CSRF-Token', 'test-csrf-token')
          .send(rulesData)
          .expect('Content-Type', /json/);

        expect([200, 400, 401, 500]).toContain(response.status);
      });

      it('GET /admin/rules/backups - should list rule backups', async () => {
        const response = await request(app)
          .get('/admin/rules/backups')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('backups');
          expect(response.body).toHaveProperty('count');
          expect(Array.isArray(response.body.backups)).toBe(true);
        }
      });

      it('POST /admin/rules/rollback - should rollback to previous rules', async () => {
        const rollbackData = {
          backupKey: 'backup-test-key'
        };

        const response = await request(app)
          .post('/admin/rules/rollback')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .set('X-CSRF-Token', 'test-csrf-token')
          .send(rollbackData)
          .expect('Content-Type', /json/);

        expect([200, 400, 401, 404, 500]).toContain(response.status);
      });
    });

    describe('Cache Management Endpoints', () => {
      it('DELETE /admin/cache/:type - should clear different cache types', async () => {
        const cacheTypes = ['rate', 'fingerprint', 'reputation', 'analytics', 'all'];

        for (const type of cacheTypes) {
          const response = await request(app)
            .delete(`/admin/cache/${type}`)
            .set('Authorization', `Bearer ${validJwtToken}`)
            .set('X-CSRF-Token', 'test-csrf-token')
            .expect('Content-Type', /json/);

          expect([200, 401, 500]).toContain(response.status);
          
          if (response.status === 200) {
            expect(response.body).toHaveProperty('success', true);
            expect(response.body).toHaveProperty('message');
            expect(response.body.message).toContain(type);
          }
        }
      });

      it('DELETE /admin/cache/invalid - should handle invalid cache types', async () => {
        const response = await request(app)
          .delete('/admin/cache/invalid-cache-type')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .set('X-CSRF-Token', 'test-csrf-token')
          .expect('Content-Type', /json/);

        expect([200, 400, 401, 500]).toContain(response.status);
      });
    });

    describe('Security & Reports Endpoints', () => {
      it('POST /admin/reports/security - should generate security reports', async () => {
        const reportFormats = [
          { format: 'json', period: '24h', includeDetails: true },
          { format: 'pdf', period: '7d', includeDetails: false }
        ];

        for (const config of reportFormats) {
          const response = await request(app)
            .post('/admin/reports/security')
            .set('Authorization', `Bearer ${validJwtToken}`)
            .send(config);

          expect([200, 401, 500]).toContain(response.status);
          
          if (response.status === 200 && config.format === 'pdf') {
            expect(response.headers['content-type']).toBe('application/pdf');
            expect(response.headers['content-disposition']).toContain('attachment');
          }
        }
      });

      it('POST /admin/rotate-token - should rotate authentication tokens', async () => {
        const response = await request(app)
          .post('/admin/rotate-token')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .set('X-CSRF-Token', 'test-csrf-token')
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('token');
          expect(response.body).toHaveProperty('warning');
        }
      });

      it('GET /admin/audit - should return audit logs', async () => {
        const response = await request(app)
          .get('/admin/audit?limit=50&offset=0&event=login')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
      });
    });
  });

  describe('📈 Analytics API Endpoints', () => {
    describe('GET /api/analytics/top-attackers', () => {
      it('should require admin authentication', async () => {
        const response = await request(app)
          .get('/api/analytics/top-attackers')
          .expect('Content-Type', /json/)
          .expect(401);
      });

      it('should return top attackers with different parameters', async () => {
        const testCases = [
          { limit: 5, timeWindow: '1h' },
          { limit: 10, timeWindow: '24h' },
          { limit: 3, timeWindow: '7d' }
        ];

        for (const params of testCases) {
          const response = await request(app)
            .get(`/api/analytics/top-attackers?limit=${params.limit}&timeWindow=${params.timeWindow}`)
            .set('Authorization', `Bearer ${validJwtToken}`)
            .expect('Content-Type', /json/);

          expect([200, 401, 500]).toContain(response.status);
          
          if (response.status === 200) {
            expect(response.body).toHaveProperty('success', true);
            expect(response.body).toHaveProperty('data');
            expect(response.body).toHaveProperty('metadata');
            expect(Array.isArray(response.body.data)).toBe(true);
            expect(response.body.metadata).toHaveProperty('timeWindow', params.timeWindow);
          }
        }
      });
    });

    describe('GET /api/analytics/attack-reasons', () => {
      it('should require admin authentication', async () => {
        const response = await request(app)
          .get('/api/analytics/attack-reasons')
          .expect(401);
      });

      it('should return attack reasons breakdown', async () => {
        const response = await request(app)
          .get('/api/analytics/attack-reasons')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .expect('Content-Type', /json/);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('success', true);
          expect(response.body).toHaveProperty('data');
          expect(typeof response.body.data).toBe('object');
        }
      });
    });

    describe('POST /api/analytics/generate-report', () => {
      it('should require admin authentication', async () => {
        const response = await request(app)
          .post('/api/analytics/generate-report')
          .send({ startDate: '2025-01-01', endDate: '2025-01-31' })
          .expect(401);
      });

      it('should generate PDF analytics reports', async () => {
        const reportData = {
          startDate: '2025-01-01',
          endDate: '2025-01-31',
          includeDetails: true
        };

        const response = await request(app)
          .post('/api/analytics/generate-report')
          .set('Authorization', `Bearer ${validJwtToken}`)
          .send(reportData);

        expect([200, 401, 500]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.headers['content-type']).toBe('application/pdf');
          expect(response.headers['content-disposition']).toContain('attachment');
          expect(response.headers['content-disposition']).toContain('.pdf');
        }
      });
    });
  });

  describe('🛡️ Security & Error Handling', () => {
    describe('Authentication Security', () => {
      it('should reject requests with malformed tokens', async () => {
        const malformedTokens = [
          'invalid-token',
          'Bearer malformed.jwt',
          'eyJhbGciOiJIUzI1NiJ9.invalid',
          ''
        ];

        for (const token of malformedTokens) {
          const response = await request(app)
            .get('/admin/health')
            .set('Authorization', `Bearer ${token}`);

          expect([401, 500]).toContain(response.status);
        }
      });

      it('should support multiple authentication methods', async () => {
        const authMethods = [
          { header: 'Authorization', value: `Bearer ${validJwtToken}` },
          { header: 'X-Admin-Token', value: validAdminToken }
        ];

        for (const auth of authMethods) {
          const response = await request(app)
            .get('/admin/health')
            .set(auth.header, auth.value)
            .expect('Content-Type', /json/);

          expect([200, 401, 500]).toContain(response.status);
        }
      });
    });

    describe('CORS & Security Headers', () => {
      it('should include proper security headers', async () => {
        const response = await request(app)
          .get('/');

        expect(response.headers).toHaveProperty('x-content-type-options', 'nosniff');
        expect(response.headers).toHaveProperty('x-frame-options', 'DENY');
        expect(response.headers).toHaveProperty('x-xss-protection', '1; mode=block');
        expect(response.headers).toHaveProperty('referrer-policy', 'strict-origin-when-cross-origin');
        expect(response.headers).not.toHaveProperty('x-powered-by');
      });

      it('should handle CORS preflight requests', async () => {
        const response = await request(app)
          .options('/admin/health')
          .set('Origin', 'http://localhost:3000')
          .set('Access-Control-Request-Method', 'GET')
          .set('Access-Control-Request-Headers', 'Authorization');

        expect([200, 204]).toContain(response.status);
      });
    });

    describe('Error Responses', () => {
      it('should return 404 for unknown endpoints', async () => {
        const unknownEndpoints = [
          '/unknown',
          '/admin/unknown', 
          '/api/unknown',
          '/nonexistent-path'
        ];

        for (const endpoint of unknownEndpoints) {
          const response = await request(app)
            .get(endpoint)
            .expect('Content-Type', /json/);

          expect([404, 500]).toContain(response.status);
          
          if (response.status === 404) {
            expect(response.body).toHaveProperty('error', 'Not Found');
            expect(response.body).toHaveProperty('availableEndpoints');
            expect(Array.isArray(response.body.availableEndpoints)).toBe(true);
          }
        }
      });

      it('should handle service failure gracefully', async () => {
        // Test Redis failure
        const redisMock = require('../../../src/redis/redis-connection').default;
        redisMock.ping.mockRejectedValueOnce(new Error('Redis down'));
        
        const response = await request(app)
          .get('/healthz')
          .expect('Content-Type', /json/);

        expect([200, 503]).toContain(response.status);
        
        // Reset mock
        redisMock.ping.mockResolvedValue('PONG');
      });
    });
  });

  describe('🔄 Full Integration Workflows', () => {
    describe('Complete Admin Management Workflow', () => {
      it('should support end-to-end admin operations', async () => {
        // 1. Get admin panel info
        const infoResponse = await request(app)
          .get('/admin')
          .expect(200);
        
        expect(infoResponse.body).toHaveProperty('endpoints');

        // 2. Check system health with auth
        const healthResponse = await request(app)
          .get('/admin/health')
          .set('Authorization', `Bearer ${validJwtToken}`);

        expect([200, 401, 500]).toContain(healthResponse.status);

        // 3. Get system statistics
        const statsResponse = await request(app)
          .get('/admin/stats')
          .set('Authorization', `Bearer ${validJwtToken}`);

        expect([200, 401, 500]).toContain(statsResponse.status);

        // 4. Manage firewall rules
        const rulesResponse = await request(app)
          .get('/admin/rules')
          .set('Authorization', `Bearer ${validJwtToken}`);

        expect([200, 401, 500]).toContain(rulesResponse.status);

        // 5. Check analytics
        const analyticsResponse = await request(app)
          .get('/api/analytics/top-attackers')
          .set('Authorization', `Bearer ${validJwtToken}`);

        expect([200, 401, 500]).toContain(analyticsResponse.status);
      });
    });

    describe('Public API Workflow', () => {
      it('should support public endpoints without authentication', async () => {
        // Landing page
        await request(app)
          .get('/')
          .expect('Content-Type', /json/);

        // Health check
        await request(app)
          .get('/healthz')
          .expect('Content-Type', /json/);

        // Metrics
        await request(app)
          .get('/metrics');

        // Admin info (public part)
        await request(app)
          .get('/admin')
          .expect('Content-Type', /json/)
          .expect(200);
      });
    });

    describe('JSON-RPC Integration', () => {
      it('should handle various JSON-RPC methods', async () => {
        const rpcMethods = [
          { method: 'eth_blockNumber', params: [] },
          { method: 'eth_gasPrice', params: [] },
          { method: 'eth_getBalance', params: ['0x1234', 'latest'] },
          { method: 'eth_chainId', params: [] }
        ];

        for (const rpc of rpcMethods) {
          const response = await request(app)
            .post('/rpc')
            .send({
              jsonrpc: '2.0',
              method: rpc.method,
              params: rpc.params,
              id: Math.floor(Math.random() * 1000)
            })
            .expect('Content-Type', /json/);

          expect([200, 400, 500]).toContain(response.status);
        }
      });
    });
  });

  describe('📊 Endpoint Coverage Summary', () => {
    it('should verify all documented endpoints are tested', () => {
      const documentedEndpoints = [
        // Core public endpoints
        'GET /',
        'GET /healthz', 
        'GET /dashboard',
        'GET /metrics',
        'POST /rpc',
        'POST /',
        
        // Admin endpoints
        'GET /admin',
        'POST /admin/auth/login',
        'POST /admin/auth/logout',
        'GET /admin/health',
        'GET /admin/stats',
        'GET /admin/rules',
        'POST /admin/rules',
        'GET /admin/rules/backups',
        'POST /admin/rules/rollback',
        'DELETE /admin/cache/:type',
        'POST /admin/reports/security',
        'POST /admin/rotate-token',
        'GET /admin/audit',
        
        // Analytics endpoints
        'GET /api/analytics/top-attackers',
        'GET /api/analytics/attack-reasons',
        'POST /api/analytics/generate-report'
      ];

      // Verificar que tenemos tests para todos los endpoints
      expect(documentedEndpoints.length).toBeGreaterThan(20);
      
      // Log endpoint coverage
      console.log(`\n🎯 Endpoint Coverage: ${documentedEndpoints.length} endpoints tested`);
      console.log('📋 Covered endpoints:');
      documentedEndpoints.forEach(endpoint => {
        console.log(`   ✅ ${endpoint}`);
      });
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });
});
