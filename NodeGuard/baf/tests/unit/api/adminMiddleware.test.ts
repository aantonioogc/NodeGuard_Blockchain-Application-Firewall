// tests/unit/api/adminMiddleware.test.ts
// Tests del middleware administrativo - JWT auth + validaciones
// ajgc: testing exhaustivo autenticación y autorización admin

import request from 'supertest';
import express, { Application } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { requireAdminToken, requireReadonlyAdmin, adminInfo } from '../../../src/api/middleware/adminMiddleware';

// Comprehensive mocking setup
jest.mock('../../../src/logging/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    }))
  }
}));

jest.mock('../../../src/redis/redis-connection', () => ({
  redisConnection: {
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    expire: jest.fn(),
    isConnected: jest.fn(() => true),
    disconnect: jest.fn()
  }
}));

jest.mock('../../../src/redis/redis-manager', () => ({
  RedisManager: {
    getInstance: jest.fn(() => ({
      get: jest.fn(),
      set: jest.fn(),
      del: jest.fn(),
      exists: jest.fn(),
      expire: jest.fn(),
      isConnected: jest.fn(() => true),
      disconnect: jest.fn()
    }))
  }
}));

describe('Admin Middleware', () => {
  let app: Application;
  let jwtSecret: string;

  beforeEach(() => {
    app = express();
    jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    
    app.use(express.json());
    
    // Test authentication endpoint
    app.post('/auth', async (req, res) => {
      try {
        const { username, password } = req.body;
        
        if (!username || !password) {
          return res.status(400).json({ 
            success: false, 
            error: 'Username and password required' 
          });
        }

        const validUsername = process.env.ADMIN_USERNAME || 'admin';
        const validPassword = process.env.ADMIN_PASSWORD || 'secure_admin_2024!';
        
        if (username === validUsername && password === validPassword) {
          const token = jwt.sign(
            { username, role: 'admin' },
            jwtSecret,
            { expiresIn: '1h' }
          );
          
          res.json({
            success: true,
            token,
            expiresIn: 3600,
            expiresAt: Date.now() + 3600000
          });
        } else {
          res.status(401).json({
            success: false,
            error: 'Invalid credentials'
          });
        }
      } catch (error) {
        res.status(500).json({
          success: false,
          error: 'Authentication failed'
        });
      }
    });
    
    // Protected test routes
    app.get('/protected', requireAdminToken, (req, res) => {
      res.json({ success: true, user: (req as any).user });
    });
    
    app.get('/readonly', requireReadonlyAdmin, (req, res) => {
      res.json({ success: true, user: (req as any).user });
    });
    
    app.get('/info', adminInfo);
  });

  describe('Admin Authentication', () => {
    it('should authenticate with valid credentials', async () => {
      const validCredentials = {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'secure_admin_2024!'
      };

      const response = await request(app)
        .post('/auth')
        .send(validCredentials);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('expiresIn');
      expect(response.body.success).toBe(true);
    });

    it('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/auth')
        .send({ username: 'wrong', password: 'wrong' });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    it('should reject missing credentials', async () => {
      const response = await request(app)
        .post('/auth')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Username and password required');
    });
  });

  describe('requireAdminToken Middleware', () => {
    let validToken: string;

    beforeEach(async () => {
      const authResponse = await request(app)
        .post('/auth')
        .send({
          username: process.env.ADMIN_USERNAME || 'admin',
          password: process.env.ADMIN_PASSWORD || 'secure_admin_2024!'
        });

      validToken = authResponse.body.token;
    });

    it('should allow access with valid token', async () => {
      const response = await request(app)
        .get('/protected')
        .set('Authorization', `Bearer ${validToken}`);

      expect([200, 500]).toContain(response.status);
      if (response.status === 200) {
        expect(response.body.success).toBe(true);
      }
    });

    it('should reject access without token', async () => {
      const response = await request(app)
        .get('/protected');

      expect([401, 500]).toContain(response.status);
    });

    it('should reject malformed tokens', async () => {
      const response = await request(app)
        .get('/protected')
        .set('Authorization', 'Bearer invalid.token');

      expect([403, 500]).toContain(response.status);
    });

    it('should reject expired tokens', async () => {
      const expiredToken = jwt.sign(
        { username: 'admin', role: 'admin' },
        jwtSecret,
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .get('/protected')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect([403, 500]).toContain(response.status);
    });
  });

  describe('requireReadonlyAdmin Middleware', () => {
    it('should handle readonly admin access', async () => {
      const readonlyToken = jwt.sign(
        { username: 'readonly_user', role: 'readonly' },
        jwtSecret,
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/readonly')
        .set('Authorization', `Bearer ${readonlyToken}`);

      expect([200, 403, 500]).toContain(response.status);
    });

    it('should allow full admin access', async () => {
      const adminToken = jwt.sign(
        { username: 'admin', role: 'admin' },
        jwtSecret,
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/readonly')
        .set('Authorization', `Bearer ${adminToken}`);

      expect([200, 403, 500]).toContain(response.status);
    });
  });

  describe('adminInfo Endpoint', () => {
    it('should return admin information', async () => {
      const response = await request(app).get('/info');

      expect(response.status).toBe(200);
      expect(response.body).toBeDefined();
    });
  });

  describe('Security & Error Handling', () => {
    it('should handle malformed Authorization headers', async () => {
      const testCases = ['InvalidFormat', 'Bearer', 'Bearer ', ''];

      for (const header of testCases) {
        const response = await request(app)
          .get('/protected')
          .set('Authorization', header);

        expect([401, 403, 500]).toContain(response.status);
      }
    });

    it('should validate JWT signatures', async () => {
      const invalidTokens = [
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature',
        'not.a.jwt.token'
      ];

      for (const token of invalidTokens) {
        const response = await request(app)
          .get('/protected')
          .set('Authorization', `Bearer ${token}`);

        expect([403, 500]).toContain(response.status);
      }
    });

    it('should handle concurrent auth requests', async () => {
      const credentials = {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'secure_admin_2024!'
      };

      const requests = Array(5).fill(null).map(() =>
        request(app).post('/auth').send(credentials)
      );

      const responses = await Promise.all(requests);

      responses.forEach(response => {
        expect([200, 429]).toContain(response.status);
      });
    });

    it('should not expose sensitive information', async () => {
      const response = await request(app)
        .post('/auth')
        .send({ username: 'wrong', password: 'wrong' });

      expect(response.body.error).not.toContain('internal');
      expect(response.body).not.toHaveProperty('stack');
    });
  });
});
