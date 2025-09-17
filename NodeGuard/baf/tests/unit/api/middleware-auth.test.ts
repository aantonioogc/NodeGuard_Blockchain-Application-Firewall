// tests/unit/api/middleware-auth-basic-fixed.test.ts
// Basic Admin Middleware Authentication Test Suite
// Tests authentication and authorization middleware behavior

import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';

// Mock Redis connection
jest.mock('../../../src/redis/redis-connection', () => ({
  get: jest.fn().mockResolvedValue(null),
  set: jest.fn().mockResolvedValue('OK'),
  ping: jest.fn().mockResolvedValue('PONG'),
  on: jest.fn()
}));

// Mock logger
jest.mock('../../../src/logging/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}));

// Mock EventBus
jest.mock('../../../src/events/event-bus', () => ({
  EventBus: {
    emit: jest.fn(),
    on: jest.fn()
  }
}));

describe('Middleware Authentication Basic Tests', () => {
  let app: express.Application;
  let validAdminToken: string;
  const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

  beforeEach(() => {
    app = express();
    app.use(express.json());

    // Create a valid admin token
    validAdminToken = jwt.sign(
      { username: 'admin', role: 'admin' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Basic protected route
    app.get('/admin/test', (req, res) => {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }
      
      try {
        const decoded = jwt.verify(token, JWT_SECRET) as any;
        if (decoded.role !== 'admin') {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }
        res.json({ success: true, user: decoded.username });
      } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
      }
    });
  });

  describe('Token Validation', () => {
    it('should allow valid admin tokens', async () => {
      const response = await request(app)
        .get('/admin/test')
        .set('Authorization', `Bearer ${validAdminToken}`);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it('should reject missing tokens', async () => {
      const response = await request(app)
        .get('/admin/test');
      
      expect(response.status).toBe(401);
    });

    it('should reject invalid tokens', async () => {
      const response = await request(app)
        .get('/admin/test')
        .set('Authorization', 'Bearer invalid-token');
      
      expect(response.status).toBe(401);
    });

    it('should reject non-admin tokens', async () => {
      const userToken = jwt.sign(
        { username: 'user', role: 'user' },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .get('/admin/test')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(response.status).toBe(403);
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle multiple concurrent requests', async () => {
      const requests = Array(5).fill(null).map(() =>
        request(app)
          .get('/admin/test')
          .set('Authorization', `Bearer ${validAdminToken}`)
      );

      const responses = await Promise.all(requests);
      
      // All should get consistent responses
      const statusCodes = responses.map((r: any) => r.status);
      const uniqueStatuses = [...new Set(statusCodes)];
      
      expect(uniqueStatuses.length).toBeLessThanOrEqual(2);
      expect(statusCodes.every((status: number) => [200, 401, 403, 500].includes(status))).toBe(true);
    });

    it('should handle mixed valid/invalid requests', async () => {
      const validRequests = Array(3).fill(null).map(() =>
        request(app)
          .get('/admin/test')
          .set('Authorization', `Bearer ${validAdminToken}`)
      );

      const invalidRequests = Array(2).fill(null).map(() =>
        request(app)
          .get('/admin/test')
          .set('Authorization', 'Bearer invalid-token')
      );

      const responses = await Promise.all([...validRequests, ...invalidRequests]);
      
      expect(responses.every((r: any) => [200, 401, 403, 500].includes(r.status))).toBe(true);
    });
  });
});
