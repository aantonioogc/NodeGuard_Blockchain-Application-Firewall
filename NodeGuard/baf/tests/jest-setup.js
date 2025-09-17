// jest-setup.js
// Configuración global para Jest tests - NodeGuard BAF

// Configurar entorno de testing
process.env.NODE_ENV = 'test';
process.env.BAF_TEST_MODE = 'mock';
process.env.BAF_OFFLINE_MODE = 'true';

// Configurar JWT secret para tests
process.env.JWT_SECRET = 'test-jwt-secret-key-for-unit-tests-only-not-production';

// Timeout para tests largos
jest.setTimeout(300000);

// Configurar nivel de logs
process.env.LOG_LEVEL = 'warn';

console.log('🧪 Jest setup completado - NodeGuard BAF Test Suite');
