// tests/setup.js
// Setup global para tests

// Configurar variables de entorno para tests
process.env.NODE_ENV = 'test';
process.env.BAF_CONSOLE_LOGS = 'false';
process.env.BAF_URL = 'http://localhost:3000';
process.env.ETH_RPC_URL = 'http://localhost:8545';

// Configurar timeout global
jest.setTimeout(300000);
