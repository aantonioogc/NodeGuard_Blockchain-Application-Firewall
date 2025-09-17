// tests/jest.config.js
// Configuración Jest simplificada para NodeGuard BAF

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  
  // Directorios de testing
  roots: [
    '<rootDir>/unit',
    '<rootDir>/threat-scenarios',
    '<rootDir>/system',
  ],

  // Patrones de archivos de test
  testMatch: [
    '**/*.test.ts',
    '**/*.test.js'
  ],

  // Configuración TypeScript y JavaScript
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
    '^.+\\.jsx?$': 'babel-jest'
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  
  // Resolver paths relativos al src principal
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/../src/$1'
  },

  // Setup básico
  setupFiles: ['<rootDir>/jest-setup.js'],
  setupFilesAfterEnv: ['<rootDir>/setup.js'],
  
  // Timeout para tests
  testTimeout: 300000,
  
  // Configuración básica
  verbose: true,
  testPathIgnorePatterns: ['/node_modules/'],
  maxWorkers: 1,
  forceExit: true
};
