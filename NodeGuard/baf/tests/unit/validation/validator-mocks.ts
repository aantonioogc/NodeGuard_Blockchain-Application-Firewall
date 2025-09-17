// tests/unit/validation/validator-mocks.ts
// Mock implementations for validation components

import { jest } from '@jest/globals';

export const createUnifiedValidatorMock = () => {
  const metrics = {
    totalValidations: 42,
    successfulValidations: 40,
    failedValidations: 2,
    averageValidationTime: 1.5,
    requestsPerSecond: 100,
    memoryUsage: {
      heapUsed: 50 * 1024 * 1024,
      heapTotal: 100 * 1024 * 1024,
      external: 10 * 1024 * 1024,
      rss: 80 * 1024 * 1024
    }
  };

  const eventHandlers = new Map();

  return {
    validateJsonRpc: jest.fn((request: any, context?: any) => {
      // Mock basic JSON-RPC validation
      if (!request || typeof request !== 'object') {
        return {
          success: false,
          errors: [{ code: 'INVALID_REQUEST_STRUCTURE', message: 'Invalid request structure' }]
        };
      }

      // Check for invalid structure first (like { invalid: 'structure' })
      if (!request.jsonrpc && !request.method && request.invalid) {
        return {
          success: false,
          errors: [{ code: 'JSON_RPC_INVALID_STRUCTURE', message: 'Invalid JSON-RPC structure' }]
        };
      }

      if (!request.jsonrpc || request.jsonrpc !== '2.0') {
        return {
          success: false,
          errors: [{ code: 'INVALID_JSONRPC_VERSION', message: 'Invalid JSON-RPC version' }]
        };
      }

      if (!request.method || typeof request.method !== 'string') {
        return {
          success: false,
          errors: [{ code: 'MISSING_METHOD', message: 'Missing or invalid method' }]
        };
      }

      // Check for blocked methods
      const blockedMethods = ['admin_peers', 'debug_traceTransaction', 'miner_start'];
      if (blockedMethods.includes(request.method)) {
        return {
          success: false,
          errors: [{ code: 'METHOD_BLOCKED', message: `Method ${request.method} is blocked` }]
        };
      }

      // Check parameter limits
      if (request.params && Array.isArray(request.params) && request.params.length > 10) {
        return {
          success: false,
          errors: [{ code: 'TOO_MANY_PARAMETERS', message: 'Too many parameters' }]
        };
      }

      return {
        success: true,
        data: request
      };
    }),

    validateTransaction: jest.fn((transaction: any, context?: any) => {
      if (!transaction || typeof transaction !== 'object') {
        return {
          success: false,
          errors: [{ code: 'INVALID_TRANSACTION_STRUCTURE', message: 'Invalid transaction structure' }]
        };
      }

      // Check for valid transaction type
      if (!transaction.type || !['0x0', '0x1', '0x2'].includes(transaction.type)) {
        return {
          success: false,
          errors: [{ code: 'INVALID_TRANSACTION_TYPE', message: 'Invalid transaction type' }]
        };
      }

      // Legacy transaction validation
      if (transaction.type === '0x0' && !transaction.gasPrice) {
        return {
          success: false,
          errors: [{ code: 'MISSING_GAS_PRICE', message: 'Legacy transaction missing gasPrice' }]
        };
      }

      // EIP-1559 transaction validation
      if (transaction.type === '0x2') {
        if (!transaction.maxFeePerGas || !transaction.maxPriorityFeePerGas) {
          return {
            success: false,
            errors: [{ code: 'MISSING_EIP1559_FIELDS', message: 'EIP-1559 transaction missing fee fields' }]
          };
        }
      }

      // Check for invalid gas price (too high or malformed)
      if (transaction.gasPrice === '0x999999999999999999999' || transaction.gasPrice === 'invalid_gas_price') {
        return {
          success: false,
          errors: [{ code: 'INVALID_GAS_PRICE', message: 'Gas price too high or malformed' }]
        };
      }

      return {
        success: true,
        data: transaction
      };
    }),

    validateBatch: jest.fn((batch: any, context?: any) => {
      if (!Array.isArray(batch)) {
        return {
          success: false,
          errors: [{ code: 'INVALID_BATCH_STRUCTURE', message: 'Batch must be an array' }]
        };
      }

      if (batch.length === 0) {
        return {
          success: false,
          errors: [{ code: 'EMPTY_BATCH', message: 'Batch cannot be empty' }]
        };
      }

      if (batch.length > 100) {
        return {
          success: false,
          errors: [{ code: 'BATCH_TOO_LARGE', message: 'Batch size exceeds maximum limit' }]
        };
      }

      // Check if any request in batch is invalid
      const hasInvalid = batch.some(req => 
        !req || typeof req !== 'object' || !req.jsonrpc || !req.method
      );

      if (hasInvalid) {
        return {
          success: false,
          errors: [{ code: 'INVALID_BATCH_REQUEST', message: 'Invalid request in batch' }]
        };
      }

      return {
        success: true,
        data: batch
      };
    }),

    validateRules: jest.fn((rules: any) => {
      if (!rules || typeof rules !== 'object') {
        return {
          success: false,
          errors: [{ code: 'INVALID_RULES_STRUCTURE', message: 'Invalid rules structure' }]
        };
      }

      // Check for invalid enforcement mode first (specific case)
      if (rules.enforcement && rules.enforcement.mode === 'invalid_mode') {
        return {
          success: false,
          errors: [{ code: 'INVALID_ENFORCEMENT_MODE', message: 'Invalid enforcement mode' }]
        };
      }

      // Then check for missing required fields
      if (!rules.version && !rules.rules && !rules.meta) {
        return {
          success: false,
          errors: [{ code: 'MISSING_REQUIRED_RULES_FIELDS', message: 'Missing required rules fields' }]
        };
      }

      // Check for valid enforcement modes
      if (rules.rules && rules.rules.enforcement && 
          !['strict', 'permissive', 'learning'].includes(rules.rules.enforcement.mode)) {
        return {
          success: false,
          errors: [{ code: 'INVALID_ENFORCEMENT_MODE', message: 'Invalid enforcement mode' }]
        };
      }

      return {
        success: true,
        data: rules
      };
    }),

    getMetrics: jest.fn(() => metrics),

    isHealthy: jest.fn(() => true),

    on: jest.fn((event: string, callback: Function) => {
      if (!eventHandlers.has(event)) {
        eventHandlers.set(event, []);
      }
      eventHandlers.get(event).push(callback);
    }),

    emit: jest.fn((event: string, data?: any) => {
      const handlers = eventHandlers.get(event) || [];
      handlers.forEach((handler: Function) => handler(data));
    }),

    // Additional helper methods
    reset: jest.fn(() => {
      // Reset metrics
      Object.assign(metrics, {
        totalValidations: 0,
        successfulValidations: 0,
        failedValidations: 0,
        averageValidationTime: 0,
        requestsPerSecond: 0
      });
      eventHandlers.clear();
    })
  };
};

export const createValidationMocks = () => ({
  jsonRpcValidator: {
    validate: jest.fn(),
    getMetrics: jest.fn()
  },
  transactionValidator: {
    validate: jest.fn(),
    getMetrics: jest.fn()
  }
});
