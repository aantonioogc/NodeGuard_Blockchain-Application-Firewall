// tests/unit/setup.ts
// Test utilities and setup helpers

export const generateTestData = () => ({
  validTransactions: [
    // Legacy transaction
    {
      type: '0x0', // Legacy
      nonce: '0x1',
      gasPrice: '0x3b9aca00',
      gasLimit: '0x5208',
      to: '0x742d35Cc6634C0532925a3b8D0C8f8b4fdE77d',
      value: '0x0',
      data: '0x'
    },
    // EIP-1559 transaction
    {
      type: '0x2', // EIP-1559
      nonce: '0x1',
      maxFeePerGas: '0x77359400',
      maxPriorityFeePerGas: '0x77359400',
      gasLimit: '0x5208',
      to: '0x742d35Cc6634C0532925a3b8D0C8f8b4fdE77d',
      value: '0x0',
      data: '0x',
      chainId: '0x1'
    }
  ],
  invalidTransactions: [
    null,
    { invalid: 'transaction' },
    { type: '0x99' } // Unknown type
  ],
  validJsonRpcRequests: [
    {
      jsonrpc: '2.0',
      method: 'eth_blockNumber',
      params: [],
      id: 1
    },
    {
      jsonrpc: '2.0',
      method: 'eth_getBalance',
      params: ['0x742d35Cc6634C0532925a3b8D0C8f8b4fdE77d', 'latest'],
      id: 2
    }
  ],
  invalidJsonRpcRequests: [
    null,
    { invalid: 'request' },
    { jsonrpc: '1.0', method: 'test' }, // Invalid version
    { jsonrpc: '2.0' } // Missing method
  ],
  
  // JSON-RPC request generator
  jsonRpcRequest: (method: string, params: any[] = [], options: any = {}) => ({
    jsonrpc: '2.0',
    method,
    params,
    id: options.id || 1,
    ...options
  }),
  
  // Legacy transaction generator
  legacyTransaction: (overrides: any = {}) => ({
    type: '0x0',
    nonce: '0x1',
    gasPrice: '0x3b9aca00',
    gasLimit: '0x5208',
    to: '0x742d35Cc6634C0532925a3b8D0C8f8b4fdE77d',
    value: '0x0',
    data: '0x',
    ...overrides
  }),
  
  // EIP-1559 transaction generator
  eip1559Transaction: (overrides: any = {}) => ({
    type: '0x2',
    nonce: '0x1',
    maxFeePerGas: '0x77359400',
    maxPriorityFeePerGas: '0x77359400',
    gasLimit: '0x5208',
    to: '0x742d35Cc6634C0532925a3b8D0C8f8b4fdE77d',
    value: '0x0',
    data: '0x',
    chainId: '0x1',
    ...overrides
  }),
  
  // Valid rules configuration generator
  validRulesConfig: () => ({
    version: '1.0.0',
    rules: {
      rateLimit: {
        enabled: true,
        requestsPerMinute: 100,
        burstSize: 10
      },
      blockList: {
        enabled: true,
        addresses: ['0x1234567890123456789012345678901234567890'],
        methods: ['admin_peers', 'debug_traceTransaction']
      },
      validation: {
        enabled: true,
        strictMode: false,
        maxParams: 10
      },
      security: {
        enabled: true,
        requireAuth: true,
        allowedOrigins: ['*']
      }
    },
    metadata: {
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: '1.0.0'
    }
  })
});

export const createMockRequest = (override: any = {}) => ({
  jsonrpc: '2.0',
  method: 'eth_getBalance',
  params: [],
  id: 1,
  ...override
});

export const createMockTransaction = (override: any = {}) => ({
  type: '0x0',
  nonce: '0x1',
  gasPrice: '0x9184e72a000',
  gasLimit: '0x5208',
  to: '0x742d35cc6669f39e98eaa4cb9c3e2c888c5c8c2d',
  value: '0x0',
  data: '0x',
  ...override
});
