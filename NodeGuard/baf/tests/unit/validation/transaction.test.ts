// unit/validation/transaction-basic.test.ts
/**
 * @test UNIT - Transaction Validation Basic Tests
 * @description Pruebas básicas de validación de transacciones Ethereum
 * @objective Verificar validación de transacciones EIP-2718, EIP-1559 y legacy
 * @execution Jest unit test runner
 * @guarantees Validación correcta de estructura y campos de transacciones
 * @benefits Testing rápido sin dependencias de blockchain real
 * @codeInvolvement Validación manual de transacciones
 * @realBlockchain No (unit test con validación local)
 * @complexity Basic to Intermediate
 */

// Tipos para transacciones
interface LegacyTransaction {
  nonce: number | string;
  gasPrice: string;
  gasLimit: number | string;
  to?: string;
  value: number | string;
  data?: string;
  v?: number;
  r?: string;
  s?: string;
  chainId?: number;
}

interface EIP1559Transaction {
  type: 2;
  chainId: number;
  nonce: number | string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  gasLimit: number | string;
  to?: string;
  value: number | string;
  data?: string;
  accessList?: Array<{ address: string; storageKeys: string[] }>;
  v?: number;
  r?: string;
  s?: string;
}

interface EIP2930Transaction {
  type: 1;
  chainId: number;
  nonce: number | string;
  gasPrice: string;
  gasLimit: number | string;
  to?: string;
  value: number | string;
  data?: string;
  accessList?: Array<{ address: string; storageKeys: string[] }>;
  v?: number;
  r?: string;
  s?: string;
}

type Transaction = LegacyTransaction | EIP1559Transaction | EIP2930Transaction;

interface ValidationResult<T = unknown> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
}

interface ValidationError {
  code: string;
  message: string;
  field?: string;
}

// Validador de transacciones básico
class SimpleTransactionValidator {
  private maxGasLimit = 15000000;
  private maxGasPriceWei = BigInt('100000000000'); // 100 Gwei
  private chainIds = [1, 3, 4, 5, 42, 1337]; // Mainnet, testnets, local

  validate(tx: unknown): ValidationResult<Transaction> {
    if (!tx || typeof tx !== 'object') {
      return {
        success: false,
        errors: [{
          code: 'INVALID_TRANSACTION_OBJECT',
          message: 'Transaction must be a valid object'
        }]
      };
    }

    const transaction = tx as any;

    // Detectar tipo de transacción
    if (transaction.type === 2) {
      return this.validateEIP1559(transaction);
    } else if (transaction.type === 1) {
      return this.validateEIP2930(transaction);
    } else if (transaction.type === 0 || transaction.type === undefined) {
      return this.validateLegacy(transaction);
    } else {
      return {
        success: false,
        errors: [{
          code: 'INVALID_TRANSACTION_TYPE',
          message: `Unsupported transaction type: ${transaction.type}`
        }]
      };
    }
  }

  private validateLegacy(tx: any): ValidationResult<LegacyTransaction> {
    const errors: ValidationError[] = [];

    // Validar campos específicos legacy primero
    if (!tx.gasPrice) {
      errors.push({ code: 'MISSING_GAS_PRICE', message: 'Gas price is required', field: 'gasPrice' });
    } else if (!this.isValidHex(tx.gasPrice)) {
      errors.push({ code: 'INVALID_GAS_PRICE_FORMAT', message: 'Gas price must be a valid hex string', field: 'gasPrice' });
    } else if (this.hexToBigInt(tx.gasPrice) > this.maxGasPriceWei) {
      errors.push({ code: 'GAS_PRICE_TOO_HIGH', message: 'Gas price exceeds maximum', field: 'gasPrice' });
    }

    // Validar firma EIP-155 si está presente
    if (tx.chainId && tx.v !== undefined) {
      if (!this.isValidEIP155Signature(tx.v, tx.chainId)) {
        errors.push({ code: 'INVALID_EIP155_SIGNATURE', message: 'Invalid EIP-155 signature', field: 'v' });
      }
    }

    // Validaciones comunes DESPUÉS
    const commonErrors = this.validateCommonFields(tx);
    errors.push(...commonErrors);

    if (errors.length > 0) {
      return { success: false, errors };
    }

    return { success: true, data: tx as LegacyTransaction };
  }

  private validateEIP1559(tx: any): ValidationResult<EIP1559Transaction> {
    const errors: ValidationError[] = [];

    // Validar campos específicos EIP-1559
    if (!tx.maxFeePerGas) {
      errors.push({ code: 'MISSING_MAX_FEE_PER_GAS', message: 'maxFeePerGas is required', field: 'maxFeePerGas' });
    } else if (!this.isValidHex(tx.maxFeePerGas)) {
      errors.push({ code: 'INVALID_MAX_FEE_FORMAT', message: 'maxFeePerGas must be a valid hex string', field: 'maxFeePerGas' });
    }

    if (!tx.maxPriorityFeePerGas) {
      errors.push({ code: 'MISSING_MAX_PRIORITY_FEE', message: 'maxPriorityFeePerGas is required', field: 'maxPriorityFeePerGas' });
    } else if (!this.isValidHex(tx.maxPriorityFeePerGas)) {
      errors.push({ code: 'INVALID_PRIORITY_FEE_FORMAT', message: 'maxPriorityFeePerGas must be a valid hex string', field: 'maxPriorityFeePerGas' });
    }

    // Validar que maxPriorityFeePerGas <= maxFeePerGas
    if (tx.maxFeePerGas && tx.maxPriorityFeePerGas) {
      const maxFee = this.hexToBigInt(tx.maxFeePerGas);
      const priorityFee = this.hexToBigInt(tx.maxPriorityFeePerGas);
      if (priorityFee > maxFee) {
        errors.push({ code: 'PRIORITY_FEE_TOO_HIGH', message: 'Priority fee cannot exceed max fee' });
      }
    }

    // Validar chainId
    if (!tx.chainId) {
      errors.push({ code: 'MISSING_CHAIN_ID', message: 'chainId is required for EIP-1559', field: 'chainId' });
    } else if (!this.chainIds.includes(tx.chainId)) {
      errors.push({ code: 'UNSUPPORTED_CHAIN_ID', message: 'Unsupported chain ID', field: 'chainId' });
    }

    // Validar access list si está presente
    if (tx.accessList && !this.isValidAccessList(tx.accessList)) {
      errors.push({ code: 'INVALID_ACCESS_LIST', message: 'Invalid access list format', field: 'accessList' });
    }

    // Validaciones comunes
    const commonErrors = this.validateCommonFields(tx);
    errors.push(...commonErrors);

    if (errors.length > 0) {
      return { success: false, errors };
    }

    return { success: true, data: tx as EIP1559Transaction };
  }

  private validateEIP2930(tx: any): ValidationResult<EIP2930Transaction> {
    const errors: ValidationError[] = [];

    // EIP-2930 es como legacy pero con access list
    if (!tx.gasPrice) {
      errors.push({ code: 'MISSING_GAS_PRICE', message: 'Gas price is required', field: 'gasPrice' });
    } else if (!this.isValidHex(tx.gasPrice)) {
      errors.push({ code: 'INVALID_GAS_PRICE_FORMAT', message: 'Gas price must be a valid hex string', field: 'gasPrice' });
    }

    if (!tx.chainId) {
      errors.push({ code: 'MISSING_CHAIN_ID', message: 'chainId is required for EIP-2930', field: 'chainId' });
    }

    if (tx.accessList && !this.isValidAccessList(tx.accessList)) {
      errors.push({ code: 'INVALID_ACCESS_LIST', message: 'Invalid access list format', field: 'accessList' });
    }

    const commonErrors = this.validateCommonFields(tx);
    errors.push(...commonErrors);

    if (errors.length > 0) {
      return { success: false, errors };
    }

    return { success: true, data: tx as EIP2930Transaction };
  }

  private validateCommonFields(tx: any): ValidationError[] {
    const errors: ValidationError[] = [];

    if (tx.nonce === undefined) {
      errors.push({ code: 'MISSING_NONCE', message: 'Nonce is required', field: 'nonce' });
    } else {
      const nonceValue = this.toNumber(tx.nonce);
      if (nonceValue < 0) {
        errors.push({ code: 'INVALID_NONCE', message: 'Nonce cannot be negative', field: 'nonce' });
      }
    }

    if (!tx.gasLimit && tx.gasLimit !== 0) {
      errors.push({ code: 'MISSING_GAS_LIMIT', message: 'Gas limit is required', field: 'gasLimit' });
    } else {
      const gasLimitValue = this.toNumber(tx.gasLimit);
      if (gasLimitValue > this.maxGasLimit) {
        errors.push({ code: 'GAS_LIMIT_TOO_HIGH', message: 'Gas limit exceeds maximum', field: 'gasLimit' });
      } else if (gasLimitValue < 21000) {
        errors.push({ code: 'GAS_LIMIT_TOO_LOW', message: 'Gas limit too low for basic transaction', field: 'gasLimit' });
      }
    }

    if (tx.value === undefined) {
      errors.push({ code: 'MISSING_VALUE', message: 'Value is required', field: 'value' });
    }

    if (tx.to && !this.isValidAddress(tx.to)) {
      errors.push({ code: 'INVALID_TO_ADDRESS', message: 'Invalid recipient address', field: 'to' });
    }

    if (tx.data && tx.data !== '0x' && !this.isValidHex(tx.data)) {
      errors.push({ code: 'INVALID_DATA_FORMAT', message: 'Data must be valid hex', field: 'data' });
    }

    return errors;
  }

  private isValidHex(value: string): boolean {
    return typeof value === 'string' && /^0x[0-9a-fA-F]*$/.test(value);
  }

  private isValidAddress(address: string): boolean {
    return /^0x[0-9a-fA-F]{40}$/.test(address);
  }

  private isValidAccessList(accessList: any[]): boolean {
    if (!Array.isArray(accessList)) return false;
    return accessList.every(item => 
      item.address && this.isValidAddress(item.address) &&
      Array.isArray(item.storageKeys) &&
      item.storageKeys.every((key: string) => this.isValidHex(key) && key.length === 66)
    );
  }

  private hexToBigInt(hex: string): bigint {
    return BigInt(hex);
  }

  private toNumber(value: string | number): number {
    return typeof value === 'string' && value.startsWith('0x') 
      ? parseInt(value, 16) 
      : typeof value === 'string' 
        ? parseInt(value, 10)
        : value;
  }

  private isValidEIP155Signature(v: number, chainId: number): boolean {
    // EIP-155: v = CHAIN_ID * 2 + 35 + {0, 1}
    return v === chainId * 2 + 35 || v === chainId * 2 + 36;
  }
}

// Helpers para generar transacciones de test
const createLegacyTransaction = (overrides: Partial<LegacyTransaction> = {}): LegacyTransaction => ({
  nonce: 42,
  gasPrice: '0x2540be400', // 10 Gwei
  gasLimit: 21000,
  to: '0x742d35cc6694c02c0cb6cc2c56b127b58e5c7d7d',
  value: 1000000000000000000, // 1 ETH
  data: '0x',
  ...overrides
});

const createEIP1559Transaction = (overrides: Partial<EIP1559Transaction> = {}): EIP1559Transaction => ({
  type: 2,
  chainId: 1,
  nonce: 42,
  maxFeePerGas: '0x2540be400', // 10 Gwei
  maxPriorityFeePerGas: '0x77359400', // 2 Gwei
  gasLimit: 21000,
  to: '0x742d35cc6694c02c0cb6cc2c56b127b58e5c7d7d',
  value: 1000000000000000000,
  data: '0x',
  accessList: [],
  ...overrides
});

const createEIP2930Transaction = (overrides: Partial<EIP2930Transaction> = {}): EIP2930Transaction => ({
  type: 1,
  chainId: 1,
  nonce: 42,
  gasPrice: '0x2540be400',
  gasLimit: 21000,
  to: '0x742d35cc6694c02c0cb6cc2c56b127b58e5c7d7d',
  value: 1000000000000000000,
  data: '0x',
  accessList: [],
  ...overrides
});

describe('Transaction Basic Validation', () => {
  let validator: SimpleTransactionValidator;

  beforeEach(() => {
    validator = new SimpleTransactionValidator();
  });

  describe('Legacy Transactions', () => {
    /**
     * @test Validación de transacción legacy válida
     */
    test('should validate valid legacy transaction', () => {
      const tx = createLegacyTransaction();
      const result = validator.validate(tx);

      expect(result.success).toBe(true);
      expect(result.data).toEqual(tx);
    });

    /**
     * @test Validación con firma EIP-155
     */
    test('should validate legacy transaction with EIP-155 signature', () => {
      const tx = createLegacyTransaction({
        chainId: 1,
        v: 37, // chainId * 2 + 35 = 1 * 2 + 35 = 37
        r: '0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608',
        s: '0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada'
      });
      const result = validator.validate(tx);

      expect(result.success).toBe(true);
    });

    /**
     * @test Rechazo por falta de gasPrice
     */
    test('should reject legacy transaction without gasPrice', () => {
      const tx = createLegacyTransaction();
      delete (tx as any).gasPrice;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_GAS_PRICE');
    });

    /**
     * @test Rechazo por gasPrice inválido
     */
    test('should reject legacy transaction with invalid gasPrice format', () => {
      const tx = createLegacyTransaction({ gasPrice: 'invalid_hex' });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_GAS_PRICE_FORMAT');
    });

    /**
     * @test Rechazo por gasPrice demasiado alto
     */
    test('should reject legacy transaction with excessive gasPrice', () => {
      const tx = createLegacyTransaction({ gasPrice: '0x174876e800000' }); // 400 Gwei
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('GAS_PRICE_TOO_HIGH');
    });
  });

  describe('EIP-1559 Transactions', () => {
    /**
     * @test Validación de transacción EIP-1559 válida
     */
    test('should validate valid EIP-1559 transaction', () => {
      const tx = createEIP1559Transaction();
      const result = validator.validate(tx);

      expect(result.success).toBe(true);
      expect(result.data).toEqual(tx);
      expect((result.data as EIP1559Transaction).type).toBe(2);
    });

    /**
     * @test Rechazo por falta de maxFeePerGas
     */
    test('should reject EIP-1559 transaction without maxFeePerGas', () => {
      const tx = createEIP1559Transaction();
      delete (tx as any).maxFeePerGas;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_MAX_FEE_PER_GAS');
    });

    /**
     * @test Rechazo por falta de maxPriorityFeePerGas
     */
    test('should reject EIP-1559 transaction without maxPriorityFeePerGas', () => {
      const tx = createEIP1559Transaction();
      delete (tx as any).maxPriorityFeePerGas;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_MAX_PRIORITY_FEE');
    });

    /**
     * @test Rechazo cuando priority fee > max fee
     */
    test('should reject EIP-1559 transaction with priority fee higher than max fee', () => {
      const tx = createEIP1559Transaction({
        maxFeePerGas: '0x77359400', // 2 Gwei
        maxPriorityFeePerGas: '0x2540be400' // 10 Gwei
      });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('PRIORITY_FEE_TOO_HIGH');
    });

    /**
     * @test Rechazo por falta de chainId
     */
    test('should reject EIP-1559 transaction without chainId', () => {
      const tx = createEIP1559Transaction();
      delete (tx as any).chainId;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_CHAIN_ID');
    });

    /**
     * @test Validación con access list válida
     */
    test('should validate EIP-1559 transaction with valid access list', () => {
      const tx = createEIP1559Transaction({
        accessList: [
          {
            address: '0x742d35cc6694c02c0cb6cc2c56b127b58e5c7d7d',
            storageKeys: ['0x0000000000000000000000000000000000000000000000000000000000000001']
          }
        ]
      });
      const result = validator.validate(tx);

      expect(result.success).toBe(true);
    });
  });

  describe('EIP-2930 Transactions', () => {
    /**
     * @test Validación de transacción EIP-2930 válida
     */
    test('should validate valid EIP-2930 transaction', () => {
      const tx = createEIP2930Transaction();
      const result = validator.validate(tx);

      expect(result.success).toBe(true);
      expect((result.data as EIP2930Transaction).type).toBe(1);
    });

    /**
     * @test Rechazo por falta de gasPrice
     */
    test('should reject EIP-2930 transaction without gasPrice', () => {
      const tx = createEIP2930Transaction();
      delete (tx as any).gasPrice;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_GAS_PRICE');
    });

    /**
     * @test Rechazo por falta de chainId
     */
    test('should reject EIP-2930 transaction without chainId', () => {
      const tx = createEIP2930Transaction();
      delete (tx as any).chainId;
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('MISSING_CHAIN_ID');
    });
  });

  describe('Common Field Validation', () => {
    /**
     * @test Rechazo por gasLimit demasiado alto
     */
    test('should reject transaction with excessive gas limit', () => {
      const tx = createLegacyTransaction({ gasLimit: 20000000 });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('GAS_LIMIT_TOO_HIGH');
    });

    /**
     * @test Rechazo por gasLimit demasiado bajo
     */
    test('should reject transaction with insufficient gas limit', () => {
      const tx = createLegacyTransaction({ gasLimit: 15000 });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('GAS_LIMIT_TOO_LOW');
    });

    /**
     * @test Rechazo por dirección inválida
     */
    test('should reject transaction with invalid recipient address', () => {
      const tx = createLegacyTransaction({ to: '0xinvalid' });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_TO_ADDRESS');
    });

    /**
     * @test Rechazo por nonce negativo
     */
    test('should reject transaction with negative nonce', () => {
      const tx = createLegacyTransaction({ nonce: -1 });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_NONCE');
    });

    /**
     * @test Rechazo por data inválida
     */
    test('should reject transaction with invalid data format', () => {
      const tx = createLegacyTransaction({ data: 'not-hex-data' }); // Cambio de 'not-hex' a 'not-hex-data'
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_DATA_FORMAT');
    });
  });

  describe('Invalid Transaction Types', () => {
    /**
     * @test Rechazo de objeto nulo
     */
    test('should reject null transaction', () => {
      const result = validator.validate(null);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_TRANSACTION_OBJECT');
    });

    /**
     * @test Rechazo de tipo inválido
     */
    test('should reject unsupported transaction type', () => {
      const tx = { type: 99, nonce: 0, gasLimit: 21000, value: 0 };
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_TRANSACTION_TYPE');
    });
  });

  describe('Access List Validation', () => {
    /**
     * @test Rechazo de access list inválida
     */
    test('should reject invalid access list format', () => {
      const tx = createEIP1559Transaction({
        accessList: [{ invalidField: 'value' }] as any
      });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_ACCESS_LIST');
    });

    /**
     * @test Rechazo de storage key inválida
     */
    test('should reject invalid storage key in access list', () => {
      const tx = createEIP1559Transaction({
        accessList: [{
          address: '0x742d35cc6694c02c0cb6cc2c56b127b58e5c7d7d',
          storageKeys: ['0xinvalid']
        }]
      });
      const result = validator.validate(tx);

      expect(result.success).toBe(false);
      expect(result.errors?.[0]?.code).toBe('INVALID_ACCESS_LIST');
    });
  });

  describe('Performance Tests', () => {
    /**
     * @test Performance de validación individual
     */
    test('should validate transaction quickly', () => {
      const tx = createLegacyTransaction();
      const startTime = process.hrtime.bigint();

      validator.validate(tx);

      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      expect(durationMs).toBeLessThan(2);
    });

    /**
     * @test Throughput de validación
     */
    test('should handle high throughput validation', () => {
      const transactions = Array(1000).fill(0).map(() => createEIP1559Transaction());
      const startTime = Date.now();

      transactions.forEach(tx => validator.validate(tx));

      const endTime = Date.now();
      const duration = endTime - startTime;
      const throughput = (transactions.length / duration) * 1000;

      expect(throughput).toBeGreaterThan(5000); // > 5k transactions/sec
    });
  });
});
