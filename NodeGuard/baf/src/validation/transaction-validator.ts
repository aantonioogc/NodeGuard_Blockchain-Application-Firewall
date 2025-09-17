// src/validation/transaction-validator.ts
// ajgc: validador de transacciones NodeGuard - simplificado y niquelao

import { z } from 'zod';
import { EventEmitter } from 'events';
import {
  transactionObjectSchema,
  rawTransactionSchema
} from './schemas/transaction';
import { ValidationResult, ValidationContext, ValidationError } from './types';
import { logger } from '../logging/logger';

/**
 * Validador de Transacciones
 * Versión simplificada sin dependencias externas pesadas
 */
export class TransactionValidator extends EventEmitter {
  private metrics = {
    totalValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    transactionTypes: new Map<string, number>()
  };

  constructor(private config = {
    enableEIP1559: true,
    enableEIP2930: true,
    enableEIP155: true,
    maxGasLimit: 15000000, // ajgc: límite sensato para gas
    enableValueValidation: true,
    enableNonceValidation: true,
    allowLegacyTransactions: false,
    supportedChainIds: [1, 3, 4, 5, 42] // redes Ethereum
  }) {
    super();
  }

  /**
   * Validar transacción principal - ajgc: niquelao y simplificado
   */
  validateTransaction(transaction: unknown, context?: ValidationContext): ValidationResult {
    try {
      this.metrics.totalValidations++;
      
      let validatedTx;
      if (typeof transaction === 'string') {
        // transacción raw hexadecimal
        validatedTx = rawTransactionSchema.parse(transaction);
      } else {
        // objeto de transacción
        validatedTx = transactionObjectSchema.parse(transaction);
      }
      
      this.metrics.successfulValidations++;
      
      return {
        success: true,
        data: validatedTx
      };
      
    } catch (error) {
      this.metrics.failedValidations++;
      
      return {
        success: false,
        errors: [this.formatError(error as Error, context)]
      };
    }
  }

  private formatError(error: Error, context?: ValidationContext): ValidationError {
    if (error instanceof z.ZodError) {
      return {
        code: 'TRANSACTION_VALIDATION_ERROR',
        message: 'Estructura de transacción inválida',
        path: error.issues[0]?.path.map(String) || [],
        context: {
          issues: error.issues.map(issue => ({
            path: issue.path.join('.'),
            message: issue.message,
            code: issue.code
          })),
          ...(context as Record<string, unknown>)
        }
      };
    }

    return {
      code: 'TRANSACTION_VALIDATION_ERROR',
      message: error.message,
      context: context as Record<string, unknown>
    };
  }

  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }
}

export default TransactionValidator;