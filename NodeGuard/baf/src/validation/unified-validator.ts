// src/validation/unified-validator.ts
// ajgc: validador unificado NodeGuard - hub central de validación

import { EventEmitter } from 'events';
import JsonRpcValidator from './json-rpc-validator';
import RuleValidator from './rule-validator';
import TransactionValidator from './transaction-validator';
import { ValidationResult, ValidationContext, ValidatorConfig } from './types';
import { logger } from '../logging/logger';

/**
 * Validador Unificado
 * 
 * Hub central de validación que coordina todas las actividades de validación.
 * Proporciona una interfaz única para todas las necesidades de validación.
 */
export class UnifiedValidator extends EventEmitter {
  private jsonRpcValidator: JsonRpcValidator;
  private ruleValidator: RuleValidator;
  private transactionValidator: TransactionValidator;
  
  private metrics = {
    totalValidations: 0,
    validationsByType: new Map<string, number>(),
    averageLatency: 0,
    errors: 0
  };

  constructor(private config: Partial<ValidatorConfig> = {}) {
    super();
    
    // inicializar validadores individuales
    this.jsonRpcValidator = new JsonRpcValidator();
    this.ruleValidator = new RuleValidator();
    this.transactionValidator = new TransactionValidator();
    
    // reenviar eventos
    this.setupEventForwarding();
    
    logger.info('Validador Unificado inicializado');
  }

  /**
   * Validar petición JSON-RPC
   */
  validateJsonRpc(payload: unknown, context?: ValidationContext): ValidationResult {
    this.updateMetrics('jsonrpc');
    return this.jsonRpcValidator.validate(payload, context);
  }

  /**
   * Validar regla
   */
  validateRule(rule: unknown, context?: ValidationContext): ValidationResult {
    this.updateMetrics('rule');
    return this.ruleValidator.validateRule(rule, context);
  }

  /**
   * Validar transacción - ajgc: niquelao este método
   */
  validateTransaction(transaction: unknown, context?: ValidationContext): ValidationResult {
    this.updateMetrics('transaction');
    return this.transactionValidator.validateTransaction(transaction, context);
  }

  /**
   * Obtener todas las métricas
   */
  getMetrics(): {
    unified: {
      totalValidations: number;
      validationsByType: Map<string, number>;
      averageLatency: number;
      errors: number;
    };
    jsonRpc: ReturnType<JsonRpcValidator['getMetrics']>;
    rule: ReturnType<RuleValidator['getMetrics']>;
    transaction: ReturnType<TransactionValidator['getMetrics']>;
  } {
    return {
      unified: { ...this.metrics },
      jsonRpc: this.jsonRpcValidator.getMetrics(),
      rule: this.ruleValidator.getMetrics(),
      transaction: this.transactionValidator.getMetrics()
    };
  }

  /**
   * Verificación de salud
   */
  isHealthy(): boolean {
    const totalValidations = this.metrics.totalValidations;
    const errorRate = totalValidations > 0 ? this.metrics.errors / totalValidations : 0;
    
    return errorRate < 0.1; // menos del 10% de tasa de error
  }

  private updateMetrics(type: string): void {
    this.metrics.totalValidations++;
    
    const count = this.metrics.validationsByType.get(type) || 0;
    this.metrics.validationsByType.set(type, count + 1);
  }

  private setupEventForwarding(): void {
    // reenviar eventos de validadores individuales
    [this.jsonRpcValidator, this.ruleValidator, this.transactionValidator].forEach(validator => {
      validator.on('validated', (data: any) => this.emit('validated', data));
      validator.on('validationError', (error: any) => {
        this.metrics.errors++;
        this.emit('validationError', error);
      });
    });
  }
}

// exportar instancia singleton - ajgc: solo una instancia para todo el sistema
const unifiedValidator = new UnifiedValidator();
export default unifiedValidator;
