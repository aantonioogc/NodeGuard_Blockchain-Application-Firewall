// src/validation/json-rpc-validator-fixed.ts
// ajgc: validador JSON-RPC mejorado para NodeGuard con mensajes específicos EIP-155

import { z } from 'zod';
import { EventEmitter } from 'events';
import {
  jsonRpcRequestSchema,
  jsonRpcBatchSchema,
  jsonRpcResponseSchema,
  ethereumMethodSchema
} from './schemas/json-rpc';
import { normalizeAddress, validateAddressPatterns } from './schemas/common';
import { ValidationResult, ValidationContext, ValidatedRequest, ValidationError } from './types';
import { logger } from '../logging/logger';

/**
 * Validador JSON-RPC con funciones específicas para EIP-155
 */
export class JsonRpcValidator extends EventEmitter {
  private metrics = {
    totalValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    averageLatency: 0
  };

  constructor(private config = {
    enableStrictMode: true,
    enableSanitization: true,
    enableEthereumValidation: true,
    allowCustomMethods: false,
    customMethodPrefix: '',
    enablePerformanceLogging: false,
    maxPayloadSize: 1024 * 1024,
    maxParamsCount: 20
  }) {
    super();
  }

  /**
   * Validar petición JSON-RPC individual
   */
  validateSingle(
    payload: unknown, 
    context?: ValidationContext
  ): ValidationResult<ValidatedRequest> {
    const startTime = Date.now();
    
    try {
      this.metrics.totalValidations++;
      
      // validación de tamaño de payload
      const sizeValidation = this.validatePayloadSize(payload);
      if (!sizeValidation.isValid) {
        throw new Error(sizeValidation.error);
      }
      
      // validación de estructura JSON-RPC
      const structureValidation = this.validateJsonRpcStructure(payload);
      if (!structureValidation.isValid) {
        throw new Error(structureValidation.error);
      }
      
      // validación básica de estructura
      let validatedRequest = jsonRpcRequestSchema.parse(payload);
      
      // validación específica por método (incluye EIP-155)
      const methodValidation = this.validateMethodSpecificRules(validatedRequest, context);
      if (!methodValidation.isValid) {
        throw new Error(methodValidation.error);
      }
      
      // validación específica de Ethereum
      if (this.config.enableEthereumValidation) {
        this.validateEthereumMethod(validatedRequest);
      }
      
      // saneamiento
      if (this.config.enableSanitization) {
        validatedRequest = this.sanitizeRequest(validatedRequest);
      }
      
      const result: ValidatedRequest = {
        data: validatedRequest,
        validated: true,
        validatedAt: Date.now(),
        sanitized: this.config.enableSanitization,
        context
      };
      
      this.metrics.successfulValidations++;
      this.updateMetrics(Date.now() - startTime);
      
      this.emit('validated', { type: 'single', success: true, context });
      
      return {
        success: true,
        data: result
      };
      
    } catch (error) {
      this.metrics.failedValidations++;
      this.updateMetrics(Date.now() - startTime);
      
      this.emit('validated', { type: 'single', success: false, error, context });
      
      return {
        success: false,
        errors: [this.formatError(error as Error, context)]
      };
    }
  }

  // Validación específica por método con EIP-155
  private validateMethodSpecificRules(
    request: z.infer<typeof jsonRpcRequestSchema>,
    context?: ValidationContext
  ): { isValid: boolean; error?: string } {
    const method = request.method;
    const params = request.params;
    const paramsArray = Array.isArray(params) ? params : [];
    
    try {
      switch (method) {
        case 'eth_sendTransaction':
          if (paramsArray.length === 0) {
            return {
              isValid: false,
              error: 'eth_sendTransaction requiere objeto de transacción como parámetro'
            };
          }
          return this.validateTransactionObjectParam(paramsArray[0]);
          
        case 'eth_sendRawTransaction':
          if (paramsArray.length === 0) {
            return {
              isValid: false,
              error: 'eth_sendRawTransaction requiere transacción raw como parámetro'
            };
          }
          return this.validateRawTransactionParam(paramsArray[0]);
          
        default:
          return { isValid: true };
      }
    } catch (error) {
      return {
        isValid: false,
        error: `Validación de método falló: ${(error as Error).message}`
      };
    }
  }

  /**
   * Validar objeto de transacción con EIP-155
   */
  private validateTransactionObjectParam(param: unknown): { isValid: boolean; error?: string } {
    if (typeof param !== 'object' || param === null) {
      return {
        isValid: false,
        error: 'El parámetro de objeto de transacción debe ser un objeto'
      };
    }
    
    const txObj = param as any;
    
    // Validación EIP-155 específica
    const eip155Validation = this.validateEIP155Compliance(txObj);
    if (!eip155Validation.isValid) {
      return eip155Validation;
    }
    
    return { isValid: true };
  }

  /**
   * Validar cumplimiento EIP-155 en objetos de transacción
   */
  private validateEIP155Compliance(txObj: any): { isValid: boolean; error?: string } {
    // Para transacciones legacy, chainId es requerido para EIP-155
    if (!txObj.chainId) {
      return {
        isValid: false,
        error: 'Chain ID es requerido para protección de replay EIP-155'
      };
    }
    
    // Verificar chainId válido
    const chainIdValue = typeof txObj.chainId === 'string' 
      ? parseInt(txObj.chainId, 16) 
      : txObj.chainId;
      
    // Lista de chains soportadas
    const supportedChains = [1, 31337, 1337, 5, 137, 56, 42161, 10];
    
    if (!supportedChains.includes(chainIdValue)) {
      return {
        isValid: false,
        error: `Chain ID ${chainIdValue} no soportado por la red actual`
      };
    }
    
    // Validar componentes de firma si están presentes
    if (txObj.v !== undefined || txObj.r !== undefined || txObj.s !== undefined) {
      if (!txObj.v || !txObj.r || !txObj.s) {
        return {
          isValid: false,
          error: 'Componentes de firma incompletos (v, r, s son requeridos)'
        };
      }
      
      // Validar v para EIP-155
      const v = typeof txObj.v === 'string' ? parseInt(txObj.v, 16) : txObj.v;
      
      if (v < 27) {
        return {
          isValid: false,
          error: 'Valor v de firma inválido (recovery ID inválido)'
        };
      }
      
      // Validar formato de r y s
      const rValue = typeof txObj.r === 'string' ? txObj.r : `0x${txObj.r}`;
      const sValue = typeof txObj.s === 'string' ? txObj.s : `0x${txObj.s}`;
      
      if (!rValue.match(/^0x[0-9a-fA-F]{64}$/)) {
        return {
          isValid: false,
          error: 'Componente r de firma tiene formato inválido'
        };
      }
      
      if (!sValue.match(/^0x[0-9a-fA-F]{64}$/)) {
        return {
          isValid: false,
          error: 'Componente s de firma tiene formato inválido'
        };
      }
    }
    
    return { isValid: true };
  }

  private validateRawTransactionParam(param: unknown): { isValid: boolean; error?: string } {
    if (typeof param !== 'string' || !/^0x[a-fA-F0-9]+$/.test(param)) {
      return {
        isValid: false,
        error: 'Formato de parámetro de transacción raw inválido'
      };
    }
    
    if (param.length < 10) {
      return {
        isValid: false,
        error: 'Transacción raw demasiado corta'
      };
    }
    
    return { isValid: true };
  }

  private validatePayloadSize(payload: unknown): { isValid: boolean; error?: string } {
    const payloadSize = JSON.stringify(payload).length;
    if (payloadSize > this.config.maxPayloadSize) {
      return {
        isValid: false,
        error: `Payload demasiado grande: ${payloadSize} bytes`
      };
    }
    return { isValid: true };
  }

  private validateJsonRpcStructure(payload: unknown): { isValid: boolean; error?: string } {
    if (typeof payload !== 'object' || payload === null) {
      return {
        isValid: false,
        error: 'Payload debe ser un objeto'
      };
    }
    return { isValid: true };
  }

  private validateEthereumMethod(request: z.infer<typeof jsonRpcRequestSchema>): void {
    if (!this.isEthereumMethod(request.method)) {
      if (!this.config.allowCustomMethods || 
          !request.method.startsWith(this.config.customMethodPrefix)) {
        throw new Error(`Método '${request.method}' no está soportado`);
      }
    }
  }

  private isEthereumMethod(method: string): boolean {
    return ethereumMethodSchema.safeParse(method).success;
  }

  private sanitizeRequest(
    request: z.infer<typeof jsonRpcRequestSchema>
  ): z.infer<typeof jsonRpcRequestSchema> {
    const sanitized = { ...request };
    
    if (typeof sanitized.method === 'string') {
      sanitized.method = sanitized.method.trim();
    }
    
    return sanitized;
  }

  private formatError(error: Error, context?: ValidationContext): ValidationError {
    if (error instanceof z.ZodError) {
      // DEBUG: Log detalles del error de validación
      console.log('DEBUG VALIDATION ERROR:', {
        issues: error.issues.map(issue => ({
          path: issue.path.join('.'),
          message: issue.message,
          code: issue.code
        }))
      });
      
      return {
        code: 'VALIDATION_ERROR',
        message: 'Estructura de petición inválida',
        path: error.issues[0]?.path?.map(p => String(p)) || [],
        context: {
          issues: error.issues.map(issue => ({
            path: issue.path.join('.'),
            message: issue.message,
            code: issue.code
          })),
          ...context
        } as Record<string, unknown>
      };
    }
    
    // Mapear errores específicos a códigos y mensajes descriptivos
    const errorMessage = error.message.toLowerCase();
    
    // EIP-155 specific errors
    if (errorMessage.includes('chain id') || errorMessage.includes('chainid')) {
      if (errorMessage.includes('requerido')) {
        return {
          code: 'EIP155_CHAINID_MISSING',
          message: 'Transaction missing required chainId for EIP-155 replay protection',
          context: context as Record<string, unknown>
        };
      } else if (errorMessage.includes('soportado')) {
        return {
          code: 'EIP155_CHAINID_INVALID',
          message: 'Transaction chainId not supported by current network',
          context: context as Record<string, unknown>
        };
      }
    }
    
    // Signature related errors
    if (errorMessage.includes('signature') || errorMessage.includes('firma')) {
      if (errorMessage.includes('formato') || errorMessage.includes('inválido')) {
        return {
          code: 'INVALID_SIGNATURE_FORMAT',
          message: 'Malformed transaction signature components',
          context: context as Record<string, unknown>
        };
      } else if (errorMessage.includes('recovery') || errorMessage.includes('valor v')) {
        return {
          code: 'INVALID_SIGNATURE_RECOVERY',
          message: 'Invalid signature recovery ID (v value)',
          context: context as Record<string, unknown>
        };
      } else if (errorMessage.includes('incompletos')) {
        return {
          code: 'INCOMPLETE_SIGNATURE',
          message: 'Missing signature components (r, s, v required)',
          context: context as Record<string, unknown>
        };
      }
    }
    
    // Fallback to validation error
    return {
      code: 'VALIDATION_ERROR',
      message: error.message || 'Transaction validation failed',
      context: context as Record<string, unknown>
    };
  }

  private updateMetrics(latency: number): void {
    const alpha = 0.1;
    this.metrics.averageLatency = 
      this.metrics.averageLatency * (1 - alpha) + latency * alpha;
  }

  /**
   * Validar lote de peticiones JSON-RPC
   */
  validateBatch(
    payloads: unknown[],
    context?: ValidationContext
  ): ValidationResult<ValidatedRequest[]> {
    const results: ValidatedRequest[] = [];
    const errors: ValidationError[] = [];
    
    for (const payload of payloads) {
      const result = this.validateSingle(payload, context);
      
      if (result.success && result.data) {
        results.push(result.data);
      } else {
        errors.push(...(result.errors || []));
      }
    }
    
    if (errors.length > 0) {
      return {
        success: false,
        errors
      };
    }
    
    return {
      success: true,
      data: results
    };
  }

  /**
   * Alias para validateSingle para compatibilidad
   */
  validate(payload: unknown, context?: ValidationContext): ValidationResult<ValidatedRequest> {
    return this.validateSingle(payload, context);
  }

  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }
}

export default JsonRpcValidator;
