// src/utils/transaction-utils.ts
// ajgc: utils para transacciones NodeGuard

import { logger } from '../logging/logger';
import { TransactionValidator } from '../validation/transaction-validator';

/**
 * ajgc: campos de transacción mejorados con soporte EIP
 * Mantenido para compatibilidad hacia atrás
 */
export interface EnhancedTxFields {
  hash?: string;
  from?: string;
  to?: string;
  nonce?: number;
  value?: bigint;
  data?: string;
  gasPrice?: bigint;
  gasLimit?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  type?: number;
  chainId?: number;
  accessList?: Array<{
    address: string;
    storageKeys: string[];
  }>;
  v?: number;
  r?: string;
  s?: string;
  functionSelector?: string;
  isContractCall: boolean;
  isContractCreation: boolean;
  estimatedComplexity: 'low' | 'medium' | 'high';
}

// inicializar validador unificado
const transactionValidator = new TransactionValidator();

/**
 * ajgc: parsing de transacción raw - implementación local simplificada
 * Esto está niquelao para manejar formatos básicos
 */
export function parseRawTx(raw: string): EnhancedTxFields {
  try {
    logger.debug('Parseando transacción raw (implementación local)', {
      metadata: { rawLength: raw?.length || 0 }
    });
    
    // Validar usando el validador unificado
    const validationResult = transactionValidator.validateTransaction(raw);
    
    if (validationResult.success && validationResult.data) {
      // Convertir resultado a EnhancedTxFields
      const data = validationResult.data as any;
      return {
        hash: data.hash,
        from: data.from,
        to: data.to,
        nonce: data.nonce,
        value: data.value ? BigInt(data.value) : undefined,
        data: data.data,
        gasPrice: data.gasPrice ? BigInt(data.gasPrice) : undefined,
        gasLimit: data.gasLimit ? BigInt(data.gasLimit) : undefined,
        maxFeePerGas: data.maxFeePerGas ? BigInt(data.maxFeePerGas) : undefined,
        maxPriorityFeePerGas: data.maxPriorityFeePerGas ? BigInt(data.maxPriorityFeePerGas) : undefined,
        type: data.type,
        chainId: data.chainId,
        accessList: data.accessList,
        v: data.v,
        r: data.r,
        s: data.s,
        functionSelector: data.data && data.data.length >= 10 ? data.data.substring(0, 10) : undefined,
        isContractCall: !!(data.to && data.data && data.data.length > 2),
        isContractCreation: !data.to && !!(data.data && data.data.length > 2),
        estimatedComplexity: data.data && data.data.length > 1000 ? 'high' : 'low'
      };
    }
    
    // devolver objeto mínimo seguro si falla validación
    return {
      isContractCall: false,
      isContractCreation: false,
      estimatedComplexity: 'low'
    };
    
  } catch (error) {
    const err = error as Error;
    logger.warn('Falló parsing de transacción raw', {
      error: err,
      metadata: { rawLength: raw?.length || 0 }
    });
    
    // devolver objeto mínimo seguro
    return {
      isContractCall: false,
      isContractCreation: false,
      estimatedComplexity: 'low'
    };
  }
}

/**
 * ajgc: parsing transacción EIP-2718 - implementación local
 */
export function parseEIP2718Transaction(raw: string): EnhancedTxFields | null {
  try {
    logger.debug('Parseando transacción EIP-2718 (implementación local)');
    
    const result = parseRawTx(raw); // usar nuestra propia función
    
    // devolver null si el parsing falló
    if (!result.hash && !result.from && !result.to) {
      return null;
    }
    
    return result;
    
  } catch (error) {
    logger.warn('Falló parsing EIP-2718', {
      error: error as Error
    });
    return null;
  }
}

/**
 * ajgc: extraer direcciones de transacción - implementación local
 */
export function extractTxAddresses(method: string, params: unknown[] | undefined): { from?: string; to?: string } {
  try {
    logger.debug('Extrayendo direcciones de transacción (implementación local)', {
      method,
      metadata: { paramCount: params?.length || 0 }
    });
    
    if (!params || params.length === 0) {
      return {};
    }

    // Extraer direcciones según el método
    switch (method) {
      case 'eth_sendTransaction':
      case 'eth_sendRawTransaction':
      case 'eth_call':
      case 'eth_estimateGas':
        const txParam = params[0] as any;
        return {
          from: txParam?.from,
          to: txParam?.to
        };
      
      case 'eth_getTransactionByHash':
      case 'eth_getTransactionReceipt':
        // estos métodos no contienen direcciones en parámetros
        return {};
      
      default:
        // intentar extraer del primer parámetro si parece un objeto de transacción
        const firstParam = params[0] as any;
        if (firstParam && typeof firstParam === 'object') {
          return {
            from: firstParam.from,
            to: firstParam.to
          };
        }
        return {};
    }
    
  } catch (error) {
    logger.warn('Falló extracción de direcciones', {
      error: error as Error,
      metadata: { method }
    });
    return {};
  }
}

/**
 * ajgc: extracción de campos de transacción raw - implementación local
 */
export function extractRawTxFields(rawTx: string): EnhancedTxFields {
  logger.debug('Extrayendo campos de transacción raw (implementación local)');
  return parseRawTx(rawTx); // usar nuestra propia función
}

/**
 * ajgc: validar firma EIP-155 - implementación local simplificada
 */
export function validateEIP155Signature(fields: EnhancedTxFields): {
  isValid: boolean;
  isEIP155: boolean;
  expectedChainId?: number;
  issues: string[];
} {
  logger.debug('Validando firma EIP-155 (implementación local)', {
    metadata: {
      hasSignature: !!(fields.v && fields.r && fields.s),
      chainId: fields.chainId
    }
  });
  
  const issues: string[] = [];
  
  // Verificar que tenemos componentes de firma
  if (!fields.v || !fields.r || !fields.s) {
    issues.push('Missing signature components');
    return {
      isValid: false,
      isEIP155: false,
      issues
    };
  }
  
  // Verificar EIP-155 (v >= 37 para mainnet)
  const isEIP155 = fields.v >= 37;
  const expectedChainId = isEIP155 ? Math.floor((fields.v - 35) / 2) : undefined;
  
  // Verificar coincidencia de chainId si está presente
  if (isEIP155 && fields.chainId && expectedChainId !== fields.chainId) {
    issues.push(`Chain ID mismatch: expected ${expectedChainId}, got ${fields.chainId}`);
  }
  
  return {
    isValid: issues.length === 0,
    isEIP155,
    expectedChainId,
    issues
  };
}

/**
 * ajgc: analizar selector de función - implementación local
 */
export function analyzeFunctionSelector(selector?: string): {
  name?: string;
  category: 'transfer' | 'approval' | 'swap' | 'staking' | 'governance' | 'other';
  riskLevel: 'low' | 'medium' | 'high';
  description?: string;
} {
  logger.debug('Analizando selector de función (implementación local)', {
    metadata: { selector, hasSelector: !!selector }
  });
  
  if (!selector || selector.length < 10) {
    return {
      category: 'other',
      riskLevel: 'low',
      description: 'Invalid or missing function selector'
    };
  }
  
  const selectorLower = selector.toLowerCase();
  
  // Base de conocimiento de selectores comunes
  const knownSelectors: Record<string, {
    name: string;
    category: 'transfer' | 'approval' | 'swap' | 'staking' | 'governance' | 'other';
    riskLevel: 'low' | 'medium' | 'high';
    description: string;
  }> = {
    '0xa9059cbb': { // transfer(address,uint256)
      name: 'transfer',
      category: 'transfer',
      riskLevel: 'medium',
      description: 'ERC-20 token transfer'
    },
    '0x095ea7b3': { // approve(address,uint256)
      name: 'approve',
      category: 'approval',
      riskLevel: 'high',
      description: 'ERC-20 token approval'
    },
    '0x23b872dd': { // transferFrom(address,address,uint256)
      name: 'transferFrom',
      category: 'transfer',
      riskLevel: 'high',
      description: 'ERC-20 delegated transfer'
    },
    '0x40c10f19': { // mint(address,uint256)
      name: 'mint',
      category: 'other',
      riskLevel: 'high',
      description: 'Token minting function'
    },
    '0x42966c68': { // burn(uint256)
      name: 'burn',
      category: 'other',
      riskLevel: 'medium',
      description: 'Token burning function'
    }
  };
  
  const known = knownSelectors[selectorLower];
  if (known) {
    return known;
  }
  
  // Análisis heurístico básico
  return {
    category: 'other',
    riskLevel: 'low',
    description: 'Unknown function selector'
  };
}

// exportar validador unificado para conveniencia
export { TransactionValidator };

/**
 * ajgc: función para obtener instancia del validador unificado
 */
export function getTransactionValidator(): TransactionValidator {
  return transactionValidator;
}

/**
 * ajgc: helper de migración para identificar código que necesita actualizarse
 */
export function logDeprecatedUsage(functionName: string, replacement: string): void {
  logger.warn(`Función deprecated usada: ${functionName}. Por favor migrar a: ${replacement}`, {
    stack: new Error().stack?.split('\n')[2]?.trim()
  });
}

// export por defecto para compatibilidad hacia atrás
export default parseRawTx;
