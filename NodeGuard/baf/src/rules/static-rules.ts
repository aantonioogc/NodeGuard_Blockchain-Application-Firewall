// src/rules/static-rules.ts
// ajgc: motor de reglas estáticas NodeGuard
import { StaticRules, RuleDecision } from "./types";
import { logger } from "../logging/logger";
// import { parseTransaction } from "ethers"; // No usado actualmente
import type { Transaction } from "ethers";

// Importar desde módulos de validación unificados
import { JsonRpcValidator } from "../validation/json-rpc-validator";
import { TransactionValidator } from "../validation/transaction-validator";
import { RuleValidator } from "../validation/rule-validator";
import { normalizeAddress, validateAddressPatterns } from "../validation/schemas/common";

import { SECURITY_DEFAULTS, THREAT_DETECTION, NETWORK_CONFIG } from "./config";

/**
 * Motor de Reglas Estáticas Mejorado - REFACTORIZADO
 * 
 * Ahora usa módulos de validación unificados para consistencia.
 * Toda la lógica de validación se ha extraído a validadores especializados.
 */

interface StaticRuleContext {
  payload?: any;
  method: string;
  rawTx?: string;
  parsedTx?: any;
  ip?: string;
  from?: string;
  to?: string;
  timestamp?: number;
  requestId?: string;
}

// Inicializar validadores
const jsonRpcValidator = new JsonRpcValidator();
const transactionValidator = new TransactionValidator();
const ruleValidator = new RuleValidator();

/**
 * Evaluación de reglas estáticas mejorada - ajgc: usa validadores unificados
 */
export function evaluateStaticRules(
  context: StaticRuleContext,
  rules: StaticRules
): RuleDecision | undefined {
  const startTime = Date.now();
  
  try {
    logger.debug('Evaluando reglas estáticas', {
      method: context.method,
      requestId: context.requestId,
      metadata: {
        hasRawTx: !!context.rawTx
      }
    });

    // Contexto mejorado con datos adicionales
    const enhancedContext = enhanceContext(context);

    // Capa 1: Validación JSON-RPC usando validador unificado
    let decision = evaluateJsonRpcRules(enhancedContext, rules);
    if (decision) return decision;

    // Capa 2: Reglas basadas en métodos
    decision = evaluateMethodRules(enhancedContext, rules);
    if (decision) return decision;

    // Capa 3: Reglas basadas en direcciones
    decision = evaluateAddressRules(enhancedContext, rules);
    if (decision) return decision;

    // Capa 4: Validación de transacciones usando validador unificado
    if (enhancedContext.rawTx) {
      decision = evaluateTransactionRules(enhancedContext, rules);
      if (decision) return decision;
    }

    // Capa 5: Reglas avanzadas de seguridad
    decision = evaluateAdvancedSecurityRules(enhancedContext, rules);
    if (decision) return decision;

    const evaluationTime = Date.now() - startTime;
    if (evaluationTime > 1000) { // umbral de 1 segundo en lugar de tamaño de payload
      logger.warn('Evaluación de reglas estáticas tardó más de lo esperado', {
        method: context.method,
        duration: evaluationTime,
        metadata: {
          evaluationTimeMs: `${evaluationTime}ms`
        }
      });
    }

    // Todas las reglas pasaron
    return undefined;
    
  } catch (error) {
    const err = error as Error;
    logger.error('Fallo en evaluación de reglas estáticas', {
      error: err,
      method: context.method,
      requestId: context.requestId
    });
    
    return {
      decision: "block",
      reason: "rule_evaluation_error",
      ruleId: "system:error",
      metadata: { error: err.message }
    };
  }
}

/**
 * Mejorar contexto con campos calculados adicionales - USANDO VALIDADOR UNIFICADO
 */
function enhanceContext(context: StaticRuleContext): StaticRuleContext {
  const enhanced = { ...context };
  
  // Usar validador unificado para normalización de direcciones
  enhanced.from = normalizeAddress(context.from || context.payload?.params?.[0]?.from);
  enhanced.to = normalizeAddress(context.to || context.payload?.params?.[0]?.to);
  
  // Añadir timestamp si falta
  enhanced.timestamp = context.timestamp || Date.now();
  
  return enhanced;
}

/**
 * Validación JSON-RPC usando validador unificado - NUEVO
 */
function evaluateJsonRpcRules(context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  if (!context.payload) return undefined;

  try {
    // Usar validador JSON-RPC unificado
    const validationResult = jsonRpcValidator.validateSingle(context.payload, {
      clientIp: context.ip,
      requestId: context.requestId,
      timestamp: context.timestamp
    });

    if (!validationResult.success) {
      const errors = validationResult.errors || [];
      const firstError = errors[0];
      
      return {
        decision: "block",
        reason: firstError?.code || "json_rpc_validation_failed",
        ruleId: "jsonRpcValidation",
        metadata: {
          errors: errors.map(e => e.message),
          context: firstError?.context
        }
      };
    }

    return undefined;
  } catch (error) {
    return {
      decision: "block",
      reason: "json_rpc_validation_error",
      ruleId: "jsonRpcValidation",
      metadata: { error: (error as Error).message }
    };
  }
}

/**
 * Evaluación de reglas basadas en métodos - SIMPLIFICADO (validación de payload movida al validador JSON-RPC)
 */
function evaluateMethodRules(context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  const method = context.method;

  // Verificación de whitelist
  if (rules.static?.allowedMethods && rules.static.allowedMethods.length > 0) {
    if (!rules.static.allowedMethods.includes(method)) {
      logger.warn('Método no en whitelist', { method });
      return {
        decision: "block",
        reason: "method_not_in_whitelist",
        ruleId: "allowedMethods",
        metadata: { method, allowedMethods: rules.static.allowedMethods.length }
      };
    }
  }

  // Verificación de blacklist
  if (rules.static?.blockedMethods?.includes(method)) {
    logger.warn('Método bloqueado por blacklist', { method });
    return {
      decision: "block",
      reason: "blocked_method",
      ruleId: "blockedMethods",
      metadata: { method }
    };
  }

  // Constraints específicos por método - ajgc: esto está niquelao
  const methodConstraints = rules.static?.methodParamConstraints?.[method];
  if (methodConstraints && context.rawTx) {
    const dataSize = (context.rawTx.length - 2) / 2; // Quitar prefijo 0x
    if (methodConstraints.maxDataSizeBytes && dataSize > methodConstraints.maxDataSizeBytes) {
      return {
        decision: "block",
        reason: "method_data_size_exceeded",
        ruleId: "methodParamConstraints",
        metadata: {
          method,
          dataSize,
          maxSize: methodConstraints.maxDataSizeBytes
        }
      };
    }
  }

  return undefined;
}

/**
 * Evaluación de reglas basadas en direcciones - USANDO VALIDADOR UNIFICADO
 */
function evaluateAddressRules(context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  const { from, to } = context;

  // Verificación de direcciones bloqueadas
  if (rules.static?.blockedAddresses) {
    const blockedAddresses = rules.static.blockedAddresses.map(addr => addr.toLowerCase());
    
    if (from && blockedAddresses.includes(from.toLowerCase())) {
      return {
        decision: "block",
        reason: "blocked_from_address",
        ruleId: "blockedAddresses",
        metadata: { address: from, type: 'from' }
      };
    }

    if (to && blockedAddresses.includes(to.toLowerCase())) {
      return {
        decision: "block",
        reason: "blocked_to_address", 
        ruleId: "blockedAddresses",
        metadata: { address: to, type: 'to' }
      };
    }
  }

  // Verificación de direcciones permitidas
  if (rules.static?.allowedAddresses && rules.static.allowedAddresses.length > 0) {
    const allowedAddresses = rules.static.allowedAddresses.map(addr => addr.toLowerCase());
    
    if (from && !allowedAddresses.includes(from.toLowerCase())) {
      return {
        decision: "block",
        reason: "from_address_not_allowed",
        ruleId: "allowedAddresses",
        metadata: { address: from }
      };
    }
  }

  // Validación de patrones de direcciones usando validador unificado
  if (from || to) {
    const validation = validateAddressPatterns(from, to);
    if (!validation.isValid) {
      return {
        decision: "block",
        reason: "invalid_address_format",
        ruleId: "addressValidation",
        metadata: { 
          errors: validation.errors,
          from,
          to
        }
      };
    }
  }

  return undefined;
}

/**
 * Transaction validation using unified validator - COMPLETELY REFACTORED
 */
function evaluateTransactionRules(context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  if (!context.rawTx || typeof context.rawTx !== 'string') {
    return undefined;
  }

  try {
    // Use unified transaction validator
    const validationResult = transactionValidator.validateTransaction(context.rawTx, {
      requestId: context.requestId,
      clientIp: context.ip,
      timestamp: context.timestamp
    });

    if (!validationResult.success) {
      const errors = validationResult.errors || [];
      const firstError = errors[0];
      
      return {
        decision: "block",
        reason: firstError?.code || "transaction_validation_failed",
        ruleId: "transactionValidation",
        metadata: {
          errors: errors.map(e => e.message),
          rawTxLength: context.rawTx.length,
          isHex: context.rawTx.startsWith('0x')
        }
      };
    }

    // Get parsed transaction from validator
    const parsedTx = validationResult.data;
    context.parsedTx = parsedTx;

    // Additional rule-specific validations
    const contractValidation = evaluateContractRules(parsedTx, rules);
    if (contractValidation) return contractValidation;

    const gasValidation = evaluateGasAndFeeRules(parsedTx, rules);
    if (gasValidation) return gasValidation;

    const functionValidation = evaluateFunctionSelectorRules(parsedTx, rules);
    if (functionValidation) return functionValidation;

    const threatValidation = evaluateThreatPatterns(parsedTx, context, rules);
    if (threatValidation) return threatValidation;

    return undefined;
    
  } catch (error) {
    const err = error as Error;
    logger.warn('Transaction validation failed', {
      error: err,
      metadata: {
        rawTxLength: context.rawTx.length
      }
    });
    
    return {
      decision: "block",
      reason: "transaction_validation_error",
      ruleId: "transactionValidation",
      metadata: {
        error: err.message,
        rawTxLength: context.rawTx.length,
        isHex: context.rawTx.startsWith('0x')
      }
    };
  }
}

/**
 * Contract interaction rules - UNCHANGED (specific to static rules)
 */
function evaluateContractRules(txFields: any, rules: StaticRules): RuleDecision | undefined {
  // Contract blacklist
  if (rules.static?.blockedContracts && txFields.to) {
    const blockedContracts = rules.static.blockedContracts.map(addr => addr.toLowerCase());
    if (blockedContracts.includes(txFields.to.toLowerCase())) {
      return {
        decision: "block",
        reason: "blocked_contract",
        ruleId: "blockedContracts",
        metadata: { contractAddress: txFields.to }
      };
    }
  }

  // Contract creation restrictions
  if (txFields.isContractCreation) {
    const creationRules = rules.static?.contractCreation;
    if (creationRules?.blocked === true) {
      return {
        decision: "block",
        reason: "contract_creation_blocked",
        ruleId: "contractCreation",
        metadata: { dataSize: txFields.data?.length || 0 }
      };
    }

    if (creationRules?.maxBytecodeSize) {
      const bytecodeSize = txFields.data ? txFields.data.length / 2 - 1 : 0;
      if (bytecodeSize > creationRules.maxBytecodeSize) {
        return {
          decision: "block",
          reason: "contract_bytecode_too_large",
          ruleId: "contractCreation",
          metadata: { bytecodeSize, maxSize: creationRules.maxBytecodeSize }
        };
      }
    }
  }

  return undefined;
}

/**
 * Gas and fee rules - UNCHANGED (specific to static rules)
 */
function evaluateGasAndFeeRules(txFields: any, rules: StaticRules): RuleDecision | undefined {
  const gasConstraints = rules.static?.gasAndFeeConstraints;

  // Gas limit validation
  if (gasConstraints?.maxGasLimit && txFields.gasLimit) {
    const gasLimit = Number(txFields.gasLimit);
    if (gasLimit > gasConstraints.maxGasLimit) {
      return {
        decision: "block",
        reason: "gas_limit_exceeded",
        ruleId: "gasAndFeeConstraints",
        metadata: { gasLimit, maxGasLimit: gasConstraints.maxGasLimit }
      };
    }
  }

  // Gas price validation
  const minGasPrice = gasConstraints?.minGasPriceWei ? BigInt(gasConstraints.minGasPriceWei) : null;
  const maxGasPrice = gasConstraints?.maxGasPriceWei ? BigInt(gasConstraints.maxGasPriceWei) : null;

  if (txFields.gasPrice) {
    if (minGasPrice && txFields.gasPrice < minGasPrice) {
      return {
        decision: "block",
        reason: "gas_price_too_low",
        ruleId: "gasAndFeeConstraints",
        metadata: {
          gasPrice: txFields.gasPrice.toString(),
          minGasPrice: minGasPrice.toString()
        }
      };
    }

    if (maxGasPrice && txFields.gasPrice > maxGasPrice) {
      return {
        decision: "block",
        reason: "gas_price_too_high",
        ruleId: "gasAndFeeConstraints",
        metadata: {
          gasPrice: txFields.gasPrice.toString(),
          maxGasPrice: maxGasPrice.toString()
        }
      };
    }
  }

  if (txFields.maxFeePerGas) {
    if (minGasPrice && txFields.maxFeePerGas < minGasPrice) {
      return {
        decision: "block",
        reason: "max_fee_per_gas_too_low",
        ruleId: "gasAndFeeConstraints",
        metadata: {
          maxFeePerGas: txFields.maxFeePerGas.toString(),
          minGasPrice: minGasPrice.toString()
        }
      };
    }

    if (maxGasPrice && txFields.maxFeePerGas > maxGasPrice) {
      return {
        decision: "block",
        reason: "max_fee_per_gas_too_high",
        ruleId: "gasAndFeeConstraints",
        metadata: {
          maxFeePerGas: txFields.maxFeePerGas.toString(),
          maxGasPrice: maxGasPrice.toString()
        }
      };
    }
  }

  return undefined;
}

/**
 * Function selector rules - USING UNIFIED VALIDATOR
 */
function evaluateFunctionSelectorRules(txFields: any, rules: StaticRules): RuleDecision | undefined {
  if (!txFields.data || txFields.data.length < 10) {
    return undefined;
  }

  const functionSelector = txFields.functionSelector || txFields.data.substring(0, 10);
  
  // Simple function selector analysis - ajgc: análisis básico local
  const selectorAnalysis = {
    selector: functionSelector,
    riskLevel: 'low' as 'low' | 'medium' | 'high',
    description: 'unknown_function'
  };

  // Detectar selectores de alto riesgo conocidos
  const highRiskSelectors = [
    '0xa9059cbb', // transfer(address,uint256)
    '0x095ea7b3', // approve(address,uint256)
    '0x23b872dd', // transferFrom(address,address,uint256)
    '0x40c10f19', // mint(address,uint256)
    '0x42966c68', // burn(uint256)
    '0x79cc6790', // burnFrom(address,uint256)
  ];

  if (highRiskSelectors.includes(functionSelector.toLowerCase())) {
    selectorAnalysis.riskLevel = 'high';
    selectorAnalysis.description = 'high_risk_token_function';
  }

  // Global function selector blacklist
  if (rules.static?.functionSelectorBlacklist?.includes(functionSelector.toLowerCase())) {
    return {
      decision: "block",
      reason: "blocked_function_selector",
      ruleId: "functionSelectorBlacklist",
      metadata: {
        selector: functionSelector,
        analysis: selectorAnalysis
      }
    };
  }

  // Contract-specific function blacklist
  if (rules.static?.contractFunctionBlacklist && txFields.to) {
    const contractBlacklist = rules.static.contractFunctionBlacklist[txFields.to.toLowerCase()] ||
      rules.static.contractFunctionBlacklist['*'] || [];
    
    if (contractBlacklist.includes(functionSelector.toLowerCase())) {
      return {
        decision: "block",
        reason: "blocked_function_for_contract",
        ruleId: "contractFunctionBlacklist",
        metadata: {
          selector: functionSelector,
          contract: txFields.to,
          analysis: selectorAnalysis
        }
      };
    }
  }

  // High-risk function detection
  if (selectorAnalysis.riskLevel === 'high' && rules.static?.riskBasedBlocking?.blockHighRiskFunctions) {
    return {
      decision: "block",
      reason: "high_risk_function_detected",
      ruleId: "riskBasedBlocking",
      metadata: {
        selector: functionSelector,
        analysis: selectorAnalysis
      }
    };
  }

  return undefined;
}

/**
 * Threat pattern evaluation - UNCHANGED (MEV detection specific to static rules)
 */
function evaluateThreatPatterns(txFields: any, context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  if (!SECURITY_DEFAULTS.advancedSecurity.enableMEVDetection) {
    return undefined;
  }

  // MEV detection
  if (txFields.gasPrice || txFields.maxFeePerGas) {
    const effectiveGasPrice = txFields.maxFeePerGas || txFields.gasPrice;
    const avgGasPrice = BigInt(NETWORK_CONFIG.chainSpecific.ethereum.avgGasPrice);

    if (effectiveGasPrice && effectiveGasPrice > avgGasPrice * BigInt(5)) {
      if (txFields.functionSelector && THREAT_DETECTION.signatures.suspiciousSelectors.includes(txFields.functionSelector)) {
        return {
          decision: rules.static?.mevProtection?.blockSuspicious === true ? "block" : "monitor",
          reason: "potential_mev_transaction",
          ruleId: "mevProtection",
          metadata: {
            gasPrice: effectiveGasPrice.toString(),
            avgGasPrice: avgGasPrice.toString(),
            functionSelector: txFields.functionSelector,
            multiplier: Number(effectiveGasPrice / avgGasPrice)
          }
        };
      }
    }
  }

  return undefined;
}

/**
 * Advanced security rules - SIMPLIFIED (temporal/geo moved to specialized modules)
 */
function evaluateAdvancedSecurityRules(context: StaticRuleContext, rules: StaticRules): RuleDecision | undefined {
  // Cross-chain validation
  if (NETWORK_CONFIG.crossChain.enableCrossChainAnalysis && context.parsedTx?.chainId) {
    const chainId = context.parsedTx.chainId;
    if (!NETWORK_CONFIG.supportedChainIds.includes(chainId)) {
      return {
        decision: "block",
        reason: "unsupported_chain_id",
        ruleId: "crossChainValidation",
        metadata: {
          chainId,
          supportedChains: NETWORK_CONFIG.supportedChainIds
        }
      };
    }
  }

  // Temporal anomaly detection
  if (context.timestamp) {
    const now = Date.now();
    const age = now - context.timestamp;
    
    if (age < 0 && Math.abs(age) > 300000) { // 5 minutes tolerance
      return {
        decision: "block",
        reason: "future_timestamp",
        ruleId: "temporalValidation",
        metadata: {
          timestamp: context.timestamp,
          now,
          drift: age
        }
      };
    }
  }

  return undefined;
}

export default evaluateStaticRules;
