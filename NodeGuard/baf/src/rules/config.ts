// src/rules/config.ts
// ajgc: configuración central del sistema de reglas NodeGuard
import path from "path";
import { logger } from "../logging/logger";

/**
 * Configuración central para el sistema de reglas del BAF NodeGuard
 * Gestión centralizada y tipada por ajgc
 */

// Configuración Redis principal
export const RULES_REDIS_KEY = process.env.BAF_RULES_REDIS_KEY || "baf:rules:static";
export const RULES_BACKUP_LIST_KEY = process.env.BAF_RULES_BACKUPS_KEY || "baf:rules:backups";
export const RULES_VERSION_KEY = process.env.BAF_RULES_VERSION_KEY || "baf:rules:version";

// File System Configuration
export const LOCAL_RULES_PATH = process.env.BAF_LOCAL_RULES_PATH || 
  path.resolve(process.cwd(), "rules.json");
export const RULES_BACKUP_DIR = process.env.BAF_RULES_BACKUP_DIR || 
  path.resolve(process.cwd(), "backups", "rules");

// Configuración de caché y rendimiento - ajgc: esto controla el TTL
export const RULES_CACHE_TTL_MS = Number(process.env.BAF_RULES_CACHE_TTL_MS || 300000); // 5 min
export const RULES_RELOAD_POLL_MS = Number(process.env.BAF_RULES_RELOAD_POLL_MS || 60000); // 1 min
export const RULES_MAX_JSON_SIZE_BYTES = Number(process.env.BAF_RULES_MAX_JSON_SIZE_BYTES || 10 * 1024 * 1024); // 10MB

// Configuración de seguridad por defecto - NodeGuard BAF
export const SECURITY_DEFAULTS = {
  enforcementMode: (process.env.BAF_ENFORCEMENT_MODE as 'block' | 'monitor' | 'dry-run') || 'block',
  
  // Límites de rate limiting por defecto - Ajustados para detección DoS más agresiva
  rateLimiting: {
    ipTps: Number(process.env.BAF_RATE_LIMIT_IP_TPS || 5), // Más agresivo para tests DoS
    addressTps: Number(process.env.BAF_RATE_LIMIT_ADDRESS_TPS || 3), // Más sensible
    methodTps: Number(process.env.BAF_RATE_LIMIT_METHOD_TPS || 8), // Más estricto
    windowSeconds: Number(process.env.BAF_RATE_WINDOW_SECONDS || 10), // Ventana más corta
    burstMultiplier: Number(process.env.BAF_RATE_BURST_MULTIPLIER || 1.2) // Menos permisivo
  },
  
  // Token bucket - ajgc: configuración del balde de tokens
  tokenBucket: {
    capacity: Number(process.env.BAF_TB_CAPACITY || 100),
    refillPerSecond: Number(process.env.BAF_TB_REFILL_PER_SECOND || 50),
    maxBurst: Number(process.env.BAF_TB_MAX_BURST || 200)
  },
  
  // Fingerprinting - esto está niquelao
  fingerprint: {
    windowSeconds: Number(process.env.BAF_FINGERPRINT_WINDOW_SECONDS || 300),
    maxRepeats: Number(process.env.BAF_FINGERPRINT_MAX_REPEATS || 10),
    enableCrossBatchAnalysis: process.env.BAF_FINGERPRINT_CROSS_BATCH !== 'false',
    enableMLFingerprinting: process.env.BAF_ML_FINGERPRINTING === 'true'
  },
  
  // Constraints de gas y transacciones
  gasConstraints: {
    maxGasLimit: Number(process.env.BAF_MAX_GAS_LIMIT || 15000000), // 15M gas
    minGasPriceWei: process.env.BAF_MIN_GAS_PRICE_WEI || '1000000000', // 1 gwei
    maxGasPriceWei: process.env.BAF_MAX_GAS_PRICE_WEI || '1000000000000', // 1000 gwei
    maxValueWei: process.env.BAF_MAX_VALUE_WEI || '100000000000000000000' // 100 ETH
  },
  
  // Cumplimiento EIP - para mantener compatibilidad blockchain
  eipCompliance: {
    enforceEIP155: process.env.BAF_ENFORCE_EIP155 !== 'false',
    enforceEIP2718: process.env.BAF_ENFORCE_EIP2718 !== 'false',
    enforceEIP1559: process.env.BAF_ENFORCE_EIP1559 !== 'false',
    allowLegacyTransactions: process.env.BAF_ALLOW_LEGACY_TX !== 'false'
  },
  
  // Límites de payload
  payloadLimits: {
    maxRpcPayloadSizeBytes: Number(process.env.BAF_MAX_RPC_PAYLOAD_SIZE || 1024 * 1024),
    maxBatchSize: Number(process.env.BAF_MAX_BATCH_SIZE || 100),
    maxDataSizeBytes: Number(process.env.BAF_MAX_DATA_SIZE || 128 * 1024),
    maxParamsCount: Number(process.env.BAF_MAX_PARAMS_COUNT || 20)
  },
  
  // Características avanzadas de seguridad - NodeGuard BAF
  advancedSecurity: {
    enableMEVDetection: process.env.BAF_MEV_DETECTION === 'true',
    enableSybilDetection: process.env.BAF_SYBIL_DETECTION !== 'false',
    enableContractAnalysis: process.env.BAF_CONTRACT_ANALYSIS !== 'false',
    enableReputationSystem: process.env.BAF_REPUTATION_SYSTEM !== 'false',
    enableMLDetection: process.env.BAF_ML_DETECTION === 'true',
    enableBehaviorAnalysis: process.env.BAF_BEHAVIOR_ANALYSIS !== 'false'
  }
};

// Configuración de detección de amenazas - ajgc: patrones de ataque conocidos
export const THREAT_DETECTION = {
  // Detección basada en firmas
  signatures: {
    knownAttackPatterns: [
      '0xa9059cbb', // transfer - ataques de alto volumen
      '0x23b872dd', // transferFrom - ataques de aprobación
      '0x095ea7b3'  // approve - ataques de aprobación ilimitada
    ],
    suspiciousSelectors: [
      '0x38ed1739', // swapExactTokensForTokens - MEV
      '0x7ff36ab5', // swapExactETHForTokens - MEV
      '0x5c11d795'  // swapExactTokensForETHSupportingFeeOnTransferTokens - MEV
    ],
    contractCreationPatterns: [
      /^0x60806040/, // Creación de contrato estándar
      /^0x608060405234801561001057600080fd5b50/ // Creación compleja
    ]
  },
  
  // Patrones de comportamiento
  behavioral: {
    rapidFireThreshold: 100, // Requests por minuto - de locos
    burstPatternWindow: 10000, // 10 segundos
    suspciciousGasMultiplier: 10, // 10x precio gas promedio
    mevThresholdGwei: 50,
    sybilAddressThreshold: 50 // Direcciones únicas desde misma IP
  },
  
  // Sistema de puntuación de riesgo
  riskScoring: {
    baselineRisk: 10,
    maxRiskScore: 100,
    riskFactors: {
      unknownContract: 15,
      highGasPrice: 10,
      unusualMethod: 8,
      repeatPattern: 12,
      crossChainAnomaly: 20,
      temporalAnomaly: 5
    }
  }
};

// Configuración de rendimiento y monitoreo
export const PERFORMANCE_CONFIG = {
  metricsEnabled: process.env.BAF_METRICS_ENABLED !== 'false',
  metricsRetentionHours: Number(process.env.BAF_METRICS_RETENTION_HOURS || 168), // 7 días
  
  // Umbrales de rendimiento - ajgc: para el monitoring
  performanceThresholds: {
    maxEvaluationTimeMs: Number(process.env.BAF_MAX_EVALUATION_TIME_MS || 100),
    maxRuleProcessingTimeMs: Number(process.env.BAF_MAX_RULE_PROCESSING_TIME_MS || 50),
    alertSlowRequestsMs: Number(process.env.BAF_ALERT_SLOW_REQUESTS_MS || 200)
  },
  
  // Estrategia de caché
  caching: {
    enableRuleResultCache: process.env.BAF_RULE_RESULT_CACHE !== 'false',
    cacheHitRateTarget: Number(process.env.BAF_CACHE_HIT_RATE_TARGET || 70),
    adaptiveCacheEnabled: process.env.BAF_ADAPTIVE_CACHE === 'true'
  }
};

// Configuración de red y blockchains - NodeGuard multichain
export const NETWORK_CONFIG = {
  // Chains soportadas
  supportedChainIds: (process.env.BAF_SUPPORTED_CHAIN_IDS || '1,137,56,42161,10')
    .split(',').map(Number).filter(Boolean),
  
  // Configuración específica por chain
  chainSpecific: {
    ethereum: {
      chainId: 1,
      avgBlockTime: 12000, // 12 segundos
      avgGasPrice: '20000000000' // 20 gwei
    },
    polygon: {
      chainId: 137,
      avgBlockTime: 2000,
      avgGasPrice: '30000000000'
    },
    bsc: {
      chainId: 56,
      avgBlockTime: 3000,
      avgGasPrice: '5000000000'
    }
  },
  
  // Detección cross-chain
  crossChain: {
    enableCrossChainAnalysis: process.env.BAF_CROSS_CHAIN_ANALYSIS === 'true',
    suspiciousChainSwitching: process.env.BAF_SUSPICIOUS_CHAIN_SWITCHING !== 'false'
  }
};

// Configuración de Machine Learning - ajgc: experimental por ahora
export const ML_CONFIG = {
  enabled: process.env.BAF_ML_ENABLED === 'true',
  models: {
    threatDetection: {
      confidence_threshold: Number(process.env.BAF_ML_THREAT_THRESHOLD || 0.7),
      model_path: process.env.BAF_ML_MODEL_PATH || './models/threat_detection.json',
      feature_count: Number(process.env.BAF_ML_FEATURE_COUNT || 15),
      update_interval_hours: Number(process.env.BAF_ML_UPDATE_INTERVAL || 24)
    },
    anomalyDetection: {
      confidence_threshold: Number(process.env.BAF_ML_ANOMALY_THRESHOLD || 0.8),
      window_size: Number(process.env.BAF_ML_WINDOW_SIZE || 1000),
      learning_rate: Number(process.env.BAF_ML_LEARNING_RATE || 0.01)
    }
  }
};

/**
 * Validador de configuración - ajgc: para verificar que todo esté bien
 */
export class ConfigValidator {
  static validate(): { isValid: boolean; errors: string[]; warnings: string[] } {
    const result = { isValid: true, errors: [] as string[], warnings: [] as string[] };
    
    try {
      // Validar TTL de caché
      if (RULES_CACHE_TTL_MS < 10000) {
        result.warnings.push('RULES_CACHE_TTL_MS muy bajo, puede causar problemas de rendimiento');
      }
      
      // Validar rutas de archivos
      if (!path.isAbsolute(LOCAL_RULES_PATH)) {
        result.warnings.push('LOCAL_RULES_PATH debería ser absoluta para producción');
      }
      
      // Validar rate limiting
      if (SECURITY_DEFAULTS.rateLimiting.ipTps <= 0) {
        result.errors.push('IP TPS debe ser positivo');
        result.isValid = false;
      }
      
      // Validar constraints de gas - echarle un ojillo a esto
      const minGas = BigInt(SECURITY_DEFAULTS.gasConstraints.minGasPriceWei);
      const maxGas = BigInt(SECURITY_DEFAULTS.gasConstraints.maxGasPriceWei);
      
      if (minGas >= maxGas) {
        result.errors.push('Precio mínimo de gas debe ser menor que el máximo');
        result.isValid = false;
      }
      
      // Validar límites de payload
      if (SECURITY_DEFAULTS.payloadLimits.maxRpcPayloadSizeBytes > RULES_MAX_JSON_SIZE_BYTES) {
        result.warnings.push('Tamaño máximo RPC excede límite máximo JSON');
      }
      
      // Validar chains soportadas
      if (NETWORK_CONFIG.supportedChainIds.length === 0) {
        result.warnings.push('No hay chain IDs configuradas');
      }
      
    } catch (error) {
      result.errors.push(`Error en validación de configuración: ${(error as Error).message}`);
      result.isValid = false;
    }
    
    return result;
  }
  
  static logValidationResult(): void {
    const validation = this.validate();
    
    if (validation.errors.length > 0) {
      logger.error('Fallo en validación de configuración NodeGuard', { 
        metadata: {
          errors: validation.errors
        }
      });
    }
    
    if (validation.warnings.length > 0) {
      logger.warn('Warnings en configuración', { 
        metadata: {
          warnings: validation.warnings
        }
      });
    }
    
    if (validation.isValid && validation.warnings.length === 0) {
      logger.info('Validación de configuración pasada correctamente');
    }
  }
}

// Compatibilidad hacia atrás - ajgc: para no romper código existente
export const DEFAULTS = {
  enforcementMode: SECURITY_DEFAULTS.enforcementMode
};

export default {
  RULES_REDIS_KEY,
  RULES_BACKUP_LIST_KEY,
  LOCAL_RULES_PATH,
  RULES_CACHE_TTL_MS,
  RULES_RELOAD_POLL_MS,
  RULES_MAX_JSON_SIZE_BYTES,
  DEFAULTS,
  SECURITY_DEFAULTS,
  THREAT_DETECTION,
  PERFORMANCE_CONFIG,
  NETWORK_CONFIG,
  ML_CONFIG
};
