// src/rules/types.ts
// ajgc: esquemas Zod y tipos para el sistema de reglas NodeGuard
import { z } from "zod";

/**
 * Esquemas Zod y tipos TypeScript para el Sistema de Reglas BAF
 * Validación completa y estricta - hecho por ajgc
 */

// Sub-esquemas mejorados

const MethodParamConstraintSchema = z.object({
  maxDataSizeBytes: z.number().int().positive().optional(),
  require_to_address_if_data: z.boolean().optional(),
  disallow_delegatecall_pattern: z.boolean().optional(),
  max_block_range: z.number().int().positive().optional(),
  disallow_wildcard_topic_excess: z.boolean().optional(),
  maxParamsCount: z.number().int().positive().optional(),
  requireValidSignature: z.boolean().optional()
}).passthrough();

const GasAndFeeConstraintsSchema = z.object({
  minGasPriceWei: z.string().optional(),
  maxGasPriceWei: z.string().optional(),
  minMaxPriorityFeePerGasWei: z.string().optional(),
  maxMaxPriorityFeePerGasWei: z.string().optional(),
  maxGasLimit: z.number().int().positive().optional(),
  maxIntrinsicGasForContractCreation: z.number().int().positive().optional(),
  dynamicGasPricing: z.object({
    enabled: z.boolean().optional().default(false),
    multiplierThreshold: z.number().positive().optional().default(5),
    adaptiveAdjustment: z.boolean().optional().default(false)
  }).optional()
}).optional();

const TransactionConstraintsSchema = z.object({
  maxRawTxLen: z.number().int().positive().optional(),
  maxValueWeiPerTx: z.string().nullable().optional(),
  require_nonce_within_range: z.object({
    enabled: z.boolean().optional().default(true),
    max_future_nonces: z.number().int().nonnegative().optional().default(100)
  }).optional(),
  require_from_whitelist_for_high_value: z.object({
    enabled: z.boolean().optional().default(false),
    thresholdWei: z.string().optional(),
    enforcedAddresses: z.array(z.string()).optional().default([])
  }).optional(),
  blockZeroValueToNullAddress: z.boolean().optional().default(true)
}).optional();

const PayloadLimitsSchema = z.object({
  maxRpcPayloadSizeBytes: z.number().int().positive().optional().default(1048576),
  maxBatchRequests: z.number().int().positive().optional().default(50),
  maxParamsCount: z.number().int().positive().optional().default(20),
  maxStringLength: z.number().int().positive().optional().default(10000)
}).optional();

const SignaturePoliciesSchema = z.object({
  require_eip155: z.boolean().optional().default(true),
  disallow_legacy_unsigned: z.boolean().optional().default(true),
  require_r_s_v_valid: z.boolean().optional().default(true),
  enforceCanonicalSignatures: z.boolean().optional().default(true),
  rejectMalleableSignatures: z.boolean().optional().default(true)
}).optional();

const ReplayProtectionSchema = z.object({
  enforce_chainid_match: z.boolean().optional().default(true),
  block_if_chainid_missing_and_legacy: z.boolean().optional().default(true),
  supportedChainIds: z.array(z.number().int()).optional().default([1, 137, 56, 42161, 10]),
  crossChainValidation: z.boolean().optional().default(false)
}).optional();

// Añadir schemas faltantes - ajgc: estos estaban incompletos
const ContractCreationSchema = z.object({
  blocked: z.boolean().optional().default(false),
  maxBytecodeSize: z.number().int().positive().optional(),
  requireWhitelist: z.boolean().optional().default(false),
  whitelistedCreators: z.array(z.string()).optional().default([]),
  gasLimitMultiplier: z.number().positive().optional().default(1.5)
}).optional();

const FunctionSelectorSchema = z.object({
  globalBlacklist: z.array(z.string()).optional().default([]),
  contractSpecific: z.record(z.array(z.string())).optional().default({}),
  patternBlacklist: z.array(z.string()).optional().default([]),
  riskAnalysis: z.boolean().optional().default(true)
}).optional();

const RiskBasedBlockingSchema = z.object({
  enabled: z.boolean().optional().default(false),
  blockHighRiskFunctions: z.boolean().optional().default(false),
  blockSuspiciousContracts: z.boolean().optional().default(false),
  riskThreshold: z.number().min(0).max(1).optional().default(0.7),
  adaptiveThresholds: z.boolean().optional().default(false)
}).optional();

const MEVProtectionSchema = z.object({
  enabled: z.boolean().optional().default(false),
  blockSuspicious: z.boolean().optional().default(false),
  gasPriceMultiplierThreshold: z.number().positive().optional().default(5),
  monitoredSelectors: z.array(z.string()).optional().default([]),
  timeWindowAnalysis: z.boolean().optional().default(true)
}).optional();

const RpcAccessSchema = z.object({
  allowedOrigins: z.array(z.string()).optional().default([]),
  allowedCidrs: z.array(z.string()).optional().default([]),
  blockedCidrs: z.array(z.string()).optional().default([]),
  requireUserAgent: z.boolean().optional().default(false),
  allowedUserAgents: z.array(z.string()).optional().default([])
}).optional();

const AuditSchema = z.object({
  logBlockedRequests: z.boolean().optional().default(true),
  logAllowedHighValueTx: z.boolean().optional().default(true),
  storeBlockedSampleLimit: z.number().int().optional().default(10000),
  storePath: z.string().optional().default("baf:audits:blocked"),
  storeRetentionDays: z.number().int().optional().default(365),
  enableDetailedLogging: z.boolean().optional().default(false),
  compressLogs: z.boolean().optional().default(true)
}).optional();

const BackupPolicySchema = z.object({
  autoBackupBeforeUpdate: z.boolean().optional().default(true),
  maxBackupsToKeep: z.number().int().optional().default(50),
  backupsListKey: z.string().optional().default("baf:rules:backups"),
  encryptBackups: z.boolean().optional().default(false),
  compressionEnabled: z.boolean().optional().default(true)
}).optional();

const EnforcementSchema = z.object({
  mode: z.enum(["block", "monitor", "dry-run"]).optional().default("block"),
  fail_open: z.boolean().optional().default(false),
  notify_on_block: z.boolean().optional().default(true),
  block_response_code: z.number().int().optional().default(-32000),
  adaptiveEnforcement: z.boolean().optional().default(false)
}).optional();

// Esquemas de reglas heurísticas mejoradas - NodeGuard
const HeuristicRulesSchema = z.object({
  rateLimit: z.object({
    perIpTps: z.number().positive().optional().default(10),
    perAddressTps: z.number().positive().optional().default(5),
    perMethodTps: z.number().positive().optional().default(20),
    windowSeconds: z.number().positive().optional().default(60),
    burstMultiplier: z.number().positive().optional().default(2),
    adaptiveEnabled: z.boolean().optional().default(true)
  }).optional(),
  tokenBucket: z.object({
    capacity: z.number().positive().optional().default(100),
    refillPerSecond: z.number().positive().optional().default(50),
    burstCapacity: z.number().positive().optional().default(200),
    methodSpecific: z.boolean().optional().default(true)
  }).optional(),
  fingerprint: z.object({
    windowSeconds: z.number().positive().optional().default(300),
    maxRepeats: z.number().positive().optional().default(10),
    enableCrossBatch: z.boolean().optional().default(true),
    enableMLFingerprinting: z.boolean().optional().default(false)
  }).optional(),
  reputation: z.object({
    enabled: z.boolean().optional().default(true),
    minScore: z.number().min(0).max(100).optional().default(20),
    adaptiveScoring: z.boolean().optional().default(true),
    decayRate: z.number().positive().optional().default(0.1)
  }).optional(),
  behavioral: z.object({
    rapidFireDetection: z.boolean().optional().default(true),
    sybilDetection: z.boolean().optional().default(true),
    mevDetection: z.boolean().optional().default(false),
    contractAnalysis: z.boolean().optional().default(true)
  }).optional()
}).optional();

// Esquema Machine Learning - ajgc: experimental
const MLDetectionSchema = z.object({
  enabled: z.boolean().optional().default(false),
  threatDetection: z.object({
    confidence_threshold: z.number().min(0).max(1).optional().default(0.7),
    model_path: z.string().optional(),
    feature_count: z.number().positive().optional().default(15),
    update_interval_hours: z.number().positive().optional().default(24)
  }).optional(),
  anomalyDetection: z.object({
    confidence_threshold: z.number().min(0).max(1).optional().default(0.8),
    window_size: z.number().positive().optional().default(1000),
    learning_rate: z.number().positive().optional().default(0.01)
  }).optional()
}).optional();

// Esquema principal mejorado - ajgc: todo junto aquí

export const StaticRulesSchema = z.object({
  meta: z.object({
    version: z.string().optional().default("2.0.0"),
    generated_by: z.string().optional(),
    created_at: z.string().optional(),
    updated_at: z.string().optional(),
    description: z.string().optional(),
    author: z.string().optional(),
    environment: z.enum(["development", "staging", "production"]).optional()
  }).optional(),

  enforcement: EnforcementSchema,

  static: z.object({
    // Controles de métodos
    blockedMethods: z.array(z.string()).optional().default([]),
    allowedMethods: z.array(z.string()).optional().default([]),
    methodParamConstraints: z.record(MethodParamConstraintSchema).optional().default({}),

    // Controles de direcciones
    blockedAddresses: z.array(z.string()).optional().default([]),
    allowedAddresses: z.array(z.string()).optional().default([]),

    // Controles de contratos
    blockedContracts: z.array(z.string()).optional().default([]),
    allowedContracts: z.array(z.string()).optional().default([]),
    contractCreation: ContractCreationSchema,

    // Controles de function selector
    functionSelectorBlacklist: z.array(z.string()).optional().default([]),
    functionSelectorPatterns: z.array(z.string()).optional().default([]),
    contractFunctionBlacklist: z.record(z.array(z.string())).optional().default({}),
    functionSelectorAnalysis: FunctionSelectorSchema,

    // Características de seguridad avanzadas
    riskBasedBlocking: RiskBasedBlockingSchema,
    mevProtection: MEVProtectionSchema,

    // Controles de red y acceso
    rpcAccess: RpcAccessSchema,

    // Constraints de transacciones
    gasAndFeeConstraints: GasAndFeeConstraintsSchema,
    transactionConstraints: TransactionConstraintsSchema,
    payloadLimits: PayloadLimitsSchema,

    // Protección de firma y replay
    signaturePolicies: SignaturePoliciesSchema,
    replayProtection: ReplayProtectionSchema,

    // Listas de control de acceso
    whitelist: z.object({
      adminIps: z.array(z.string()).optional().default([]),
      serviceAccounts: z.array(z.string()).optional().default([]),
      trustedProxies: z.array(z.string()).optional().default([])
    }).optional().default({}),

    blacklist: z.object({
      countryCodes: z.array(z.string()).optional().default([]),
      torExitNodes: z.boolean().optional().default(false),
      vpnProviders: z.boolean().optional().default(false),
      knownMaliciousIps: z.array(z.string()).optional().default([])
    }).optional().default({}),

    // Detección de patrones
    suspiciousPatterns: z.object({
      regexes: z.array(z.string()).optional().default([]),
      highEntropyDataThreshold: z.number().min(0).max(1).optional().default(0.9),
      anomalyDetection: z.boolean().optional().default(false)
    }).optional(),

    // Controles de admin
    admin: z.object({
      adminTokenKeyRedis: z.string().optional().default("baf:admin:token:hash"),
      adminIpsRequired: z.boolean().optional().default(true),
      adminAllowedMethods: z.array(z.string()).optional().default([]),
      sessionTimeout: z.number().positive().optional().default(3600),
      mfaRequired: z.boolean().optional().default(false)
    }).optional(),

    // Auditoría y cumplimiento
    audit: AuditSchema,
    backupPolicy: BackupPolicySchema,

    // Versionado y metadatos
    versioning: z.record(z.string()).optional().default({})

  }).optional().default({}),

  // Reglas heurísticas
  heuristics: HeuristicRulesSchema,

  // Machine learning
  mlDetection: MLDetectionSchema

}).strict(); // Validación estricta

// Tipos de decisión mejorados - ajgc: para las respuestas del sistema

export type RuleDecisionKind = "allow" | "block" | "monitor";

export interface RuleDecision {
  decision: RuleDecisionKind;
  reason: string;
  rule?: string;
  ruleId?: string;
  confidence?: number; // 0 a 1, para matches difusos o basados en ML
  severity?: 'low' | 'medium' | 'high' | 'critical';
  metadata?: {
    timestamp?: number;
    processingTime?: number;
    ruleLayer?: 'static' | 'heuristic' | 'ml';
    threatLevel?: 'low' | 'medium' | 'high' | 'critical';
    [key: string]: any;
  };
}

// Contexto de evaluación de reglas mejorado
export interface RuleEvaluationContext {
  method: string;
  params?: unknown[];
  clientIp: string;
  requestId: string;
  timestamp: number;
  userAgent?: string;
  origin?: string;
  extracted?: {
    from?: string;
    to?: string;
    nonce?: number;
    gasPriceWei?: bigint;
    gasLimit?: bigint;
    payloadHash?: string;
    txType?: number;
    chainId?: number;
    functionSelector?: string;
    contractAddress?: string;
    isContractCall?: boolean;
    isContractCreation?: boolean;
    signature?: {
      v: number;
      r: string;
      s: string;
    };
    accessList?: Array<{
      address: string;
      storageKeys: string[];
    }>;
  };
  security?: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    suspiciousPatterns: string[];
    riskFactors: {
      unusualGasPrice: boolean;
      suspiciousContract: boolean;
      replayAttempt: boolean;
      sybilIndicator: boolean;
      mevPotential: boolean;
    };
    compliance: {
      eip155: boolean;
      eip2718: boolean;
      eip1559: boolean;
    };
  };
  analytics?: {
    gasPriceWei?: bigint;
    gasLimit?: bigint;
    payloadHash: string;
    complexity: number;
    processingTime?: number;
    cacheHit?: boolean;
  };
}

// Interfaces de estadísticas y validación - simplificadas
export interface RuleStatistics {
  evaluationCount: number;
  blockCount: number;
  allowCount: number;
  averageEvaluationTime: number;
}

export interface RuleValidationResult {
  success: boolean;
  errors?: string[];
  warnings?: string[];
  isValid?: boolean;
  metrics?: {
    staticRuleCount: number;
    heuristicRuleCount: number;
    mlRuleCount: number;
    totalComplexity: number;
  };
}

// Exportar tipos mejorados - ajgc: para uso en el resto del sistema

export type StaticRules = z.infer<typeof StaticRulesSchema>;
export type RuleConfig = StaticRules; // Alias semántico
export type RuleResult = RuleDecision; // Compatibilidad

// Type guards mejorados - ajgc: para verificar tipos de decisiones
export function isBlockDecision(decision: RuleDecision): decision is RuleDecision & { decision: 'block' } {
  return decision.decision === 'block';
}

export function isAllowDecision(decision: RuleDecision): decision is RuleDecision & { decision: 'allow' } {
  return decision.decision === 'allow';
}

export function isMonitorDecision(decision: RuleDecision): decision is RuleDecision & { decision: 'monitor' } {
  return decision.decision === 'monitor';
}

// Validador de reglas simplificado
export class RuleValidator {
  static validateRules(rules: any): RuleValidationResult {
    try {
      const parsed = StaticRulesSchema.parse(rules);
      return {
        success: true,
        errors: [],
        warnings: []
      };
    } catch (error) {
      return {
        success: false,
        errors: [(error as Error).message],
        warnings: []
      };
    }
  }
}

export default StaticRulesSchema;
