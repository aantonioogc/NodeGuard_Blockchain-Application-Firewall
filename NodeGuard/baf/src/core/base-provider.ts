// Provider base para NodeGuard - TFG BAF
// ajgc (Antonio José González Castillo)
import * as crypto from "crypto";
import { ethers } from "ethers";
import type { Logger } from "winston";
import {
  JsonRpcValidator,
  type ValidationResult,
  type ValidationError,
  type ValidationContext
} from "../validation/indexVal";
import { type ValidatedRequest } from "../validation/types";
import { jsonRpcRequestSchema } from "../validation/schemas/json-rpc";
import { extractTxAddresses, extractRawTxFields, parseEIP2718Transaction } from "../utils/transaction-utils";
import { z } from "zod";

type JsonRpcRequest = z.infer<typeof jsonRpcRequestSchema>;

/**
 * Interfaz de análisis de transacciones
 */
export interface EnhancedEvalExtraction {
  from?: string;
  to?: string;
  nonce?: number;
  gasPriceWei?: bigint;
  maxFeePerGas?: bigint; // EIP-1559
  maxPriorityFeePerGas?: bigint; // EIP-1559
  gasLimit?: bigint;
  value?: bigint;
  data?: string;
  chainId?: number;
  txType?: number; // EIP-2718
  payloadHash?: string;
  signature?: {
    v: number;
    r: string;
    s: string;
  };
  accessList?: Array<{
    address: string;
    storageKeys: string[];
  }>;
  functionSelector?: string;
  contractAddress?: string;
  isContractCall: boolean;
  isContractCreation: boolean;
  estimatedComplexity: 'low' | 'medium' | 'high';
}

/**
 * Contexto de request con análisis de seguridad
 */
export interface EnhancedReqContext {
  // Campos JSON-RPC básicos
  jsonrpc: "2.0";
  method: string;
  params?: unknown[];
  id: JsonRpcRequest["id"];
  
  // Información del cliente
  clientIp: string;
  clientIpMasked: string;
  clientFingerprint?: string;
  
  // Metadata del request
  reqId: string;
  timestamp: number;
  requestSize: number;
  
  // Análisis de transacción
  extracted: EnhancedEvalExtraction;
  
  // Contexto de seguridad
  security: {
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
  
  // Analytics
  analytics: {
    gasPriceWei?: bigint;
    gasLimit?: bigint;
    payloadHash: string;
    complexity: number;
    processingTime?: number;
    cacheHit?: boolean;
  };
}

/**
 * Provider base del BAF
 */
export abstract class BaseProvider {
  protected readonly logger: Logger;
  private readonly jsonRpcValidator: JsonRpcValidator;
  private readonly payloadCache = new Map<string, { 
    result: any; 
    timestamp: number; 
    hits: number; 
  }>();
  private readonly suspiciousPatterns = new Map<string, number>();
  
  constructor(logger: Logger) {
    this.logger = logger;
    this.jsonRpcValidator = new JsonRpcValidator();
    this.setupPeriodicCleanup();
  }

  /**
   * Generar ID único para request
   */
  protected createReqId(): string {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString('hex');
    const counter = Math.floor(Math.random() * 1000).toString(36);
    return `${timestamp}-${random}-${counter}`;
  }

  /**
   * Hash del payload con salt opcional
   */
  protected hashPayload(payload: unknown, salt?: string): string {
    const raw = JSON.stringify(
      payload,
      typeof payload === 'object' && payload !== null ? Object.keys(payload as object).sort() : undefined
    );
    const data = salt ? raw + salt : raw;
    return crypto.createHash("sha256").update(data).digest("hex");
  }

  /**
   * Enmascarar IP para privacidad (soporta IPv6)
   */
  protected maskIp(ip: string): string {
    if (!ip || ip === 'unknown') return 'unknown';
    
    const cleanIp = ip.toString().trim();
    
    // Manejo de IPv6
    if (cleanIp.includes(':')) {
      if (cleanIp.startsWith('::ffff:')) {
        // IPv4-mapped IPv6
        const ipv4 = cleanIp.substring(7);
        return this.maskIpv4(ipv4);
      }
      // IPv6 puro - mostrar primeros 32 bits
      const parts = cleanIp.split(':');
      return parts.slice(0, 2).join(':') + '::***';
    }
    
    return this.maskIpv4(cleanIp);
  }

  private maskIpv4(ip: string): string {
    const parts = ip.split('.');
    if (parts.length === 4) {
      // ajgc: enmascarar último octeto por privacidad
      return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
    }
    return ip.substring(0, Math.min(12, ip.length)) + '...';
  }

  /**
   * Generar fingerprint del cliente para tracking
   */
  protected generateClientFingerprint(ip: string, userAgent?: string, additionalData?: any): string {
    const data = JSON.stringify({
      ip: this.maskIp(ip),
      userAgent: userAgent || 'unknown',
      additional: additionalData || {}
    });
    return crypto.createHash('md5').update(data).digest('hex').substring(0, 16);
  }

  /**
   * Parsear y extraer datos de un solo request con análisis de seguridad
   */
  protected parseAndExtractSingle(payload: unknown, clientIp: string, userAgent?: string): EnhancedReqContext {
    const startTime = Date.now();
    
    try {
      // Validar estructura JSON-RPC básica
      const validationResult = this.jsonRpcValidator.validateSingle(payload);
      if (!validationResult.success || !validationResult.data) {
        throw new Error(validationResult.errors?.[0]?.message || 'Request JSON-RPC inválido');
      }
      const req = validationResult.data.data as JsonRpcRequest;
      
      // Generar metadata del request
      const reqId = this.createReqId();
      const timestamp = Date.now();
      const requestSize = JSON.stringify(payload).length;
      const clientFingerprint = this.generateClientFingerprint(clientIp, userAgent);
      
      // Extracción de transacción mejorada
      const extracted = this.performEnhancedExtraction(req);
      
      // Análisis de seguridad
      const security = this.performSecurityAnalysis(req, extracted, clientIp);
      
      // Cálculo de analytics
      const analytics = this.computeAnalytics(req, extracted, startTime);
      
      // Verificar patrones sospechosos
      this.updateSuspiciousPatterns(clientIp, req.method, extracted);
      
      const context: EnhancedReqContext = {
        jsonrpc: req.jsonrpc as "2.0",
        method: req.method,
        params: Array.isArray(req.params) ? req.params : undefined,
        id: req.id,
        clientIp,
        clientIpMasked: this.maskIp(clientIp),
        clientFingerprint,
        reqId,
        timestamp,
        requestSize,
        extracted,
        security,
        analytics
      };

      this.logger.debug('Request parseado y analizado', {
        reqId,
        method: req.method,
        threatLevel: security.threatLevel,
        processingTime: Date.now() - startTime
      });

      return context;

    } catch (error) {
      const err = error as Error;
      this.logger.error('Error parseando request', {
        error: err.message,
        clientIp: this.maskIp(clientIp),
        payloadSize: JSON.stringify(payload).length
      });
      throw err;
    }
  }

  /**
   * Procesamiento de batch con análisis cross-request
   */
  protected parseAndExtractBatch(payload: unknown, clientIp: string, userAgent?: string): EnhancedReqContext[] {
    const startTime = Date.now();
    
    try {
      // Intentar validar como batch primero, luego como single
      let reqs: JsonRpcRequest[];
      
      if (Array.isArray(payload)) {
        // Manejar batch request
        const batchResult = this.jsonRpcValidator.validateBatch(payload);
        if (!batchResult.success || !batchResult.data) {
          throw new Error(batchResult.errors?.[0]?.message || 'Batch JSON-RPC inválido');
        }
        reqs = batchResult.data.map((validatedReq: ValidatedRequest) => validatedReq.data as JsonRpcRequest);
      } else {
        // Manejar single request
        const singleResult = this.jsonRpcValidator.validateSingle(payload);
        if (!singleResult.success || !singleResult.data) {
          throw new Error(singleResult.errors?.[0]?.message || 'Request JSON-RPC inválido');
        }
        reqs = [singleResult.data.data as JsonRpcRequest];
      }
      
      const contexts = reqs.map((req: JsonRpcRequest) => this.parseAndExtractSingle(req, clientIp, userAgent));
      
      // Análisis cross-request para batch
      this.performBatchAnalysis(contexts);
      
      this.logger.debug('Batch parseado y analizado', {
        batchSize: contexts.length,
        processingTime: Date.now() - startTime,
        clientIp: this.maskIp(clientIp)
      });

      return contexts;

    } catch (error) {
      const err = error as Error;
      this.logger.error('Error parseando batch request', {
        error: err.message,
        clientIp: this.maskIp(clientIp)
      });
      throw err;
    }
  }

  /**
   * Extracción avanzada de campos de transacción con soporte EIP
   */
  private performEnhancedExtraction(req: JsonRpcRequest): EnhancedEvalExtraction {
    const extraction: EnhancedEvalExtraction = {
      isContractCall: false,
      isContractCreation: false,
      estimatedComplexity: 'low'
    };

    try {
      // Extraer direcciones básicas
      const paramsArray = Array.isArray(req.params) ? req.params : undefined;
      const { from, to } = extractTxAddresses(req.method, paramsArray);
      extraction.from = from;
      extraction.to = to;

      // Manejar métodos de transacción raw
      if (req.method.toLowerCase() === "eth_sendrawtransaction" && req.params && Array.isArray(req.params) && typeof req.params[0] === "string") {
        const rawTx = req.params[0] as string;
        
        // Intentar parsing EIP-2718 primero
        try {
          const eip2718Fields = parseEIP2718Transaction(rawTx);
          if (eip2718Fields) {
            Object.assign(extraction, eip2718Fields);
          }
        } catch {
          // Fallback a parsing legacy
          const legacyFields = extractRawTxFields(rawTx);
          Object.assign(extraction, legacyFields);
        }
      }

      // Manejar otros métodos de transacción
      if (req.method.toLowerCase().startsWith("eth_") && Array.isArray(req.params)) {
        this.extractFromStandardMethods(req, extraction);
      }

      // Analizar interacción con contratos
      if (extraction.to) {
        if (extraction.to === '0x' || extraction.to === '') {
          extraction.isContractCreation = true;
          extraction.estimatedComplexity = 'high';
        } else {
          extraction.isContractCall = true;
          extraction.contractAddress = extraction.to;
        }
      }

      // Extraer selector de función para calls de contrato
      if (extraction.data && extraction.data.length >= 10) {
        extraction.functionSelector = extraction.data.substring(0, 10);
      }

      // ajgc: estimar complejidad de la transacción
      extraction.estimatedComplexity = this.estimateTransactionComplexity(extraction);

    } catch (error) {
      this.logger.warn('Error en extracción avanzada', { 
        error: (error as Error).message,
        method: req.method 
      });
    }

    return extraction;
  }

  /**
   * Extraer campos de métodos eth_* estándar
   */
  private extractFromStandardMethods(req: JsonRpcRequest, extraction: EnhancedEvalExtraction): void {
    if (!req.params || !Array.isArray(req.params)) return;

    const method = req.method.toLowerCase();
    
    switch (method) {
      case 'eth_sendtransaction':
        if (req.params[0] && typeof req.params[0] === 'object') {
          const txParams = req.params[0] as any;
          extraction.from = txParams.from;
          extraction.to = txParams.to;
          extraction.value = txParams.value ? BigInt(txParams.value) : undefined;
          extraction.gasLimit = txParams.gas ? BigInt(txParams.gas) : undefined;
          extraction.gasPriceWei = txParams.gasPrice ? BigInt(txParams.gasPrice) : undefined;
          extraction.maxFeePerGas = txParams.maxFeePerGas ? BigInt(txParams.maxFeePerGas) : undefined;
          extraction.maxPriorityFeePerGas = txParams.maxPriorityFeePerGas ? BigInt(txParams.maxPriorityFeePerGas) : undefined;
          extraction.data = txParams.data;
          extraction.nonce = txParams.nonce ? parseInt(txParams.nonce, 16) : undefined;
        }
        break;
      
      case 'eth_call':
      case 'eth_estimategas':
        if (req.params[0] && typeof req.params[0] === 'object') {
          const callParams = req.params[0] as any;
          extraction.from = callParams.from;
          extraction.to = callParams.to;
          extraction.data = callParams.data;
          extraction.value = callParams.value ? BigInt(callParams.value) : undefined;
        }
        break;
    }
  }

  /**
   * Análisis completo de seguridad
   */
  private performSecurityAnalysis(req: JsonRpcRequest, extracted: EnhancedEvalExtraction, clientIp: string): EnhancedReqContext['security'] {
    const suspiciousPatterns: string[] = [];
    const riskFactors = {
      unusualGasPrice: false,
      suspiciousContract: false,
      replayAttempt: false,
      sybilIndicator: false,
      mevPotential: false
    };
    
    const compliance = {
      eip155: true,
      eip2718: true,
      eip1559: true
    };

    try {
      // Análisis de gas price
      if (extracted.gasPriceWei) {
        const gasPrice = Number(extracted.gasPriceWei);
        const avgGasPrice = Number(process.env.BAF_AVG_GAS_PRICE || 20000000000); // 20 gwei
        
        if (gasPrice > avgGasPrice * 10) {
          suspiciousPatterns.push('excessive_gas_price');
          riskFactors.unusualGasPrice = true;
        } else if (gasPrice < avgGasPrice * 0.1) {
          suspiciousPatterns.push('extremely_low_gas_price');
          riskFactors.unusualGasPrice = true;
        }
      }

      // Verificar compliance EIP-1559
      if (extracted.txType === 2) {
        if (!extracted.maxFeePerGas || !extracted.maxPriorityFeePerGas) {
          suspiciousPatterns.push('invalid_eip1559_fields');
          compliance.eip1559 = false;
        }
      }

      // Análisis de interacción con contratos
      if (extracted.contractAddress) {
        const contractRiskScore = this.assessContractRisk(extracted.contractAddress, extracted.functionSelector);
        if (contractRiskScore > 0.7) {
          suspiciousPatterns.push('high_risk_contract');
          riskFactors.suspiciousContract = true;
        }
      }

      // Detección de patrones MEV
      if (this.detectMEVPattern(extracted, req.method)) {
        suspiciousPatterns.push('potential_mev_transaction');
        riskFactors.mevPotential = true;
      }

      // Indicadores de ataque Sybil
      if (this.detectSybilPattern(clientIp, extracted)) {
        suspiciousPatterns.push('sybil_indicator');
        riskFactors.sybilIndicator = true;
      }

      // Detección de ataques replay
      if (this.detectReplayAttempt(extracted)) {
        suspiciousPatterns.push('potential_replay_attack');
        riskFactors.replayAttempt = true;
        compliance.eip155 = false;
      }

    } catch (error) {
      this.logger.warn('Análisis de seguridad falló', { error: (error as Error).message });
    }

    // Determinar nivel de amenaza
    const threatLevel = this.calculateThreatLevel(suspiciousPatterns, riskFactors);

    return {
      threatLevel,
      suspiciousPatterns,
      riskFactors,
      compliance
    };
  }

  /**
   * Estimar complejidad de transacción
   */
  private estimateTransactionComplexity(extracted: EnhancedEvalExtraction): 'low' | 'medium' | 'high' {
    let score = 0;
    
    if (extracted.isContractCreation) score += 3;
    if (extracted.isContractCall) score += 1;
    if (extracted.data && extracted.data.length > 1000) score += 2;
    if (extracted.gasLimit && extracted.gasLimit > BigInt(1000000)) score += 2;
    if (extracted.accessList && extracted.accessList.length > 0) score += 1;
    
    if (score >= 5) return 'high';
    if (score >= 2) return 'medium';
    return 'low';
  }

  /**
   * Calcular nivel general de amenaza
   */
  private calculateThreatLevel(patterns: string[], risks: any): 'low' | 'medium' | 'high' | 'critical' {
    const riskCount = Object.values(risks).filter(Boolean).length;
    const patternCount = patterns.length;
    
    if (riskCount >= 3 || patternCount >= 4) return 'critical';
    if (riskCount >= 2 || patternCount >= 3) return 'high';
    if (riskCount >= 1 || patternCount >= 2) return 'medium';
    return 'low';
  }

  /**
   * Evaluar riesgo de contrato basado en dirección y selector de función
   */
  private assessContractRisk(contractAddress: string, functionSelector?: string): number {
    // ajgc: TODO - integrar con bases de datos de riesgo externas en producción
    let riskScore = 0;
    
    // Verificar contra contratos conocidos de riesgo
    const riskyContracts = (process.env.BAF_RISKY_CONTRACTS || '').split(',');
    if (riskyContracts.includes(contractAddress.toLowerCase())) {
      riskScore += 0.8;
    }
    
    // Verificar patrones de selectores de función
    if (functionSelector) {
      const riskySelectors = ['0xa9059cbb', '0x23b872dd']; // funciones transfer
      if (riskySelectors.includes(functionSelector.toLowerCase())) {
        riskScore += 0.2;
      }
    }
    
    return Math.min(riskScore, 1);
  }

  /**
   * Detectar patrones de transacción MEV
   */
  private detectMEVPattern(extracted: EnhancedEvalExtraction, method: string): boolean {
    // Gas price alto con selectores de función específicos
    if (extracted.gasPriceWei && extracted.functionSelector) {
      const gasPrice = Number(extracted.gasPriceWei);
      const avgGasPrice = Number(process.env.BAF_AVG_GAS_PRICE || 20000000000);
      
      if (gasPrice > avgGasPrice * 5) {
        const mevSelectors = ['0x38ed1739', '0x7ff36ab5']; // swapExactTokensForTokens, etc
        return mevSelectors.includes(extracted.functionSelector.toLowerCase());
      }
    }
    
    return false;
  }

  /**
   * Detectar patrones de ataque Sybil
   */
  private detectSybilPattern(clientIp: string, extracted: EnhancedEvalExtraction): boolean {
    // Verificar transacciones similares de la misma IP en corto tiempo
    const recentPatterns = this.suspiciousPatterns.get(clientIp) || 0;
    return recentPatterns > 10; // Threshold configurable
  }

  /**
   * Detectar intentos de ataque replay
   */
  private detectReplayAttempt(extracted: EnhancedEvalExtraction): boolean {
    // Verificar chain ID ausente o problemas con valor v
    if (!extracted.chainId) return true;
    
    if (extracted.signature) {
      const { v } = extracted.signature;
      // EIP-155: v debería ser chainId * 2 + 35/36
      const expectedV = extracted.chainId * 2 + 35;
      if (v !== expectedV && v !== expectedV + 1) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Computar datos de analytics
   */
  private computeAnalytics(req: JsonRpcRequest, extracted: EnhancedEvalExtraction, startTime: number): EnhancedReqContext['analytics'] {
    const payloadHash = this.hashPayload(req);
    
    // Verificar cache para requests duplicados
    const cached = this.payloadCache.get(payloadHash);
    let cacheHit = false;
    
    if (cached) {
      cached.hits++;
      cacheHit = true;
    }
    
    // Calcular puntuación de complejidad
    let complexity = 1;
    if (extracted.estimatedComplexity === 'medium') complexity = 2;
    if (extracted.estimatedComplexity === 'high') complexity = 3;
    
    return {
      gasPriceWei: extracted.gasPriceWei,
      gasLimit: extracted.gasLimit,
      payloadHash,
      complexity,
      processingTime: Date.now() - startTime,
      cacheHit
    };
  }

  /**
   * Análisis cross-request para batch
   */
  private performBatchAnalysis(contexts: EnhancedReqContext[]): void {
    if (contexts.length <= 1) return;
    
    // Analizar patrones de ataque específicos de batch
    const methods = contexts.map(ctx => ctx.method);
    const addresses = contexts.map(ctx => ctx.extracted.from).filter(Boolean);
    
    // Verificar patrones sospechosos de batch
    if (new Set(methods).size === 1 && methods.length > 50) {
      // Mismo método repetido muchas veces - posible spam
      contexts.forEach(ctx => {
        ctx.security.suspiciousPatterns.push('batch_spam_pattern');
        if (ctx.security.threatLevel === 'low') {
          ctx.security.threatLevel = 'medium';
        }
      });
    }
    
    // Verificar diversidad de direcciones (posible Sybil)
    if (new Set(addresses).size === addresses.length && addresses.length > 20) {
      contexts.forEach(ctx => {
        ctx.security.suspiciousPatterns.push('sybil_batch_pattern');
        ctx.security.riskFactors.sybilIndicator = true;
      });
    }
  }

  /**
   * Actualizar tracking de patrones sospechosos
   */
  private updateSuspiciousPatterns(clientIp: string, method: string, extracted: EnhancedEvalExtraction): void {
    const current = this.suspiciousPatterns.get(clientIp) || 0;
    
    // Incrementar contador por varios comportamientos sospechosos
    let increment = 0;
    if (extracted.estimatedComplexity === 'high') increment += 1;
    if (extracted.isContractCreation) increment += 2;
    if (method === 'eth_sendRawTransaction') increment += 1;
    
    if (increment > 0) {
      this.suspiciousPatterns.set(clientIp, current + increment);
    }
  }

  /**
   * Configurar limpieza periódica de caches y patrones
   */
  private setupPeriodicCleanup(): void {
    const cleanupInterval = Number(process.env.BAF_CLEANUP_INTERVAL || 300000); // 5 minutos
    
    setInterval(() => {
      const now = Date.now();
      const cacheExpiry = Number(process.env.BAF_CACHE_EXPIRY || 600000); // 10 minutos
      
      // Limpiar cache de payload
      for (const [key, value] of Array.from(this.payloadCache.entries())) {
        if (now - value.timestamp > cacheExpiry) {
          this.payloadCache.delete(key);
        }
      }
      
      // Limpiar patrones sospechosos (deben decaer con el tiempo)
      for (const [key, value] of Array.from(this.suspiciousPatterns.entries())) {
        if (value > 0) {
          this.suspiciousPatterns.set(key, Math.max(0, value - 1));
        }
      }
      
      this.logger.debug('Limpieza periódica completada', {
        cacheSize: this.payloadCache.size,
        patternTracking: this.suspiciousPatterns.size
      });
      
    }, cleanupInterval);
  }

  // Métodos abstractos para implementaciones
  abstract send(payload: unknown): Promise<unknown>;
  abstract isHealthy(): boolean;
  abstract cleanup(): Promise<void>;
}
