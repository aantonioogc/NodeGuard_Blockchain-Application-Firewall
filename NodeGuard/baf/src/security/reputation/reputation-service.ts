// src/reputation/reputation-service.ts
// ajgc: sistema de reputación NodeGuard

/**
 * Sistema de reputación con ML e inteligencia de amenazas
 * 
 * Características:
 * - Puntuación de reputación multidimensional
 * - Predicción de amenazas basada en ML
 * - Correlación geográfica y temporal
 * - Integración de feeds de inteligencia de amenazas
 * - Algoritmos de decaimiento adaptativo
 * - Correlación y análisis de incidentes
 * - Actualizaciones de reputación en tiempo real
 * - Seguimiento de reputación cross-entity
 * - Análisis de patrones comportamentales
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/logger';
import { EventBus } from '../../events/event-bus';
import redis from '../../redis/redis-connection';


export type EntityType = 'ip' | 'address' | 'contract' | 'domain' | 'user_agent';

export interface ReputationConfig {
  scoring: {
    initialScore: number;
    minScore: number;
    maxScore: number;
    decayEnabled: boolean;
    decayRate: number;
    decayInterval: number;
  };
  thresholds: {
    trustworthy: number;
    neutral: number;
    suspicious: number;
    malicious: number;
    blocked: number;
  };
  ml: {
    enabled: boolean;
    modelPath?: string;
    confidenceThreshold: number;
    retrainInterval: number;
  };
  geolocation: {
    enabled: boolean;
    suspiciousCountries: string[];
    blockedCountries: string[];
    vpnDetection: boolean;
  };
  incidents: {
    trackingEnabled: boolean;
    maxIncidentsPerEntity: number;
    incidentTtl: number;
    severityWeights: { [key: string]: number };
  };
  realtime: {
    enabled: boolean;
    updateInterval: number;
    batchSize: number;
  };
}

export interface ReputationScore {
  entity: string;
  type: EntityType;
  score: number;
  level: 'trustworthy' | 'neutral' | 'suspicious' | 'malicious' | 'blocked';
  confidence: number;
  lastUpdated: number;
  factors: {
    baseScore: number;
    incidentScore: number;
    behaviorScore: number;
    geoScore: number;
    temporalScore: number;
    mlScore?: number;
  };
  metadata: {
    totalIncidents: number;
    lastIncident?: number;
    geoLocation?: string;
    tags: string[];
    sources: string[];
  };
}

export interface SecurityIncident {
  id: string;
  entityId: string;
  entityType: EntityType;
  type: 'attack' | 'violation' | 'suspicious_behavior' | 'policy_breach' | 'anomaly';
  severity: number; // 1-100
  timestamp: number;
  description: string;
  details: {
    method?: string;
    rule?: string;
    pattern?: string;
    evidence?: any;
  };
  source: string;
  correlationId?: string;
}

export interface ThreatIntelligence {
  entityId: string;
  entityType: EntityType;
  threatType: string;
  severity: number;
  confidence: number;
  source: string;
  firstSeen: number;
  lastSeen: number;
  indicators: string[];
  mitigations: string[];
}

/**
 * Servicio de reputación mejorado - ajgc
 */
export class ReputationService extends EventEmitter {
  private readonly config: ReputationConfig;
  private readonly eventBus?: EventBus;
  
  // Caché y rendimiento
  private reputationCache = new Map<string, ReputationScore>();
  private incidentBuffer = new Map<string, SecurityIncident[]>();
  private threatIntelCache = new Map<string, ThreatIntelligence>();
  
  // ML y análisis
  private behaviorProfiles = new Map<string, any>();
  private geoLocationCache = new Map<string, string>();
  
  // Métricas de rendimiento
  private metrics = {
    totalQueries: 0,
    cacheHits: 0,
    incidentsRecorded: 0,
    reputationUpdates: 0,
    mlPredictions: 0,
    threatIntelHits: 0
  };

  constructor(
    config: Partial<ReputationConfig> = {},
    eventBus?: EventBus
  ) {
    super();
    
    this.config = {
      scoring: {
        initialScore: config.scoring?.initialScore ?? 50,
        minScore: config.scoring?.minScore ?? 0,
        maxScore: config.scoring?.maxScore ?? 100,
        decayEnabled: config.scoring?.decayEnabled ?? true,
        decayRate: config.scoring?.decayRate ?? 0.1,
        decayInterval: config.scoring?.decayInterval ?? 3600000 // 1 hora
      },
      thresholds: {
        trustworthy: config.thresholds?.trustworthy ?? 80,
        neutral: config.thresholds?.neutral ?? 50,
        suspicious: config.thresholds?.suspicious ?? 30,
        malicious: config.thresholds?.malicious ?? 15,
        blocked: config.thresholds?.blocked ?? 5
      },
      ml: {
        enabled: config.ml?.enabled ?? false,
        modelPath: config.ml?.modelPath,
        confidenceThreshold: config.ml?.confidenceThreshold ?? 0.7,
        retrainInterval: config.ml?.retrainInterval ?? 86400000 // 24 horas
      },
      geolocation: {
        enabled: config.geolocation?.enabled ?? false,
        suspiciousCountries: config.geolocation?.suspiciousCountries ?? [],
        blockedCountries: config.geolocation?.blockedCountries ?? [],
        vpnDetection: config.geolocation?.vpnDetection ?? false
      },
      incidents: {
        trackingEnabled: config.incidents?.trackingEnabled ?? true,
        maxIncidentsPerEntity: config.incidents?.maxIncidentsPerEntity ?? 100,
        incidentTtl: config.incidents?.incidentTtl ?? 2592000000, // 30 días
        severityWeights: config.incidents?.severityWeights ?? {
          'low': 1,
          'medium': 3,
          'high': 10,
          'critical': 25
        }
      },
      realtime: {
        enabled: config.realtime?.enabled ?? true,
        updateInterval: config.realtime?.updateInterval ?? 60000, // 1 minuto
        batchSize: config.realtime?.batchSize ?? 100
      }
    };
    
    this.eventBus = eventBus;
    
    this.setupPeriodicProcesses();
    this.setupEventHandlers();
    
    logger.info('Servicio de reputación NodeGuard creado', {
      mlEnabled: this.config.ml.enabled,
      geoEnabled: this.config.geolocation.enabled,
      realtimeEnabled: this.config.realtime.enabled
    });
  }

  /**
   * Inicializar servicio de reputación - ajgc
   */
  async initialize(): Promise<void> {
    try {
      logger.info('Inicializando servicio de reputación NodeGuard...');
      
      // Cargar feeds de inteligencia de amenazas
      await this.loadThreatIntelligence();
      
      // Inicializar modelo ML si está habilitado - de locos este sistema
      if (this.config.ml.enabled) {
        await this.initializeMLModel();
      }
      
      // Cargar datos de reputación existentes
      await this.loadExistingReputations();
      
      logger.info('Servicio de reputación NodeGuard inicializado correctamente');
      
    } catch (error) {
      const err = error as Error;
      logger.error('Fallo al inicializar servicio de reputación', { 
        error: err,
        stack: err.stack 
      });
      throw err;
    }
  }

  /**
   * Get comprehensive reputation score
   */
  async getScore(entityType: EntityType, entityId: string): Promise<number> {
    this.metrics.totalQueries++;
    
    try {
      const reputation = await this.getReputationDetails(entityType, entityId);
      return reputation.score;
    } catch (error) {
      logger.warn('Failed to get reputation score', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
      return this.config.scoring.initialScore;
    }
  }

  /**
   * Get detailed reputation information
   */
  async getReputationDetails(entityType: EntityType, entityId: string): Promise<ReputationScore> {
    const cacheKey = `${entityType}:${entityId}`;
    
    // Check cache first
    const cached = this.reputationCache.get(cacheKey);
    if (cached && (Date.now() - cached.lastUpdated) < 300000) { // 5 minutes cache
      this.metrics.cacheHits++;
      return cached;
    }

    try {
      // Load from Redis or create new
      const reputation = await this.loadOrCreateReputation(entityType, entityId);
      
      // Update with real-time factors
      await this.updateReputationFactors(reputation);
      
      // Apply ML predictions if enabled
      if (this.config.ml.enabled) {
        await this.applyMLScore(reputation);
      }
      
      // Cache the result
      this.reputationCache.set(cacheKey, reputation);
      
      return reputation;
      
    } catch (error) {
      logger.error('Failed to get reputation details', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
      
      // Return default reputation
      return this.createDefaultReputation(entityType, entityId);
    }
  }

  /**
   * Record security incident
   */
  async recordIncident(
    entityId: string, 
    incident: Omit<SecurityIncident, 'id' | 'entityId' | 'timestamp'>
  ): Promise<void> {
    const fullIncident: SecurityIncident = {
      id: this.generateIncidentId(),
      entityId,
      timestamp: Date.now(),
      ...incident
    };
    
    try {
      this.metrics.incidentsRecorded++;
      
      // Store incident
      if (this.config.incidents.trackingEnabled) {
        await this.storeIncident(fullIncident);
      }
      
      // Update reputation immediately
      await this.updateScoreFromIncident(fullIncident);
      
      // Emit event
      this.emitIncidentEvent(fullIncident);
      
      // Check for threat patterns
      await this.analyzeIncidentPatterns(fullIncident);
      
      logger.debug('Security incident recorded', {
        incidentId: fullIncident.id,
        entityType: fullIncident.entityType,
        entityId: this.maskEntity(fullIncident.entityId),
        type: fullIncident.type,
        severity: fullIncident.severity
      });
      
    } catch (error) {
      logger.error('Failed to record incident', {
        error: error as Error,
        entityId: this.maskEntity(entityId),
        incidentType: incident.type
      });
    }
  }

  /**
   * Record positive interaction (increases reputation)
   */
  async recordPositiveInteraction(
    entityType: EntityType,
    entityId: string,
    weight: number = 1
  ): Promise<void> {
    try {
      const reputation = await this.getReputationDetails(entityType, entityId);
      
      // Calculate positive score adjustment
      const adjustment = Math.min(weight * 2, 10); // Max +10 per interaction
      const newScore = Math.min(reputation.score + adjustment, this.config.scoring.maxScore);
      
      // Update reputation
      await this.updateScore(entityType, entityId, newScore, 'positive_interaction');
      
    } catch (error) {
      logger.warn('Failed to record positive interaction', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
    }
  }

  /**
   * Check if entity is blacklisted
   */
  async isBlacklisted(entityType: EntityType, entityId: string): Promise<boolean> {
    try {
      const reputation = await this.getReputationDetails(entityType, entityId);
      return reputation.score <= this.config.thresholds.blocked;
    } catch (error) {
      logger.warn('Failed to check blacklist status', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
      return false; // Fail safe
    }
  }

  /**
   * Get threat level based on reputation
   */
  async getThreatLevel(entityType: EntityType, entityId: string): Promise<'low' | 'medium' | 'high' | 'critical'> {
    try {
      const reputation = await this.getReputationDetails(entityType, entityId);
      
      if (reputation.score >= this.config.thresholds.trustworthy) return 'low';
      if (reputation.score >= this.config.thresholds.suspicious) return 'medium';
      if (reputation.score >= this.config.thresholds.malicious) return 'high';
      return 'critical';
      
    } catch (error) {
      logger.warn('Failed to get threat level', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
      return 'medium'; // Fail safe with moderate threat level
    }
  }

  /**
   * Advanced reputation analysis methods
   */
  
  private async loadOrCreateReputation(entityType: EntityType, entityId: string): Promise<ReputationScore> {
    const key = `baf:reputation:${entityType}:${entityId}`;
    
    try {
      const data = await redis.hgetall(key);
      
      if (Object.keys(data).length === 0) {
        // Create new reputation
        return this.createDefaultReputation(entityType, entityId);
      }
      
      // Parse existing reputation
      return {
        entity: entityId,
        type: entityType,
        score: parseFloat(data.score || '50'),
        level: this.calculateThreatLevel(parseFloat(data.score || '50')),
        confidence: parseFloat(data.confidence || '0.5'),
        lastUpdated: parseInt(data.lastUpdated || '0'),
        factors: JSON.parse(data.factors || '{}'),
        metadata: JSON.parse(data.metadata || '{}')
      };
      
    } catch (error) {
      logger.warn('Failed to load reputation, creating default', {
        error: error as Error,
        entityType,
        entityId: this.maskEntity(entityId)
      });
      return this.createDefaultReputation(entityType, entityId);
    }
  }
  
  private createDefaultReputation(entityType: EntityType, entityId: string): ReputationScore {
    const score = this.config.scoring.initialScore;
    
    return {
      entity: entityId,
      type: entityType,
      score,
      level: this.calculateThreatLevel(score),
      confidence: 0.3, // Low confidence for new entities
      lastUpdated: Date.now(),
      factors: {
        baseScore: score,
        incidentScore: 0,
        behaviorScore: 0,
        geoScore: 0,
        temporalScore: 0
      },
      metadata: {
        totalIncidents: 0,
        tags: [],
        sources: ['initial']
      }
    };
  }
  
  private async updateReputationFactors(reputation: ReputationScore): Promise<void> {
    // Update incident-based factors
    await this.updateIncidentFactors(reputation);
    
    // Update behavioral factors
    await this.updateBehavioralFactors(reputation);
    
    // Update geolocation factors
    if (this.config.geolocation.enabled) {
      await this.updateGeolocationFactors(reputation);
    }
    
    // Update temporal factors
    await this.updateTemporalFactors(reputation);
    
    // Calculate final score
    reputation.score = this.calculateFinalScore(reputation.factors);
    reputation.level = this.calculateThreatLevel(reputation.score);
    reputation.lastUpdated = Date.now();
  }
  
  private async updateIncidentFactors(reputation: ReputationScore): Promise<void> {
    try {
      const incidents = await this.getRecentIncidents(reputation.entity, reputation.type);
      
      let incidentScore = 0;
      let totalSeverity = 0;
      
      for (const incident of incidents) {
        const weight = this.config.incidents.severityWeights[this.getSeverityLevel(incident.severity)] || 1;
        const age = Date.now() - incident.timestamp;
        const ageDecay = Math.exp(-age / (30 * 24 * 60 * 60 * 1000)); // 30 day decay
        
        totalSeverity += incident.severity * weight * ageDecay;
      }
      
      incidentScore = Math.min(totalSeverity, 50); // Cap at 50 points
      reputation.factors.incidentScore = -incidentScore; // Negative impact
      reputation.metadata.totalIncidents = incidents.length;
      
      if (incidents.length > 0) {
        reputation.metadata.lastIncident = Math.max(...incidents.map(i => i.timestamp));
      }
      
    } catch (error) {
      logger.warn('Failed to update incident factors', {
        error: error as Error
      });
    }
  }
  
  private async updateBehavioralFactors(reputation: ReputationScore): Promise<void> {
    // Analyze behavioral patterns
    const profile = this.behaviorProfiles.get(reputation.entity);
    
    if (profile) {
      let behaviorScore = 0;
      
      // Consistent behavior = positive
      if (profile.consistency > 0.8) behaviorScore += 5;
      
      // Rapid changes = negative
      if (profile.volatility > 0.7) behaviorScore -= 10;
      
      // Normal patterns = positive
      if (profile.normalityScore > 0.6) behaviorScore += 3;
      
      reputation.factors.behaviorScore = behaviorScore;
    }
  }
  
  private async updateGeolocationFactors(reputation: ReputationScore): Promise<void> {
    if (reputation.type !== 'ip') return;
    
    try {
      const geoLocation = await this.getGeoLocation(reputation.entity);
      
      if (geoLocation) {
        reputation.metadata.geoLocation = geoLocation;
        
        let geoScore = 0;
        
        // Check against blocked countries
        if (this.config.geolocation.blockedCountries.includes(geoLocation)) {
          geoScore -= 30;
          reputation.metadata.tags.push('blocked_country');
        }
        
        // Check against suspicious countries
        if (this.config.geolocation.suspiciousCountries.includes(geoLocation)) {
          geoScore -= 10;
          reputation.metadata.tags.push('suspicious_country');
        }
        
        reputation.factors.geoScore = geoScore;
      }
      
    } catch (error) {
      logger.warn('Failed to update geolocation factors', {
        error: error as Error
      });
    }
  }
  
  private async updateTemporalFactors(reputation: ReputationScore): Promise<void> {
    const now = Date.now();
    const age = now - reputation.lastUpdated;
    
    // Apply decay if enabled
    if (this.config.scoring.decayEnabled && age > this.config.scoring.decayInterval) {
      const decayPeriods = age / this.config.scoring.decayInterval;
      const decayFactor = Math.pow(1 - this.config.scoring.decayRate, decayPeriods);
      
      reputation.factors.temporalScore = (reputation.score - this.config.scoring.initialScore) * (1 - decayFactor);
    }
  }
  
  private calculateFinalScore(factors: ReputationScore['factors']): number {
    let finalScore = factors.baseScore;
    
    finalScore += factors.incidentScore;
    finalScore += factors.behaviorScore;
    finalScore += factors.geoScore;
    finalScore += factors.temporalScore;
    
    if (factors.mlScore !== undefined) {
      finalScore += factors.mlScore;
    }
    
    // Clamp to valid range
    return Math.max(
      this.config.scoring.minScore,
      Math.min(this.config.scoring.maxScore, finalScore)
    );
  }
  
  private calculateThreatLevel(score: number): ReputationScore['level'] {
    if (score >= this.config.thresholds.trustworthy) return 'trustworthy';
    if (score >= this.config.thresholds.neutral) return 'neutral';
    if (score >= this.config.thresholds.suspicious) return 'suspicious';
    if (score >= this.config.thresholds.malicious) return 'malicious';
    return 'blocked';
  }
  
  private async applyMLScore(reputation: ReputationScore): Promise<void> {
    if (!this.config.ml.enabled) return;
    
    try {
      // Extract features for ML model
      const features = this.extractMLFeatures(reputation);
      
      // Get ML prediction (placeholder - integrate with actual ML model)
      const prediction = await this.getMMLThreatPrediction(features);
      
      if (prediction.confidence > this.config.ml.confidenceThreshold) {
        reputation.factors.mlScore = prediction.threatScore;
        reputation.confidence = Math.max(reputation.confidence, prediction.confidence);
        this.metrics.mlPredictions++;
      }
      
    } catch (error) {
      logger.warn('ML score application failed', {
        error: error as Error
      });
    }
  }

  /**
   * Utility and helper methods
   */
  
  private maskEntity(entityId: string): string {
    if (entityId.length <= 8) return entityId;
    return entityId.substring(0, 8) + '...';
  }
  
  private generateIncidentId(): string {
    return `inc-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private getSeverityLevel(severity: number): string {
    if (severity >= 80) return 'critical';
    if (severity >= 60) return 'high';
    if (severity >= 30) return 'medium';
    return 'low';
  }
  
  private async storeIncident(incident: SecurityIncident): Promise<void> {
    const key = `baf:incidents:${incident.entityType}:${incident.entityId}`;
    const incidentData = JSON.stringify(incident);
    
    await redis.zadd(key, incident.timestamp, incidentData);
    await redis.expire(key, this.config.incidents.incidentTtl / 1000);
    
    // Limit incident count per entity
    const count = await redis.zcard(key);
    if (count > this.config.incidents.maxIncidentsPerEntity) {
      const excess = count - this.config.incidents.maxIncidentsPerEntity;
      await redis.zremrangebyrank(key, 0, excess - 1);
    }
  }
  
  private async getRecentIncidents(entityId: string, entityType: EntityType): Promise<SecurityIncident[]> {
    const key = `baf:incidents:${entityType}:${entityId}`;
    
    try {
      const cutoff = Date.now() - (30 * 24 * 60 * 60 * 1000); // 30 days
      const incidents = await redis.zrangebyscore(key, cutoff, '+inf');
      
      return incidents.map(data => JSON.parse(data));
      
    } catch (error) {
      return [];
    }
  }
  
  private extractMLFeatures(reputation: ReputationScore): number[] {
    return [
      reputation.score / 100,
      reputation.factors.incidentScore / -50,
      reputation.metadata.totalIncidents / 100,
      reputation.confidence,
      (Date.now() - reputation.lastUpdated) / (24 * 60 * 60 * 1000) // Age in days
    ];
  }
  
  private async getMMLThreatPrediction(features: number[]): Promise<{ threatScore: number; confidence: number }> {
    // Placeholder ML prediction
    // In production, integrate with actual ML model
    return {
      threatScore: Math.random() * 20 - 10, // -10 to +10
      confidence: Math.random() * 0.3 + 0.7  // 0.7 to 1.0
    };
  }
  
  private async getGeoLocation(ip: string): Promise<string | undefined> {
    const cached = this.geoLocationCache.get(ip);
    if (cached) return cached;
    
    try {
      // Placeholder - integrate with actual geolocation service
      const location = 'US'; // MaxMind, IPGeolocation, etc.
      this.geoLocationCache.set(ip, location);
      return location;
    } catch (error) {
      return undefined;
    }
  }

  /**
   * Event handling and periodic processes
   */
  
  private setupEventHandlers(): void {
    if (this.eventBus) {
      this.eventBus.on('bafEvent', (event: any) => {
        if (event.type === 'block') {
          this.handleBlockEvent(event);
        }
      });
    }
  }
  
  private async handleBlockEvent(event: any): Promise<void> {
    if (event.clientIp && event.clientIp !== 'system') {
      await this.recordIncident(event.clientIp, {
        entityType: 'ip',
        type: 'policy_breach',
        severity: 30,
        description: `Request blocked: ${event.reason}`,
        details: {
          method: event.method,
          rule: event.rule
        },
        source: 'firewall'
      });
    }
  }
  
  private setupPeriodicProcesses(): void {
    // Decay scores periodically
    if (this.config.scoring.decayEnabled) {
      setInterval(() => {
        this.performDecayUpdate();
      }, this.config.scoring.decayInterval);
    }
    
    // Cleanup old data
    setInterval(() => {
      this.performCleanup();
    }, 3600000); // Every hour
    
    // Update threat intelligence
    setInterval(() => {
      this.updateThreatIntelligence();
    }, 21600000); // Every 6 hours
  }

  /**
   * Public health and management methods
   */
  
  public async isHealthy(): Promise<boolean> {
    try {
      // Test Redis connectivity
      await redis.ping();
      
      // Check cache sizes
      const cacheHealthy = this.reputationCache.size < 10000;
      
      return cacheHealthy;
      
    } catch (error) {
      return false;
    }
  }
  
  public getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }
  
  public async cleanup(): Promise<void> {
    this.reputationCache.clear();
    this.incidentBuffer.clear();
    this.threatIntelCache.clear();
    this.behaviorProfiles.clear();
    this.geoLocationCache.clear();
  }

  // Placeholder methods for future implementation
  private async loadThreatIntelligence(): Promise<void> { }
  private async initializeMLModel(): Promise<void> { }
  private async loadExistingReputations(): Promise<void> { }
  private async updateScore(entityType: EntityType, entityId: string, score: number, reason: string): Promise<void> { }
  private async updateScoreFromIncident(incident: SecurityIncident): Promise<void> { }
  private emitIncidentEvent(incident: SecurityIncident): void { }
  private async analyzeIncidentPatterns(incident: SecurityIncident): Promise<void> { }
  private async performDecayUpdate(): Promise<void> { }
  private async performCleanup(): Promise<void> { }
  private async updateThreatIntelligence(): Promise<void> { }
}

export default ReputationService;
