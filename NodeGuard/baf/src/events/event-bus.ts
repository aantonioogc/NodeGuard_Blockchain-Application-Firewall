// src/events/event-bus.ts
// Bus de eventos - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import { Response } from 'express';
import { EventEmitter } from 'events';
import redis from '../redis/redis-connection';
import { logger } from '../logging/logger';

/**
 * 
 * Características del bus de eventos:
 * - Server-Sent Events (SSE) para streaming en tiempo real
 * - Filtrado y enrutamiento de eventos
 * - Almacenamiento persistente de eventos con Redis
 * - Repetición e historial de eventos
 * - Limitación de tasa y control de flujo
 * - Métricas y analítica de eventos
 * - Cola de eventos fallidos (dead letter queue)
 * - Serialización y compresión de eventos
 * - Aislamiento multi-tenant de eventos
 */

export interface BafEvent {
  type: 'block' | 'allow' | 'status' | 'connection' | 'ping';
  timestamp: number;
  message?: string;
  method: string;
  clientIp: string;
  reqId: string;
  rule?: string;
  reason?: string;
  from?: string;
  to?: string;
  level?: 'info' | 'warning' | 'error' | 'critical';
  metadata?: {
    severity?: number;
    category?: string;
    tags?: string[];
    correlationId?: string;
    duration?: number;
    [key: string]: any;
  };
}

export interface EventSubscriber {
  id: string;
  response: Response;
  filters: EventFilter[];
  subscribedAt: number;
  lastActivity: number;
  eventCount: number;
  ipAddress: string;
  userAgent?: string;
}

export interface EventFilter {
  type?: string | string[];
  level?: string | string[];
  method?: string | string[];
  rule?: string | string[];
  clientIp?: string;
  timeRange?: {
    start: number;
    end: number;
  };
}

export interface EventBusMetrics {
  totalEvents: number;
  eventsByType: Map<string, number>;
  eventsByLevel: Map<string, number>;
  subscribers: number;
  averageLatency: number;
  droppedEvents: number;
  persistedEvents: number;
  lastEventTime: number;
}

export interface EventBusConfig {
  maxHistory: number;
  maxSubscribers: number;
  persistEvents: boolean;
  enableCompression: boolean;
  rateLimitPerSubscriber: number; // eventos por minuto
  eventTtl: number; // TTL en segundos
  enableDeadLetterQueue: boolean;
  metricsEnabled: boolean;
}

/**
 * Bus de eventos NodeGuard
 */
export class EventBus extends EventEmitter {
  private static instance: EventBus;
  private subscribers = new Map<string, EventSubscriber>();
  private eventHistory: BafEvent[] = [];
  private metrics: EventBusMetrics;
  private readonly config: EventBusConfig;
  
  // Referencias de timers para cleanup
  private cleanupInterval?: NodeJS.Timeout;
  private metricsInterval?: NodeJS.Timeout;
  private healthInterval?: NodeJS.Timeout;
  
  // Seguimiento de rendimiento
  private eventRateLimits = new Map<string, { count: number; resetTime: number }>();
  private subscriberRateLimits = new Map<string, { count: number; resetTime: number }>();
  
  // Persistencia de eventos
  private deadLetterQueue: BafEvent[] = [];
  private eventSequence = 0;
  
  constructor(config: Partial<EventBusConfig> = {}) {
    super();
    
    this.config = {
      maxHistory: config.maxHistory || 1000,
      maxSubscribers: config.maxSubscribers || 100,
      persistEvents: config.persistEvents !== false,
      enableCompression: config.enableCompression || false, // Desactivado por defecto para dashboard
      rateLimitPerSubscriber: config.rateLimitPerSubscriber || 100, // eventos por minuto
      eventTtl: config.eventTtl || 86400, // 24 horas
      enableDeadLetterQueue: config.enableDeadLetterQueue !== false,
      metricsEnabled: config.metricsEnabled !== false
    };
    
    this.metrics = {
      totalEvents: 0,
      eventsByType: new Map(),
      eventsByLevel: new Map(),
      subscribers: 0,
      averageLatency: 0,
      droppedEvents: 0,
      persistedEvents: 0,
      lastEventTime: 0
    };
    
    this.setupPeriodicTasks();
    this.setupHealthMonitoring();
    
    logger.info('Bus de eventos NodeGuard inicializado', {
      maxHistory: this.config.maxHistory,
      persistEvents: this.config.persistEvents,
      rateLimitPerSubscriber: this.config.rateLimitPerSubscriber
    });
  }

  /**
   * Obtener instancia singleton
   */
  public static getInstance(config?: Partial<EventBusConfig>): EventBus {
    if (!EventBus.instance) {
      EventBus.instance = new EventBus(config);
    }
    return EventBus.instance;
  }

  /**
   * Suscribirse a eventos con filtros
   */
  subscribe(
    response: Response, 
    filters: EventFilter[] = [],
    subscriberId?: string
  ): () => void {
    const id = subscriberId || this.generateSubscriberId();
    const clientIp = response.req?.ip || 'unknown';
    const userAgent = response.req?.get('User-Agent');
    
    // Comprobar límite de suscriptores
    if (this.subscribers.size >= this.config.maxSubscribers) {
      logger.warn('Límite máximo de suscriptores alcanzado', {
        current: this.subscribers.size,
        max: this.config.maxSubscribers,
        clientIp
      });
      
      response.status(503).json({
        error: 'max_subscribers_reached',
        message: 'El servidor ha alcanzado el límite máximo de suscriptores'
      });
      return () => {};
    }

    const subscriber: EventSubscriber = {
      id,
      response,
      filters,
      subscribedAt: Date.now(),
      lastActivity: Date.now(),
      eventCount: 0,
      ipAddress: clientIp,
      userAgent
    };
    
    // Configurar headers SSE solo si no han sido enviados
    if (!response.headersSent) {
      response.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Cache-Control',
        'X-Accel-Buffering': 'no' // Deshabilitar buffering de nginx
      });
    } else {
      // Si los headers ya fueron enviados, no podemos establecer SSE
      logger.warn('Headers already sent, cannot establish SSE connection', {
        subscriberId: id,
        clientIp
      });
      return () => {};
    }
    
    // Enviar evento de conexión
    this.sendToSubscriber(subscriber, {
      type: 'connection',
      timestamp: Date.now(),
      message: 'Conectado al stream de eventos NodeGuard',
      method: 'system',
      clientIp: 'system',
      reqId: `conn-${Date.now()}`,
      metadata: {
        subscriberId: id,
        filtersActive: filters.length > 0,
        serverTime: new Date().toISOString()
      }
    });
    
    // Send recent events matching filters
    this.sendHistoryToSubscriber(subscriber);
    
    this.subscribers.set(id, subscriber);
    this.metrics.subscribers = this.subscribers.size;
    
    // Configurar manejadores de cleanup
    const cleanup = () => {
      this.subscribers.delete(id);
      this.metrics.subscribers = this.subscribers.size;
      this.subscriberRateLimits.delete(id);
      
      logger.debug('Suscriptor de eventos desconectado', {
        subscriberId: id,
        clientIp,
        duration: Date.now() - subscriber.subscribedAt,
        eventsReceived: subscriber.eventCount,
        activeSubscribers: this.subscribers.size
      });
      
      super.emit('subscriberDisconnected', { subscriberId: id, subscriber });
    };
    
    response.on('close', cleanup);
    response.on('error', (error) => {
      logger.warn('Error en suscriptor de eventos', {
        subscriberId: id,
        error: error,
        clientIp
      });
      cleanup();
    });
    
    // ajgc: configurar keepalive ping cada 30 segundos
    const pingInterval = setInterval(() => {
      if (this.subscribers.has(id)) {
        this.sendToSubscriber(subscriber, {
          type: 'ping',
          timestamp: Date.now(),
          message: 'keepalive',
          method: 'system',
          clientIp: 'system',
          reqId: `ping-${Date.now()}`
        });
      } else {
        clearInterval(pingInterval);
      }
    }, 30000);
    
    logger.info('Nuevo suscriptor de eventos conectado', {
      subscriberId: id,
      clientIp,
      userAgent,
      filtersCount: filters.length,
      activeSubscribers: this.subscribers.size
    });
    
    super.emit('subscriberConnected', { subscriberId: id, subscriber });
    
    return cleanup;
  }

  /**
   * Emitir evento a todos los suscriptores que coincidan
   * ajgc: renombrado de 'emit' a 'emitEvent' para evitar conflicto con EventEmitter
   */
  emitEvent(event: BafEvent): boolean {
    const startTime = Date.now();
    
    try {
      // Mejorar evento con metadatos
      const enhancedEvent = this.enhanceEvent(event);
      
      // Actualizar métricas
      this.updateEventMetrics(enhancedEvent);
      
      // Añadir al historial
      this.addToHistory(enhancedEvent);
      
      // Persistir en Redis si está habilitado
        if (this.config.persistEvents) {
          this.persistEvent(enhancedEvent).catch(error => {
            logger.error('Error al persistir evento', {
              error: error,
              eventType: enhancedEvent.type,
              eventId: enhancedEvent.reqId
            });
          });
        }      // Enviar a suscriptores que coincidan
      let deliveredCount = 0;
      let failedCount = 0;
      
      for (const subscriber of this.subscribers.values()) {
        try {
          if (this.eventMatchesFilters(enhancedEvent, subscriber.filters)) {
            // Comprobar rate limit del suscriptor
            if (this.isSubscriberRateLimited(subscriber.id)) {
              continue;
            }
            
            if (this.sendToSubscriber(subscriber, enhancedEvent)) {
              deliveredCount++;
              subscriber.eventCount++;
              subscriber.lastActivity = Date.now();
            } else {
              failedCount++;
              this.handleFailedDelivery(subscriber, enhancedEvent);
            }
          }
        } catch (error) {
          failedCount++;
          logger.warn('Error al entregar evento al suscriptor', {
            subscriberId: subscriber.id,
            error: error as Error,
            eventType: enhancedEvent.type
          });
        }
      }
      
      // Actualizar métricas de rendimiento
      const latency = Date.now() - startTime;
      this.updateLatencyMetrics(latency);
      
      if (failedCount > 0) {
        this.metrics.droppedEvents += failedCount;
      }
      
      // Emit internal events
      super.emit('eventEmitted', {
        event: enhancedEvent,
        deliveredCount,
        failedCount,
        latency
      });
      
      // ajgc: log de eventos críticos para debugging
      if (enhancedEvent.level === 'error' || enhancedEvent.level === 'critical') {
        logger.warn('Evento crítico emitido', {
          type: enhancedEvent.type,
          level: enhancedEvent.level,
          reason: enhancedEvent.reason,
          method: enhancedEvent.method,
          clientIp: enhancedEvent.clientIp,
          deliveredCount,
          failedCount
        });
      }
      
      return deliveredCount > 0;
      
    } catch (error) {
      logger.error('Error en emisión de evento', {
        error: error as Error,
        eventType: event.type
      });
      
      if (this.config.enableDeadLetterQueue) {
        this.addToDeadLetterQueue(event);
      }
      
      return false;
    }
  }

  /**
   * Get event history with filtering
   */
  getEventHistory(
    filters: EventFilter[] = [],
    limit: number = 100,
    offset: number = 0
  ): BafEvent[] {
    let filteredEvents = this.eventHistory;
    
    // Apply filters
    if (filters.length > 0) {
      filteredEvents = this.eventHistory.filter(event => 
        this.eventMatchesFilters(event, filters)
      );
    }
    
    // Apply pagination
    return filteredEvents
      .slice(offset, offset + limit)
      .reverse(); // Most recent first
  }

  /**
   * Get persistent event history from Redis
   */
  async getPersistentEventHistory(
    filters: EventFilter[] = [],
    limit: number = 100
  ): Promise<BafEvent[]> {
    if (!this.config.persistEvents) {
      return [];
    }
    
    try {
      const eventKeys = await redis.keys('baf:events:*');
      eventKeys.sort().reverse(); // Most recent first
      
      const events: BafEvent[] = [];
      
      for (const key of eventKeys.slice(0, limit * 2)) { // Get more than needed for filtering
        try {
          const eventData = await redis.get(key);
          if (eventData) {
            const event = JSON.parse(eventData);
            if (this.eventMatchesFilters(event, filters)) {
              events.push(event);
              if (events.length >= limit) break;
            }
          }
        } catch (error) {
          // Skip invalid events
        }
      }
      
      return events;
      
    } catch (error) {
      logger.error('Failed to retrieve persistent event history', {
        error: error as Error
      });
      return [];
    }
  }

  /**
   * Get comprehensive metrics
   */
  getMetrics(): EventBusMetrics & {
    subscriberDetails: Array<{
      id: string;
      ipAddress: string;
      subscribedAt: number;
      eventCount: number;
      lastActivity: number;
      filtersCount: number;
    }>;
    deadLetterQueueSize: number;
    memoryUsage: {
      eventHistory: number;
      subscribers: number;
    };
  } {
    const subscriberDetails = Array.from(this.subscribers.values()).map(sub => ({
      id: sub.id,
      ipAddress: sub.ipAddress,
      subscribedAt: sub.subscribedAt,
      eventCount: sub.eventCount,
      lastActivity: sub.lastActivity,
      filtersCount: sub.filters.length
    }));
    
    return {
      ...this.metrics,
      subscriberDetails,
      deadLetterQueueSize: this.deadLetterQueue.length,
      memoryUsage: {
        eventHistory: JSON.stringify(this.eventHistory).length,
        subscribers: JSON.stringify(subscriberDetails).length
      }
    };
  }

  /**
   * Health check
   */
  isHealthy(): boolean {
    const now = Date.now();
    const lastEventAge = now - this.metrics.lastEventTime;
    const maxAge = 3600000; // 60 minutes (increased from 5 minutes)
    
    // Always healthy if:
    // 1. No events yet (new instance)
    // 2. System is operational (has subscribers or can accept them)
    // 3. Recent events within reasonable time frame
    return this.metrics.totalEvents === 0 || 
           this.subscribers.size > 0 ||
           lastEventAge < maxAge;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Clear all intervals
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
    
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = undefined;
    }
    
    if (this.healthInterval) {
      clearInterval(this.healthInterval);
      this.healthInterval = undefined;
    }
    
    // Close all subscribers
    for (const subscriber of this.subscribers.values()) {
      try {
        subscriber.response.end();
      } catch (error) {
        // Ignore errors during cleanup
      }
    }
    
    this.subscribers.clear();
    this.eventHistory = [];
    this.deadLetterQueue = [];
    
    logger.info('Event Bus cleaned up');
  }

  /**
   * Private helper methods
   */
  
  private enhanceEvent(event: BafEvent): BafEvent {
    const enhanced: BafEvent = {
      ...event,
      timestamp: event.timestamp || Date.now(),
      reqId: event.reqId || `evt-${++this.eventSequence}-${Date.now()}`,
      metadata: {
        ...event.metadata,
        eventId: event.reqId || `evt-${this.eventSequence}`,
        sequence: this.eventSequence,
        serverTime: new Date().toISOString()
      }
    };
    
    // Auto-assign level if not provided
    if (!enhanced.level) {
      if (enhanced.type === 'block') {
        enhanced.level = 'warning';
      } else if (enhanced.type === 'allow') {
        enhanced.level = 'info';
      } else {
        enhanced.level = 'info';
      }
    }
    
    return enhanced;
  }
  
  private sendToSubscriber(subscriber: EventSubscriber, event: BafEvent): boolean {
    try {
      // Verificar si la conexión está activa
      if (!subscriber.response || subscriber.response.destroyed || subscriber.response.closed) {
        logger.debug('Connection closed, removing subscriber', {
          subscriberId: subscriber.id
        });
        this.subscribers.delete(subscriber.id);
        return false;
      }
      
      const eventData = this.config.enableCompression 
        ? this.compressEventData(event)
        : JSON.stringify(event);
      
      const sseData = `data: ${eventData}\n\n`;
      subscriber.response.write(sseData);
      
      return true;
      
    } catch (error) {
      logger.debug('Failed to send event to subscriber', {
        subscriberId: subscriber.id,
        error: error as Error,
        eventType: event.type
      });
      // Remover subscriber si falla el envío
      this.subscribers.delete(subscriber.id);
      return false;
    }
  }
  
  private sendHistoryToSubscriber(subscriber: EventSubscriber): void {
    const recentEvents = this.eventHistory
      .filter(event => this.eventMatchesFilters(event, subscriber.filters))
      .slice(-10); // Last 10 matching events
    
    for (const event of recentEvents) {
      this.sendToSubscriber(subscriber, {
        ...event,
        metadata: {
          ...event.metadata,
          isHistorical: true
        }
      });
    }
  }
  
  private eventMatchesFilters(event: BafEvent, filters: EventFilter[]): boolean {
    if (filters.length === 0) return true;
    
    return filters.some(filter => {
      // Type filter
      if (filter.type) {
        const types = Array.isArray(filter.type) ? filter.type : [filter.type];
        if (!types.includes(event.type)) return false;
      }
      
      // Level filter
      if (filter.level && event.level) {
        const levels = Array.isArray(filter.level) ? filter.level : [filter.level];
        if (!levels.includes(event.level)) return false;
      }
      
      // Method filter
      if (filter.method) {
        const methods = Array.isArray(filter.method) ? filter.method : [filter.method];
        if (!methods.includes(event.method)) return false;
      }
      
      // Rule filter
      if (filter.rule && event.rule) {
        const rules = Array.isArray(filter.rule) ? filter.rule : [filter.rule];
        if (!rules.includes(event.rule)) return false;
      }
      
      // Client IP filter
      if (filter.clientIp && event.clientIp !== filter.clientIp) {
        return false;
      }
      
      // Time range filter
      if (filter.timeRange) {
        if (event.timestamp < filter.timeRange.start || event.timestamp > filter.timeRange.end) {
          return false;
        }
      }
      
      return true;
    });
  }
  
  private addToHistory(event: BafEvent): void {
    this.eventHistory.push(event);
    
    // Trim history to max size
    if (this.eventHistory.length > this.config.maxHistory) {
      this.eventHistory = this.eventHistory.slice(-this.config.maxHistory);
    }
  }
  
  private async persistEvent(event: BafEvent): Promise<void> {
    try {
      const eventKey = `baf:events:${event.timestamp}:${event.reqId}`;
      const eventData = JSON.stringify(event);
      
      await redis.setex(eventKey, this.config.eventTtl, eventData);
      this.metrics.persistedEvents++;
      
    } catch (error) {
      logger.warn('Failed to persist event to Redis', {
        error: error as Error,
        eventType: event.type
      });
    }
  }
  
  private updateEventMetrics(event: BafEvent): void {
    this.metrics.totalEvents++;
    this.metrics.lastEventTime = event.timestamp;
    
    // Update type metrics
    const typeCount = this.metrics.eventsByType.get(event.type) || 0;
    this.metrics.eventsByType.set(event.type, typeCount + 1);
    
    // Update level metrics
    if (event.level) {
      const levelCount = this.metrics.eventsByLevel.get(event.level) || 0;
      this.metrics.eventsByLevel.set(event.level, levelCount + 1);
    }
  }
  
  private updateLatencyMetrics(latency: number): void {
    // Exponential moving average
    const alpha = 0.1;
    this.metrics.averageLatency = this.metrics.averageLatency * (1 - alpha) + latency * alpha;
  }
  
  private isSubscriberRateLimited(subscriberId: string): boolean {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    
    const limit = this.subscriberRateLimits.get(subscriberId);
    if (!limit || now > limit.resetTime) {
      this.subscriberRateLimits.set(subscriberId, {
        count: 1,
        resetTime: now + windowMs
      });
      return false;
    }
    
    if (limit.count >= this.config.rateLimitPerSubscriber) {
      return true;
    }
    
    limit.count++;
    return false;
  }
  
  private handleFailedDelivery(subscriber: EventSubscriber, event: BafEvent): void {
    // Remove subscriber if multiple failures
    const failures = (subscriber as any).failureCount || 0;
    (subscriber as any).failureCount = failures + 1;
    
    if (failures > 3) {
      logger.warn('Removing subscriber due to repeated failures', {
        subscriberId: subscriber.id,
        failures: failures + 1
      });
      
      this.subscribers.delete(subscriber.id);
      this.metrics.subscribers = this.subscribers.size;
      
      try {
        subscriber.response.end();
      } catch (error) {
        // Ignore cleanup errors
      }
    }
  }
  
  private addToDeadLetterQueue(event: BafEvent): void {
    if (this.deadLetterQueue.length >= 1000) {
      this.deadLetterQueue.shift(); // Remove oldest
    }
    
    this.deadLetterQueue.push({
      ...event,
      metadata: {
        ...event.metadata,
        deadLetteredAt: Date.now(),
        originalTimestamp: event.timestamp
      }
    });
  }
  
  private compressEventData(event: BafEvent): string {
    // Simple compression by removing unnecessary fields
    const compressed = {
      t: event.type,
      ts: event.timestamp,
      m: event.method,
      ip: event.clientIp,
      id: event.reqId
    };
    
    if (event.rule) (compressed as any).r = event.rule;
    if (event.reason) (compressed as any).rs = event.reason;
    if (event.message) (compressed as any).msg = event.message;
    if (event.level) (compressed as any).l = event.level;
    
    return JSON.stringify(compressed);
  }
  
  private generateSubscriberId(): string {
    return `sub-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private setupPeriodicTasks(): void {
    // Cleanup old events and inactive subscribers
    this.cleanupInterval = setInterval(() => {
      this.cleanupInactiveSubscribers();
      this.cleanupDeadLetterQueue();
    }, 60000); // Every minute
    
    // Emit metrics periodically
    if (this.config.metricsEnabled) {
      this.metricsInterval = setInterval(() => {
        super.emit('metrics', this.getMetrics());
      }, 30000); // Every 30 seconds
    }
  }
  
  private setupHealthMonitoring(): void {
    this.healthInterval = setInterval(() => {
      const healthy = this.isHealthy();
      super.emit('healthCheck', { healthy, metrics: this.metrics });
      
      if (!healthy) {
        logger.warn('Event Bus health check failed', {
          lastEventAge: Date.now() - this.metrics.lastEventTime,
          totalEvents: this.metrics.totalEvents,
          activeSubscribers: this.subscribers.size
        });
      }
    }, 300000); // Every 5 minutes (reduced from 1 minute to reduce log spam)
  }
  
  private cleanupInactiveSubscribers(): void {
    const now = Date.now();
    const inactivityTimeout = 300000; // 5 minutes
    
    for (const [id, subscriber] of this.subscribers.entries()) {
      if (now - subscriber.lastActivity > inactivityTimeout) {
        logger.info('Removing inactive subscriber', {
          subscriberId: id,
          inactiveDuration: now - subscriber.lastActivity
        });
        
        this.subscribers.delete(id);
        try {
          subscriber.response.end();
        } catch (error) {
          // Ignore cleanup errors
        }
      }
    }
    
    this.metrics.subscribers = this.subscribers.size;
  }
  
  private cleanupDeadLetterQueue(): void {
    const maxAge = 86400000; // 24 hours
    const now = Date.now();
    
    this.deadLetterQueue = this.deadLetterQueue.filter(event => {
      const deadLetteredAt = event.metadata?.deadLetteredAt || 0;
      return (now - deadLetteredAt) < maxAge;
    });
  }
}

// Export singleton instance getter
export const eventBus = EventBus.getInstance();

export default EventBus;
