// src/utils/circuit-breaker.ts
// ajgc: patrón circuit breaker para NodeGuard

import { EventEmitter } from 'events';

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  recoveryTimeout?: number;
  monitorTimeout?: number;
}

export interface CircuitBreaker {
  execute<T>(operation: () => Promise<T>): Promise<T>;
  isOpen(): boolean;
  getMetrics(): {
    failures: number;
    successes: number;
    timeouts: number;
    state: 'closed' | 'open' | 'half-open';
    nextAttempt?: number;
  };
}

/**
 * ajgc: Circuit Breaker niquelao para proteger servicios externos
 * Evita cascadas de fallos cuando un servicio no responde
 */
export class CircuitBreaker extends EventEmitter implements CircuitBreaker {
  private failures = 0;
  private successes = 0;
  private timeouts = 0;
  private openUntil = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  private readonly failureThreshold: number;
  private readonly recoveryTimeout: number;

  constructor(options: CircuitBreakerOptions = {}) {
    super();
    this.failureThreshold = options.failureThreshold || 5;
    this.recoveryTimeout = options.recoveryTimeout || 30000; // 30 segundos para recovery
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    const currentState = this.getState();
    
    if (currentState === 'open') {
      throw new Error("Circuit breaker está abierto - servicio no disponible");
    }

    try {
      const result = await operation();
      this.recordSuccess();
      return result;
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  isOpen(): boolean {
    return this.getState() === 'open';
  }

  private getState(): 'closed' | 'open' | 'half-open' {
    const now = Date.now();
    
    if (this.openUntil > 0 && now < this.openUntil) {
      return 'open';
    } else if (this.openUntil > 0 && now >= this.openUntil && this.state === 'open') {
      // transición a half-open para echarle un ojillo al servicio
      this.state = 'half-open';
      this.openUntil = 0;
      this.emit('halfOpen');
      return 'half-open';
    } else if (this.failures >= this.failureThreshold) {
      return 'half-open';
    } else {
      return 'closed';
    }
  }

  private recordSuccess(): void {
    const previousState = this.state;
    this.failures = 0;
    this.successes++;
    this.state = 'closed';
    
    // emitir evento si el circuito estaba abierto y ahora se cierra
    if ((previousState === 'half-open' || previousState === 'open') && this.state === 'closed') {
      this.emit('close');
    }
  }

  private recordFailure(): void {
    const previousState = this.state;
    this.failures++;
    
    if (this.failures >= this.failureThreshold) {
      if (this.state === 'half-open') {
        // falló en half-open, volver a abrir
        this.openUntil = Date.now() + this.recoveryTimeout;
        this.state = 'open';
        this.emit('open');
      } else if (previousState === 'closed') {
        // primera vez que se abre - esto está de locos
        this.openUntil = Date.now() + this.recoveryTimeout;
        this.state = 'open';
        this.emit('open');
      }
    }
  }

  getMetrics() {
    return {
      failures: this.failures,
      successes: this.successes,
      timeouts: this.timeouts,
      state: this.getState(),
      nextAttempt: this.openUntil > 0 ? this.openUntil : undefined
    };
  }
}
