// src/client/baf-client.ts - Cliente BAF
// ajgc (Antonio José González Castillo) - NodeGuard TFG BAF
import axios, { AxiosInstance, AxiosError, AxiosResponse } from 'axios';
import { EventEmitter } from 'events';
import { CircuitBreaker } from '../utils/circuit-breaker';
import { logger } from '../logging/logger';

/**
 * Cliente principal del sistema NodeGuard
 * Incluye funcionalidad completa JSON-RPC y administración
 */

export interface BafClientConfig {
  rpcUrl?: string;
  adminUrl?: string;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  circuitBreaker?: {
    enabled: boolean;
    failureThreshold: number;
    recoveryTimeout: number;
  };
  auth?: {
    token?: string;
    username?: string;
    password?: string;
    autoRotateToken?: boolean;
  };
  events?: {
    enabled: boolean;
    autoReconnect: boolean;
    filters?: string[];
  };
  validation?: {
    validateRequests: boolean;
    validateResponses: boolean;
    strictMode: boolean;
  };
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params?: unknown[];
  id: string | number;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
  id: string | number;
}

export interface BafClientMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageLatency: number;
  circuitBreakerStatus: 'closed' | 'open' | 'half-open';
  connectionStatus: 'connected' | 'disconnected' | 'reconnecting';
  lastError?: string;
  uptime: number;
}

export interface AdminSession {
  token: string;
  userId: string;
  role: string;
  expiresAt: number;
  permissions: string[];
}

/**
 * Cliente NodeGuard
 * ajgc - implementación principal del TFG
 */
export class BafClient extends EventEmitter {
  private readonly config: Required<BafClientConfig>;
  private readonly rpcClient: AxiosInstance;
  private readonly adminClient: AxiosInstance;
  private readonly circuitBreaker?: CircuitBreaker;
  
  // Estado de conexiones y sesiones
  private adminSession?: AdminSession;
  private eventSource?: EventSource;
  private connectionRetries = 0;
  private readonly maxRetries = 5;
  
  // Métricas del sistema
  private metrics: BafClientMetrics = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    averageLatency: 0,
    circuitBreakerStatus: 'closed',
    connectionStatus: 'disconnected',
    uptime: Date.now()
  };
  
  // Seguimiento de requests activos
  private activeRequests = new Map<string, { startTime: number; method: string }>();
  
  constructor(config: BafClientConfig = {}) {
    super();
    
    this.config = {
      rpcUrl: config.rpcUrl || process.env.BAF_RPC_URL || 'http://127.0.0.1:3000/rpc',
      adminUrl: config.adminUrl || process.env.BAF_ADMIN_URL || 'http://127.0.0.1:3000/admin',
      timeout: config.timeout || 30000,
      retries: config.retries || 3,
      retryDelay: config.retryDelay || 1000,
      circuitBreaker: {
        enabled: config.circuitBreaker?.enabled ?? true,
        failureThreshold: config.circuitBreaker?.failureThreshold || 5,
        recoveryTimeout: config.circuitBreaker?.recoveryTimeout || 30000
      },
      auth: {
        token: config.auth?.token,
        username: config.auth?.username,
        password: config.auth?.password,
        autoRotateToken: config.auth?.autoRotateToken ?? false
      },
      events: {
        enabled: config.events?.enabled ?? true,
        autoReconnect: config.events?.autoReconnect ?? true,
        filters: config.events?.filters || []
      },
      validation: {
        validateRequests: config.validation?.validateRequests ?? true,
        validateResponses: config.validation?.validateResponses ?? true,
        strictMode: config.validation?.strictMode ?? false
      }
    };
    
    // Inicializar clientes HTTP
    this.rpcClient = this.createHttpClient(this.config.rpcUrl);
    this.adminClient = this.createHttpClient(this.config.adminUrl);
    
    // Circuit breaker para evitar cascadas de fallos
    if (this.config.circuitBreaker.enabled) {
      this.circuitBreaker = new CircuitBreaker({
        failureThreshold: this.config.circuitBreaker.failureThreshold,
        recoveryTimeout: this.config.circuitBreaker.recoveryTimeout
      });
      
      this.circuitBreaker.on('open', () => {
        this.metrics.circuitBreakerStatus = 'open';
        this.emit('circuitBreakerOpen');
      });
      
      this.circuitBreaker.on('halfOpen', () => {
        this.metrics.circuitBreakerStatus = 'half-open';
        this.emit('circuitBreakerHalfOpen');
      });
      
      this.circuitBreaker.on('close', () => {
        this.metrics.circuitBreakerStatus = 'closed';
        this.emit('circuitBreakerClose');
      });
    }
    
    this.setupPerformanceTracking();
    
    logger.info('Cliente NodeGuard inicializado', {
      rpcUrl: this.config.rpcUrl,
      adminUrl: this.config.adminUrl,
      circuitBreakerEnabled: this.config.circuitBreaker.enabled,
      eventsEnabled: this.config.events.enabled
    });
  }

  /**
   * Inicializar conexión del cliente
   */
  async initialize(): Promise<void> {
    try {
      // Probar conectividad RPC
      await this.healthCheck();
      
      // Autenticar si hay credenciales
      if (this.config.auth.username && this.config.auth.password) {
        await this.authenticate();
      }
      
      // Iniciar stream de eventos si está habilitado
      if (this.config.events.enabled) {
        await this.startEventStream();
      }
      
      this.metrics.connectionStatus = 'connected';
      this.emit('connected');
      
      logger.info('Cliente NodeGuard conectado exitosamente');
      
    } catch (error) {
      this.metrics.connectionStatus = 'disconnected';
      this.metrics.lastError = (error as Error).message;
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Métodos JSON-RPC para Ethereum
   */
  async getChainId(): Promise<string> {
    const response = await this.call('eth_chainId', []);
    return response.result as string;
  }
  
  async getBlockNumber(): Promise<string> {
    const response = await this.call('eth_blockNumber', []);
    return response.result as string;
  }
  
  async getBalance(address: string, blockTag: string = 'latest'): Promise<string> {
    const response = await this.call('eth_getBalance', [address, blockTag]);
    return response.result as string;
  }
  
  async getTransactionCount(address: string, blockTag: string = 'latest'): Promise<string> {
    const response = await this.call('eth_getTransactionCount', [address, blockTag]);
    return response.result as string;
  }
  
  async getGasPrice(): Promise<string> {
    const response = await this.call('eth_gasPrice', []);
    return response.result as string;
  }
  
  async estimateGas(txObject: any): Promise<string> {
    const response = await this.call('eth_estimateGas', [txObject]);
    return response.result as string;
  }
  
  async sendRawTransaction(rawTx: string): Promise<string> {
    if (!rawTx || !rawTx.startsWith('0x')) {
      throw new Error('Formato de transacción raw inválido');
    }
    
    const response = await this.call('eth_sendRawTransaction', [rawTx]);
    return response.result as string;
  }
  
  async sendTransaction(txObject: any): Promise<string> {
    const response = await this.call('eth_sendTransaction', [txObject]);
    return response.result as string;
  }
  
  async call(method: string, params: unknown[] = []): Promise<JsonRpcResponse> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      params,
      id: this.generateRequestId()
    };
    
    return this.sendRequest(request);
  }
  
  async batchCall(requests: Array<{ method: string; params?: unknown[] }>): Promise<JsonRpcResponse[]> {
    const batchRequests: JsonRpcRequest[] = requests.map(req => ({
      jsonrpc: '2.0',
      method: req.method,
      params: req.params || [],
      id: this.generateRequestId()
    }));
    
    return this.sendBatchRequest(batchRequests);
  }

  /**
   * API de administración
   */
  
  async authenticate(): Promise<AdminSession> {
    try {
      const response = await this.adminClient.post('/auth/login', {
        username: this.config.auth.username,
        password: this.config.auth.password
      });
      
      this.adminSession = {
        token: response.data.token,
        userId: response.data.user.id,
        role: response.data.user.role,
        expiresAt: Date.now() + (response.data.expiresIn * 1000),
        permissions: response.data.user.permissions
      };
      
      // Update admin client with auth token
      this.adminClient.defaults.headers.common['Authorization'] = `Bearer ${this.adminSession.token}`;
      
      this.emit('authenticated', this.adminSession);
      
      logger.info('Autenticación admin exitosa', {
        userId: this.adminSession.userId,
        role: this.adminSession.role
      });
      
      return this.adminSession;
      
    } catch (error) {
      logger.error('Falló la autenticación admin', { error: error as Error });
      throw new Error('Falló la autenticación');
    }
  }
  
  async getRules(): Promise<any> {
    this.ensureAuthenticated();
    
    const response = await this.adminClient.get('/rules');
    return response.data.rules;
  }
  
  async updateRules(rules: any): Promise<void> {
    this.ensureAuthenticated();
    
    await this.adminClient.post('/rules', rules, {
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': await this.getCsrfToken()
      }
    });
    
    this.emit('rulesUpdated', rules);
  }
  
  async getSystemHealth(): Promise<any> {
    this.ensureAuthenticated();
    
    const response = await this.adminClient.get('/health');
    return response.data.health;
  }
  
  async getSystemStats(): Promise<any> {
    this.ensureAuthenticated();
    
    const response = await this.adminClient.get('/stats');
    return response.data.stats;
  }
  
  async clearCache(cacheType: string): Promise<void> {
    this.ensureAuthenticated();
    
    await this.adminClient.delete(`/cache/${cacheType}`, {
      headers: {
        'X-CSRF-Token': await this.getCsrfToken()
      }
    });
    
    this.emit('cacheCleared', cacheType);
  }
  
  async getRuleBackups(): Promise<any[]> {
    this.ensureAuthenticated();
    
    const response = await this.adminClient.get('/rules/backups');
    return response.data.backups;
  }
  
  async rollbackRules(backupKey?: string): Promise<void> {
    this.ensureAuthenticated();
    
    await this.adminClient.post('/rules/rollback', 
      backupKey ? { backupKey } : {},
      {
        headers: {
          'X-CSRF-Token': await this.getCsrfToken()
        }
      }
    );
    
    this.emit('rulesRolledBack', backupKey);
  }

  /**
   * Sistema de eventos en tiempo real
   */
  
  async startEventStream(): Promise<void> {
    if (typeof EventSource === 'undefined') {
      logger.warn('EventSource no disponible, streaming deshabilitado');
      return;
    }
    
    try {
      const eventUrl = new URL('/events', this.config.adminUrl);
      
      // ajgc: añadir filtros si están especificados
      if ((this.config.events?.filters?.length ?? 0) > 0) {
        eventUrl.searchParams.set('type', this.config.events.filters!.join(','));
      }
      
      this.eventSource = new EventSource(eventUrl.toString());
      
      this.eventSource.onopen = () => {
        logger.info('Stream de eventos conectado');
        this.connectionRetries = 0;
        this.emit('eventStreamConnected');
      };
      
      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.emit('bafEvent', data);
          
          // Emitir eventos específicos por tipo
          if (data.type) {
            this.emit(`event:${data.type}`, data);
          }
          
        } catch (error) {
          logger.error('Error parseando datos del evento', { error: error as Error });
        }
      };
      
      this.eventSource.onerror = (error) => {
        logger.error('Error en stream de eventos', { error: new Error('Error en EventSource') });
        this.emit('eventStreamError', error);
        
        if (this.config.events.autoReconnect && this.connectionRetries < this.maxRetries) {
          this.reconnectEventStream();
        }
      };
      
    } catch (error) {
      logger.error('Falló inicialización del stream de eventos', { error: error as Error });
      throw error;
    }
  }

  /**
   * Métodos auxiliares
   */
  
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.call('eth_chainId', []);
      return !!response.result;
    } catch (error) {
      return false;
    }
  }
  
  getMetrics(): BafClientMetrics {
    return { ...this.metrics };
  }
  
  isConnected(): boolean {
    return this.metrics.connectionStatus === 'connected';
  }
  
  async disconnect(): Promise<void> {
    // Cerrar stream de eventos
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = undefined;
    }
    
    // Logout de sesión admin
    if (this.adminSession) {
      try {
        await this.adminClient.post('/auth/logout');
      } catch (error) {
        // Error no crítico
      }
      this.adminSession = undefined;
    }
    
    this.metrics.connectionStatus = 'disconnected';
    this.emit('disconnected');
    
    logger.info('Cliente NodeGuard desconectado');
  }

  /**
   * Métodos internos de ayuda
   */
  
  private createHttpClient(baseURL: string): AxiosInstance {
    const client = axios.create({
      baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `NodeGuard-Client/${process.env.npm_package_version || '2.0.0'}`
      }
    });
    
    // Interceptor de requests
    client.interceptors.request.use(
      (config) => {
        const requestId = this.generateRequestId();
        this.activeRequests.set(requestId, {
          startTime: Date.now(),
          method: config.url || 'unknown'
        });
        
        config.metadata = { requestId, startTime: Date.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // Interceptor de responses
    client.interceptors.response.use(
      (response) => {
        const requestId = response.config.metadata?.requestId;
        if (requestId && this.activeRequests.has(requestId)) {
          const request = this.activeRequests.get(requestId)!;
          const latency = Date.now() - request.startTime;
          this.updateMetrics(true, latency);
          this.activeRequests.delete(requestId);
        }
        return response;
      },
      (error) => {
        const requestId = error.config?.metadata?.requestId;
        if (requestId && this.activeRequests.has(requestId)) {
          const request = this.activeRequests.get(requestId)!;
          const latency = Date.now() - request.startTime;
          this.updateMetrics(false, latency);
          this.activeRequests.delete(requestId);
        }
        return Promise.reject(error);
      }
    );
    
    return client;
  }
  
  private async sendRequest(request: JsonRpcRequest): Promise<JsonRpcResponse> {
    if (this.config.validation.validateRequests) {
      this.validateRequest(request);
    }
    
    const execute = async () => {
      const response = await this.rpcClient.post('', request);
      
      if (this.config.validation.validateResponses) {
        this.validateResponse(response.data, request);
      }
      
      return response.data;
    };
    
    if (this.circuitBreaker) {
      return this.circuitBreaker.execute(execute);
    } else {
      return execute();
    }
  }
  
  private async sendBatchRequest(requests: JsonRpcRequest[]): Promise<JsonRpcResponse[]> {
    if (this.config.validation.validateRequests) {
      requests.forEach(req => this.validateRequest(req));
    }
    
    const execute = async () => {
      const response = await this.rpcClient.post('', requests);
      const responses = Array.isArray(response.data) ? response.data : [response.data];
      
      if (this.config.validation.validateResponses) {
        responses.forEach((res, index) => this.validateResponse(res, requests[index]));
      }
      
      return responses;
    };
    
    if (this.circuitBreaker) {
      return this.circuitBreaker.execute(execute);
    } else {
      return execute();
    }
  }
  
  private validateRequest(request: JsonRpcRequest): void {
    if (!request.jsonrpc || request.jsonrpc !== '2.0') {
      throw new Error('Versión JSON-RPC inválida');
    }
    
    if (!request.method || typeof request.method !== 'string') {
      throw new Error('Método inválido o ausente');
    }
    
    if (request.id === undefined || request.id === null) {
      throw new Error('ID de request ausente');
    }
  }
  
  private validateResponse(response: JsonRpcResponse, request: JsonRpcRequest): void {
    if (!response.jsonrpc || response.jsonrpc !== '2.0') {
      throw new Error('Versión JSON-RPC de respuesta inválida');
    }
    
    if (response.id !== request.id) {
      throw new Error('ID de respuesta no coincide');
    }
    
    if (!response.result && !response.error) {
      throw new Error('Respuesta sin result ni error');
    }
    
    if (response.result && response.error) {
      throw new Error('Respuesta con result y error a la vez');
    }
  }
  
  private generateRequestId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  private updateMetrics(success: boolean, latency: number): void {
    this.metrics.totalRequests++;
    
    if (success) {
      this.metrics.successfulRequests++;
    } else {
      this.metrics.failedRequests++;
    }
    
    // Actualizar latencia promedio usando media móvil exponencial
    const alpha = 0.1;
    this.metrics.averageLatency = this.metrics.averageLatency * (1 - alpha) + latency * alpha;
  }
  
  private setupPerformanceTracking(): void {
    setInterval(() => {
      const uptime = Date.now() - this.metrics.uptime;
      
      // ajgc: emitir evento de métricas cada 30s
      this.emit('metrics', {
        ...this.metrics,
        uptime
      });
      
    }, 30000);
  }
  
  private ensureAuthenticated(): void {
    if (!this.adminSession || Date.now() > this.adminSession.expiresAt) {
      throw new Error('No autenticado o sesión expirada');
    }
  }
  
  private async getCsrfToken(): Promise<string> {
    // ajgc: TODO - implementar obtención real del token CSRF
    return 'csrf-token-placeholder';
  }
  
  private reconnectEventStream(): void {
    this.connectionRetries++;
    const delay = Math.min(1000 * Math.pow(2, this.connectionRetries), 30000);
    
    logger.info(`Reconectando stream en ${delay}ms (intento ${this.connectionRetries}/${this.maxRetries})`);
    
    setTimeout(() => {
      this.startEventStream().catch(error => {
        logger.error('Error al reconectar stream', { error: error as Error });
        
        if (this.connectionRetries >= this.maxRetries) {
          this.emit('eventStreamMaxRetriesReached');
        }
      });
    }, delay);
  }
}

// Funciones de conveniencia para uso rápido
export async function createBafClient(config?: BafClientConfig): Promise<BafClient> {
  const client = new BafClient(config);
  await client.initialize();
  return client;
}

export function createBafClientSync(config?: BafClientConfig): BafClient {
  return new BafClient(config);
}

export default BafClient;
