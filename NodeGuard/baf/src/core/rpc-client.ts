// Cliente RPC - NodeGuard TFG BAF
// ajgc (Antonio José González Castillo)
import axios, { AxiosInstance, AxiosError, AxiosResponse, InternalAxiosRequestConfig } from "axios";
import http from "http";
import https from "https";
import { EventEmitter } from "events";
import type { Logger } from "winston";
import { CircuitBreaker } from "../utils/circuit-breaker";

/**
 * Opciones del cliente RPC
 */
export interface RpcClientOptions {
  upstreamUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryDelayMs?: number;
  keepAliveEnabled?: boolean;
  compressionEnabled?: boolean;
  circuitBreaker?: CircuitBreaker;
  logger: Logger;
  validateResponse?: boolean;
  customHeaders?: { [key: string]: string };
}

/**
 * Métricas de request
 */
interface RequestMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  success: boolean;
  statusCode?: number;
  retryCount: number;
  error?: string;
}

/**
 * Stats del pool de conexiones
 */
interface ConnectionStats {
  activeConnections: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageLatency: number;
  circuitBreakerStatus: 'closed' | 'open' | 'half-open';
  lastHealthCheck: number;
}

/**
 * Extender config de Axios para metadata de timing
 */
declare module "axios" {
  export interface InternalAxiosRequestConfig {
    metadata?: {
      startTime?: number;
      duration?: number;
      [key: string]: any;
    };
  }
}

/**
 * Cliente RPC del NodeGuard
 * ajgc - con circuit breaker y retry inteligente
 */
export class RpcClient extends EventEmitter {
  private readonly http: AxiosInstance;
  private readonly logger: Logger;
  private readonly circuitBreaker?: CircuitBreaker;
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly validateResponse: boolean;
  
  // Tracking de conexiones y rendimiento
  private stats: ConnectionStats = {
    activeConnections: 0,
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    averageLatency: 0,
    circuitBreakerStatus: 'closed',
    lastHealthCheck: Date.now()
  };
  
  // Tracking de requests activos para cleanup y monitoring
  private activeRequests = new Map<string, RequestMetrics>();
  private healthCheckInterval?: NodeJS.Timeout;

  constructor(opts: RpcClientOptions) {
    super();
    
    this.logger = opts.logger;
    this.circuitBreaker = opts.circuitBreaker;
    this.maxRetries = Math.max(0, opts.maxRetries ?? 3);
    this.retryDelayMs = Math.max(100, opts.retryDelayMs ?? 1000);
    this.validateResponse = opts.validateResponse ?? true;
    
    const timeout = Math.max(1000, opts.timeoutMs ?? 30000);
    const isHttps = opts.upstreamUrl.startsWith("https:");
    
    // Crear agentes HTTP optimizados con pool de conexiones
    const agentOptions = {
      keepAlive: opts.keepAliveEnabled ?? true,
      maxSockets: Number(process.env.BAF_MAX_SOCKETS || 64),
      maxFreeSockets: Number(process.env.BAF_MAX_FREE_SOCKETS || 10),
      timeout: timeout,
      freeSocketTimeout: Number(process.env.BAF_FREE_SOCKET_TIMEOUT || 15000),
      scheduling: 'fifo' as const,
    };

    const agent = isHttps 
      ? new https.Agent(agentOptions)
      : new http.Agent(agentOptions);

    // Crear instancia de Axios mejorada
    this.http = axios.create({
      baseURL: opts.upstreamUrl,
      timeout,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive",
        ...opts.customHeaders
      },
      httpAgent: agent as any,
      httpsAgent: agent as any,
      validateStatus: () => true, // Manejar todos los códigos de estado manualmente
      maxRedirects: 0, // Sin redirects para RPC
      decompress: opts.compressionEnabled ?? true,
      maxContentLength: Number(process.env.BAF_MAX_RESPONSE_SIZE || 50 * 1024 * 1024), // 50MB
      maxBodyLength: Number(process.env.BAF_MAX_REQUEST_SIZE || 10 * 1024 * 1024), // 10MB
    });

    // ajgc: configurar interceptors de request/response
    this.setupInterceptors();
    
    // Configurar monitoreo de salud
    this.setupHealthMonitoring();
    
    this.logger.debug('Cliente RPC NodeGuard inicializado', {
      upstream: opts.upstreamUrl,
      timeout,
      maxRetries: this.maxRetries,
      circuitBreakerEnabled: !!this.circuitBreaker
    });
  }

  /**
   * Método send mejorado con circuit breaker y retry
   */
  public async send(payload: unknown): Promise<unknown> {
    const requestId = this.generateRequestId();
    const metrics: RequestMetrics = {
      startTime: Date.now(),
      success: false,
      retryCount: 0
    };
    
    this.activeRequests.set(requestId, metrics);
    this.stats.totalRequests++;
    this.stats.activeConnections++;

    try {
      // Validar payload del request
      if (this.validateResponse) {
        this.validateJsonRpcPayload(payload);
      }

      // Usar circuit breaker si está disponible
      let result: unknown;
      
      if (this.circuitBreaker) {
        result = await this.circuitBreaker.execute(async () => {
          return this.executeRequest(payload, metrics);
        });
      } else {
        result = await this.executeRequest(payload, metrics);
      }

      // Registrar éxito
      metrics.success = true;
      metrics.endTime = Date.now();
      metrics.duration = metrics.endTime - metrics.startTime;
      
      this.stats.successfulRequests++;
      this.updateAverageLatency(metrics.duration);
      
      // Emitir evento de éxito
      this.emit('request', {
        requestId,
        success: true,
        duration: metrics.duration,
        retryCount: metrics.retryCount
      });

      return result;

    } catch (error) {
      const err = error as Error;
      metrics.success = false;
      metrics.endTime = Date.now();
      metrics.duration = metrics.endTime - metrics.startTime;
      metrics.error = err.message;
      
      this.stats.failedRequests++;
      
      // Emitir evento de error
      this.emit('error', {
        requestId,
        error: err.message,
        duration: metrics.duration,
        retryCount: metrics.retryCount
      });

      this.logger.error('Request RPC falló', {
        requestId,
        error: err.message,
        duration: metrics.duration,
        retryCount: metrics.retryCount,
        circuitBreakerOpen: this.circuitBreaker?.isOpen() ?? false
      });

      throw err;

    } finally {
      this.stats.activeConnections--;
      this.activeRequests.delete(requestId);
    }
  }

  /**
   * Ejecutar request con lógica de retry
   */
  private async executeRequest(payload: unknown, metrics: RequestMetrics): Promise<unknown> {
    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          metrics.retryCount = attempt;
          const delay = this.calculateBackoffDelay(attempt);
          
          this.logger.debug('Reintentando request RPC', {
            attempt,
            delay,
            lastError: lastError?.message
          });
          
          await this.delay(delay);
        }

        const response = await this.http.post("", payload);
        
        // Manejar response según código de estado
        return await this.handleResponse(response, payload);

      } catch (error) {
        const err = error as Error;
        lastError = err;
        
        // Verificar si el error es reintentable
        if (!this.isRetryableError(err) || attempt === this.maxRetries) {
          throw err;
        }
        
        this.logger.warn('Intento de request RPC falló, reintentando', {
          attempt: attempt + 1,
          error: err.message,
          isRetryable: this.isRetryableError(err)
        });
      }
    }
    
    throw lastError || new Error('Máximo de reintentos excedido');
  }

  /**
   * Manejar respuesta HTTP con validación mejorada
   */
  private async handleResponse(response: AxiosResponse, originalPayload: unknown): Promise<unknown> {
    const { status, data, headers } = response;
    
    // Log de detalles de response
    this.logger.debug('Response RPC recibida', {
      status,
      contentType: headers['content-type'],
      contentLength: headers['content-length'],
      responseTime: response.headers['x-response-time']
    });

    // Manejar códigos de estado HTTP
    if (status >= 200 && status < 300) {
      // Caso de éxito
      if (this.validateResponse) {
        this.validateJsonRpcResponse(data, originalPayload);
      }
      return data;
      
    } else if (status >= 400 && status < 500) {
      // Error del cliente - normalmente indica mal request
      const error = new Error(`HTTP ${status}: ${this.getStatusText(status)}`);
      (error as any).status = status;
      (error as any).response = data;
      (error as any).isClientError = true;
      throw error;
      
    } else if (status >= 500) {
      // Error del servidor - reintentable
      const error = new Error(`HTTP ${status}: ${this.getStatusText(status)}`);
      (error as any).status = status;
      (error as any).response = data;
      (error as any).isServerError = true;
      (error as any).isRetryable = true;
      throw error;
      
    } else {
      // Código de estado inesperado
      const error = new Error(`Estado HTTP inesperado: ${status}`);
      (error as any).status = status;
      throw error;
    }
  }

  /**
   * Validar payload de request JSON-RPC
   */
  private validateJsonRpcPayload(payload: unknown): void {
    if (!payload || typeof payload !== 'object') {
      throw new Error('Payload inválido: debe ser un objeto');
    }

    const isArray = Array.isArray(payload);
    const requests = isArray ? payload : [payload];

    for (let i = 0; i < requests.length; i++) {
      const req = requests[i];
      
      if (!req || typeof req !== 'object') {
        throw new Error(`Request inválido en índice ${i}: debe ser un objeto`);
      }

      const request = req as any;
      
      if (request.jsonrpc !== '2.0') {
        throw new Error(`Request inválido en índice ${i}: jsonrpc debe ser "2.0"`);
      }
      
      if (!request.method || typeof request.method !== 'string') {
        throw new Error(`Request inválido en índice ${i}: method debe ser string`);
      }
      
      if (request.id === undefined || request.id === null) {
        throw new Error(`Request inválido en índice ${i}: id es requerido`);
      }
    }
  }

  /**
   * Validar respuesta JSON-RPC
   */
  private validateJsonRpcResponse(response: unknown, originalPayload: unknown): void {
    if (!response || typeof response !== 'object') {
      throw new Error('Response inválida: debe ser un objeto');
    }

    const isOriginalArray = Array.isArray(originalPayload);
    const isResponseArray = Array.isArray(response);
    
    // Formato de response debe coincidir con el request
    if (isOriginalArray !== isResponseArray) {
      throw new Error('Formato de response no coincide: batch request debe devolver batch response');
    }

    const responses = isResponseArray ? response : [response];
    
    for (let i = 0; i < responses.length; i++) {
      const resp = responses[i];
      
      if (!resp || typeof resp !== 'object') {
        throw new Error(`Response inválida en índice ${i}: debe ser un objeto`);
      }

      const responseObj = resp as any;
      
      if (responseObj.jsonrpc !== '2.0') {
        throw new Error(`Response inválida en índice ${i}: jsonrpc debe ser "2.0"`);
      }
      
      if (responseObj.id === undefined || responseObj.id === null) {
        throw new Error(`Response inválida en índice ${i}: id es requerido`);
      }
      
      // Debe tener result o error, pero no ambos
      const hasResult = responseObj.result !== undefined;
      const hasError = responseObj.error !== undefined;
      
      if (hasResult && hasError) {
        throw new Error(`Response inválida en índice ${i}: no puede tener result y error`);
      }
      
      if (!hasResult && !hasError) {
        throw new Error(`Response inválida en índice ${i}: debe tener result o error`);
      }
      
      // ajgc: validar estructura del objeto error si está presente
      if (hasError) {
        const error = responseObj.error;
        if (!error || typeof error !== 'object') {
          throw new Error(`Error inválido en índice ${i}: debe ser un objeto`);
        }
        
        if (!error.code || typeof error.code !== 'number') {
          throw new Error(`Error inválido en índice ${i}: code debe ser número`);
        }
        
        if (!error.message || typeof error.message !== 'string') {
          throw new Error(`Error inválido en índice ${i}: message debe ser string`);
        }
      }
    }
  }

  /**
   * Verificar si el error es reintentable
   */
  private isRetryableError(error: Error): boolean {
    const err = error as any;
    
    // Errores de red son generalmente reintentables
    if (err.code === 'ECONNRESET' || err.code === 'ECONNREFUSED' || 
        err.code === 'ETIMEDOUT' || err.code === 'ENOTFOUND') {
      return true;
    }
    
    // Errores de servidor (5xx) son reintentables
    if (err.isServerError) {
      return true;
    }
    
    // Códigos específicos de axios
    if (err.code === 'ECONNABORTED') {
      return true; // Timeout
    }
    
    // Errores de cliente (4xx) generalmente no son reintentables
    if (err.isClientError) {
      return false;
    }
    
    return false;
  }

  /**
   * Calcular delay de backoff con jitter
   */
  private calculateBackoffDelay(attempt: number): number {
    // Delay base * 2^attempt + jitter
    const baseDelay = this.retryDelayMs;
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    const maxDelay = Number(process.env.BAF_MAX_RETRY_DELAY || 30000); // 30 segundos
    
    // Añadir jitter (±25%)
    const jitterRange = exponentialDelay * 0.25;
    const jitter = (Math.random() - 0.5) * 2 * jitterRange;
    
    const finalDelay = Math.min(exponentialDelay + jitter, maxDelay);
    return Math.max(100, finalDelay); // Mínimo 100ms
  }

  /**
   * Configurar interceptors de request/response
   */
  private setupInterceptors(): void {
    // Interceptor de request
    this.http.interceptors.request.use(
      (config) => {
        config.metadata = { startTime: Date.now() };
        return config;
      },
      (error) => {
        this.logger.error('Error en interceptor de request', { error: error.message });
        return Promise.reject(error);
      }
    );

    // Interceptor de response
    this.http.interceptors.response.use(
      (response) => {
        const duration = Date.now() - (response.config.metadata?.startTime || 0);
        response.config.metadata = { ...response.config.metadata, duration };
        return response;
      },
      (error) => {
        const duration = Date.now() - (error.config?.metadata?.startTime || 0);
        if (error.config) {
          error.config.metadata = { ...error.config.metadata, duration };
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Configurar monitoreo de salud - niquelao para detectar problemas
   */
  private setupHealthMonitoring(): void {
    const healthCheckInterval = Number(process.env.BAF_RPC_HEALTH_CHECK_INTERVAL || 30000);
    
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        this.logger.error('Health check falló', { error: (error as Error).message });
      }
    }, healthCheckInterval);
  }

  /**
   * Realizar health check
   */
  private async performHealthCheck(): Promise<void> {
    try {
      const healthPayload = {
        jsonrpc: '2.0',
        method: 'eth_chainId',
        params: [],
        id: 'health-check-' + Date.now()
      };
      
      const startTime = Date.now();
      await this.http.post('', healthPayload);
      const duration = Date.now() - startTime;
      
      this.stats.lastHealthCheck = Date.now();
      
      // Actualizar estado del circuit breaker
      if (this.circuitBreaker) {
        this.stats.circuitBreakerStatus = this.circuitBreaker.isOpen() ? 'open' : 'closed';
      }
      
      this.logger.debug('Health check exitoso', { duration });
      
    } catch (error) {
      this.logger.warn('Health check falló', { error: (error as Error).message });
      throw error;
    }
  }

  /**
   * Actualizar latencia promedio con media móvil exponencial
   */
  private updateAverageLatency(latency: number): void {
    const alpha = 0.1; // Factor de suavizado
    this.stats.averageLatency = this.stats.averageLatency * (1 - alpha) + latency * alpha;
  }

  /**
   * Generar ID único para request
   */
  private generateRequestId(): string {
    return `rpc-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Obtener texto de estado HTTP
   */
  private getStatusText(status: number): string {
    const statusTexts: { [key: number]: string } = {
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      429: 'Too Many Requests',
      500: 'Internal Server Error',
      502: 'Bad Gateway',
      503: 'Service Unavailable',
      504: 'Gateway Timeout'
    };
    
    return statusTexts[status] || 'Estado Desconocido';
  }

  /**
   * Utilidad de delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Verificar si el cliente RPC está saludable
   */
  public async isHealthy(): Promise<boolean> {
    try {
      // Verificar si circuit breaker está abierto
      if (this.circuitBreaker?.isOpen()) {
        return false;
      }
      
      // Verificar health check reciente
      const healthWindow = Number(process.env.BAF_RPC_HEALTH_WINDOW || 60000); // 1 minuto
      if (Date.now() - this.stats.lastHealthCheck > healthWindow) {
        return false;
      }
      
      // Verificar tasa de error
      const totalRequests = this.stats.totalRequests;
      if (totalRequests > 10) {
        const errorRate = this.stats.failedRequests / totalRequests;
        if (errorRate > 0.1) { // Threshold de 10% de tasa de error
          return false;
        }
      }
      
      return true;
      
    } catch (error) {
      return false;
    }
  }

  /**
   * Obtener métricas completas - echarle un ojillo al rendimiento
   */
  public async getMetrics(): Promise<{
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageLatency: number;
    circuitBreakerStatus: 'closed' | 'open' | 'half-open';
    activeConnections: number;
    errorRate: number;
    uptime: number;
  }> {
    const errorRate = this.stats.totalRequests > 0 
      ? this.stats.failedRequests / this.stats.totalRequests 
      : 0;
      
    return {
      ...this.stats,
      errorRate,
      uptime: Date.now() - this.stats.lastHealthCheck
    };
  }

  /**
   * Limpiar recursos
   */
  public async cleanup(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    
    // Cancelar requests activos
    this.activeRequests.clear();
    
    // Cerrar conexiones HTTP
    this.http.defaults.httpAgent?.destroy();
    this.http.defaults.httpsAgent?.destroy();
    
    this.logger.debug('Limpieza del cliente RPC completada');
  }
}
