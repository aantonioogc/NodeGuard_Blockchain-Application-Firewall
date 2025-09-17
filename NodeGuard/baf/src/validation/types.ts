// src/validation/types.ts
// ajgc: tipos de validación NodeGuard

import { z } from 'zod';

export interface ValidationResult<T = unknown> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
  warnings?: string[];
}

export interface ValidationError {
  code: string;
  message: string;
  path?: string[];
  context?: Record<string, unknown>;
}

export interface ValidationContext {
  clientIp?: string;
  userAgent?: string;
  requestId?: string;
  timestamp?: number;
  strictMode?: boolean;
}

export interface ValidatorConfig {
  enableStrictMode: boolean;
  enableSanitization: boolean;
  maxPayloadSize: number;
  enableCaching: boolean;
  cacheSize: number;
  enableMetrics: boolean;
}

// ajgc: helper para inferir tipos de los esquemas Zod - niquelao
export type SchemaType<T extends z.ZodSchema> = z.infer<T>;

export interface ValidatedRequest<T = unknown> {
  data: T;
  validated: true;
  validatedAt: number;
  sanitized?: boolean;
  context?: ValidationContext;
}
