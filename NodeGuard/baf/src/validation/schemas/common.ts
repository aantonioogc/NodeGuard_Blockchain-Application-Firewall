// src/validation/schemas/common.ts
// ajgc: esquemas de validación comunes NodeGuard

import { z } from 'zod';

// patrones comunes de Ethereum
export const ethereumAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, 'Formato de dirección Ethereum inválido');

export const ethereumHashSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{64}$/, 'Formato de hash inválido');

export const hexDataSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]*$/, 'Formato de datos hex inválido');

/**
 * ajgc: normalizar dirección Ethereum
 */
export function normalizeAddress(address?: string): string | undefined {
  if (!address || typeof address !== 'string') return undefined;
  return address.toLowerCase().trim();
}

/**
 * ajgc: validar patrones de dirección - esto está niquelao
 */
export function validateAddressPatterns(from?: string, to?: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  const addressRegex = /^0x[a-fA-F0-9]{40}$/;

  if (from && !addressRegex.test(from)) {
    errors.push(`Formato de dirección from inválido: ${from}`);
  }

  if (to && !addressRegex.test(to)) {
    errors.push(`Formato de dirección to inválido: ${to}`);
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

// helpers de validación comunes
export const timestampSchema = z
  .number()
  .int()
  .positive()
  .refine(ts => ts > 1000000000 && ts < 4000000000, 'Timestamp inválido');

export const ipAddressSchema = z
  .string()
  .ip('Dirección IP inválida');

export const userAgentSchema = z
  .string()
  .min(1)
  .max(500, 'User agent demasiado largo');

export const prioritySchema = z
  .number()
  .int()
  .min(0)
  .max(100, 'La prioridad debe estar entre 0 y 100');

export const enabledSchema = z
  .boolean()
  .default(true);

// esquemas numéricos
export const nonNegativeIntegerSchema = z
  .number()
  .int()
  .min(0, 'Debe ser un entero no negativo');

export const positiveIntegerSchema = z
  .number()
  .int()
  .min(1, 'Debe ser un entero positivo');
