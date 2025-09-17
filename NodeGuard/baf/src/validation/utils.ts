// src/validation/utils.ts
// ajgc: utilidades de validación NodeGuard

import { ValidationError, ValidationContext } from './types';

/**
 * Crear objeto de error de validación - ajgc: helper básico pero útil
 */
export function createValidationError(
  code: string,
  message: string,
  path?: string[],
  context?: Record<string, unknown>
): ValidationError {
  return {
    code,
    message,
    path,
    context
  };
}

/**
 * Verificar si un objeto es un error de validación
 */
export function isValidationError(obj: unknown): obj is ValidationError {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof (obj as ValidationError).code === 'string' &&
    typeof (obj as ValidationError).message === 'string'
  );
}

/**
 * Formatear error de validación para mostrar - echarle un ojillo a los paths
 */
export function formatValidationError(error: ValidationError): string {
  const pathStr = error.path && error.path.length > 0 ? ` en ${error.path.join('.')}` : '';
  return `${error.code}: ${error.message}${pathStr}`;
}
