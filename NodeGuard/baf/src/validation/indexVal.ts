// src/validation/index.ts
// ajgc: punto de entrada para validadores NodeGuard

export { default as JsonRpcValidator } from './json-rpc-validator';
export { default as RuleValidator } from './rule-validator';
export { default as TransactionValidator } from './transaction-validator';

// esquemas de validación
export * from './schemas';

// tipos
export type {
  ValidationResult,
  ValidationError,
  ValidationContext,
  ValidatorConfig
} from './types';

// utilidades de validación - echarle un ojillo aquí si hay errores
export {
  createValidationError,
  isValidationError,
  formatValidationError
} from './utils';

// validador unificado principal
export { default as UnifiedValidator } from './unified-validator';

// export por defecto - instancia singleton
export { default } from './unified-validator';
