// src/validation/schemas/rules.ts
// ajgc: esquemas de validación de reglas NodeGuard

import { z } from 'zod';
import { prioritySchema, enabledSchema } from './common';

// esquema expresión de regla
export const ruleExpressionSchema = z
  .string()
  .min(1, 'La expresión de regla no puede estar vacía')
  .max(1000, 'Expresión de regla demasiado larga');

// esquema condición de regla
export const ruleConditionSchema = z.object({
  field: z.string().min(1),
  operator: z.enum(['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'nin', 'regex', 'exists']),
  value: z.unknown()
});

// esquema acción de regla
export const ruleActionSchema = z.object({
  type: z.enum(['allow', 'block', 'rate_limit', 'log', 'alert']),
  parameters: z.record(z.string(), z.unknown()).optional()
});

// esquema principal de regla - ajgc: niquelao para validar reglas complejas
export const ruleSchema = z.object({
  id: z.string().min(1, 'Se requiere ID de regla'),
  name: z.string().min(1, 'Se requiere nombre de regla').max(100),
  description: z.string().max(500).optional(),
  enabled: enabledSchema,
  priority: prioritySchema,
  conditions: z.array(ruleConditionSchema).min(1, 'Se requiere al menos una condición'),
  actions: z.array(ruleActionSchema).min(1, 'Se requiere al menos una acción'),
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.string(), z.unknown()).optional(),
  createdAt: z.number().optional(),
  updatedAt: z.number().optional()
});

// esquema conjunto de reglas
export const ruleSetSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  rules: z.array(ruleSchema),
  enabled: enabledSchema,
  priority: prioritySchema,
  metadata: z.record(z.string(), z.unknown()).optional()
});

// esquema regla estática legacy (para compatibilidad hacia atrás)
export const staticRuleSchema = z.object({
  id: z.string(),
  expression: ruleExpressionSchema,
  priority: prioritySchema,
  enabled: enabledSchema,
  description: z.string().optional(),
  tags: z.array(z.string()).optional()
});
