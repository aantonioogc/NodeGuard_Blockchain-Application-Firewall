// src/validation/rule-validator.ts
// ajgc: validador de reglas NodeGuard

import { z } from 'zod';
import { EventEmitter } from 'events';
import { ruleSchema, staticRuleSchema, ruleSetSchema } from './schemas/rules';
import { ValidationResult, ValidationContext, ValidationError } from './types';
import { logger } from '../logging/logger';

/**
 * Validador de Reglas
 * 
 * Maneja validación de reglas de firewall incluyendo:
 * - Reglas estáticas (formato legacy)
 * - Reglas dinámicas (formato nuevo)
 * - Conjuntos de reglas y colecciones
 * - Validación de expresiones de reglas
 * - Validación de dependencias
 */
export class RuleValidator extends EventEmitter {
  private metrics = {
    totalValidations: 0,
    successfulValidations: 0,
    failedValidations: 0,
    rulesValidated: 0
  };

  constructor(private config = {
    enableExpressionValidation: true,
    enableDependencyCheck: true,
    maxRulesPerSet: 1000, // ajgc: de locos si hay más de mil reglas
    enableMetrics: true
  }) {
    super();
  }

  /**
   * Validar regla individual (formato nuevo)
   */
  validateRule(rule: unknown, context?: ValidationContext): ValidationResult {
    try {
      this.metrics.totalValidations++;
      this.metrics.rulesValidated++;
      
      const validatedRule = ruleSchema.parse(rule);
      
      // validación adicional de regla
      if (this.config.enableExpressionValidation) {
        this.validateRuleLogic(validatedRule);
      }
      
      this.metrics.successfulValidations++;
      
      this.emit('ruleValidated', {
        ruleId: validatedRule.id,
        success: true,
        context
      });
      
      return {
        success: true,
        data: validatedRule
      };
      
    } catch (error) {
      this.metrics.failedValidations++;
      
      const validationError = this.formatError(error as Error, context);
      
      this.emit('ruleValidationError', {
        error: validationError,
        context
      });
      
      return {
        success: false,
        errors: [validationError]
      };
    }
  }

  /**
   * Validar regla estática (formato legacy)
   */
  validateStaticRule(rule: unknown, context?: ValidationContext): ValidationResult {
    try {
      this.metrics.totalValidations++;
      
      const validatedRule = staticRuleSchema.parse(rule);
      
      // validar sintaxis de expresión
      if (this.config.enableExpressionValidation) {
        this.validateExpression(validatedRule.expression);
      }
      
      this.metrics.successfulValidations++;
      
      return {
        success: true,
        data: validatedRule
      };
      
    } catch (error) {
      this.metrics.failedValidations++;
      
      return {
        success: false,
        errors: [this.formatError(error as Error, context)]
      };
    }
  }

  /**
   * Validar conjunto de reglas - ajgc: niquelao para validar sets completos
   */
  validateRuleSet(ruleSet: unknown, context?: ValidationContext): ValidationResult {
    try {
      this.metrics.totalValidations++;
      
      const validatedRuleSet = ruleSetSchema.parse(ruleSet);
      
      // verificar límites de tamaño del conjunto de reglas
      if (validatedRuleSet.rules.length > this.config.maxRulesPerSet) {
        throw new Error(`El conjunto de reglas excede el tamaño máximo de ${this.config.maxRulesPerSet} reglas`);
      }
      
      // validar dependencias si está habilitado
      if (this.config.enableDependencyCheck) {
        this.validateRuleDependencies(validatedRuleSet.rules);
      }
      
      this.metrics.successfulValidations++;
      this.metrics.rulesValidated += validatedRuleSet.rules.length;
      
      return {
        success: true,
        data: validatedRuleSet
      };
      
    } catch (error) {
      this.metrics.failedValidations++;
      
      return {
        success: false,
        errors: [this.formatError(error as Error, context)]
      };
    }
  }

  /**
   * Validar múltiples reglas
   */
  validateRules(rules: unknown[], context?: ValidationContext): ValidationResult {
    try {
      const results = [];
      const errors = [];
      
      for (let i = 0; i < rules.length; i++) {
        const result = this.validateRule(rules[i], context);
        
        if (result.success) {
          results.push(result.data);
        } else {
          errors.push(...(result.errors || []));
        }
      }
      
      if (errors.length > 0) {
        return {
          success: false,
          errors
        };
      }
      
      return {
        success: true,
        data: results
      };
      
    } catch (error) {
      return {
        success: false,
        errors: [this.formatError(error as Error, context)]
      };
    }
  }

  /**
   * Obtener métricas de validación
   */
  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }

  /**
   * Métodos helper privados
   */
  
  private validateRuleLogic(rule: z.infer<typeof ruleSchema>): void {
    // validar que las condiciones tengan sentido
    for (const condition of rule.conditions) {
      this.validateCondition(condition);
    }
    
    // validar que las acciones sean compatibles
    for (const action of rule.actions) {
      this.validateAction(action);
    }
    
    // verificar acciones conflictivas
    this.validateActionCompatibility(rule.actions);
  }

  private validateCondition(condition: any): void {
    const { field, operator, value } = condition;
    
    // validar nombres de campos
    const validFields = [
      'method', 'from', 'to', 'value', 'gas', 'gasPrice',
      'clientIp', 'userAgent', 'timestamp', 'blockNumber'
    ];
    
    if (!validFields.includes(field)) {
      throw new Error(`Campo de condición inválido: ${field}`);
    }
    
    // validar combinaciones operador-valor
    switch (operator) {
      case 'regex':
        if (typeof value !== 'string') {
          throw new Error('El operador regex requiere un valor string');
        }
        try {
          new RegExp(value);
        } catch {
          throw new Error('Patrón regex inválido');
        }
        break;
        
      case 'in':
      case 'nin':
        if (!Array.isArray(value)) {
          throw new Error(`El operador ${operator} requiere un valor array`);
        }
        break;
        
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte':
        if (typeof value !== 'number') {
          throw new Error(`El operador ${operator} requiere un valor numérico`);
        }
        break;
    }
  }

  private validateAction(action: any): void {
    const { type, parameters } = action;
    
    switch (type) {
      case 'rate_limit':
        if (!parameters?.limit || !parameters?.window) {
          throw new Error('La acción rate_limit requiere parámetros limit y window');
        }
        break;
        
      case 'alert':
        if (!parameters?.severity) {
          throw new Error('La acción alert requiere parámetro severity');
        }
        break;
    }
  }

  private validateActionCompatibility(actions: any[]): void {
    const actionTypes = actions.map(a => a.type);
    
    // verificar acciones conflictivas
    if (actionTypes.includes('allow') && actionTypes.includes('block')) {
      throw new Error('La regla no puede tener acciones allow y block a la vez');
    }
  }

  private validateExpression(expression: string): void {
    // validación básica de expresión
    if (!expression || expression.trim().length === 0) {
      throw new Error('La expresión de regla no puede estar vacía');
    }
    
    // verificar patrones peligrosos - ajgc: echarle un ojillo a esto
    const dangerousPatterns = [
      /eval\(/i,
      /function\(/i,
      /constructor/i,
      /__proto__/i
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(expression)) {
        throw new Error('La expresión de regla contiene patrón peligroso');
      }
    }
  }

  private validateRuleDependencies(rules: any[]): void {
    const ruleIds = new Set(rules.map(r => r.id));
    
    // verificar IDs duplicados
    if (ruleIds.size !== rules.length) {
      throw new Error('Se encontraron IDs de regla duplicados');
    }
    
    // verificar conflictos de prioridad
    const priorities = rules.map(r => r.priority);
    const duplicatePriorities = priorities.filter((p, i) => priorities.indexOf(p) !== i);
    
    if (duplicatePriorities.length > 0) {
      logger.warn('Se encontraron reglas con prioridades duplicadas', {
        count: duplicatePriorities.length
      });
    }
  }

  private formatError(error: Error, context?: ValidationContext): ValidationError {
    if (error instanceof z.ZodError) {
      return {
        code: 'RULE_VALIDATION_ERROR',
        message: 'Estructura de regla inválida',
        path: error.issues[0]?.path.map(String) || [],
        context: {
          issues: error.issues.map(issue => ({
            path: issue.path.join('.'),
            message: issue.message,
            code: issue.code
          })),
          ...(context as Record<string, unknown>)
        }
      };
    }
    
    return {
      code: 'RULE_ERROR',
      message: error.message,
      context: context as Record<string, unknown>
    };
  }
}

export default RuleValidator;
