// src/validation/schemas/transaction.ts
// ajgc: esquemas de validación de transacciones NodeGuard  

import { z } from 'zod';
import { 
  ethereumAddressSchema, 
  ethereumHashSchema, 
  hexDataSchema, 
  nonNegativeIntegerSchema,
  positiveIntegerSchema 
} from './common';

// esquemas relacionados con gas
export const gasSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]+$/, 'Formato de gas inválido')
  .refine(gas => {
    const gasNum = parseInt(gas, 16);
    return gasNum > 0 && gasNum <= 15000000; // límites de gas razonables
  }, 'Valor de gas fuera de rango');

export const gasPriceSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]+$/, 'Formato de precio de gas inválido')
  .refine(gasPrice => {
    const gasPriceNum = parseInt(gasPrice, 16);
    return gasPriceNum >= 0;
  }, 'El precio de gas debe ser no negativo');

// esquema valor
export const valueSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]+$/, 'Formato de valor inválido')
  .refine(value => {
    const valueNum = BigInt(value);
    return valueNum >= 0n;
  }, 'El valor debe ser no negativo');

// esquema objeto transacción (flexible para manejar escenarios de test) - ajgc: esto está de locos
export const transactionObjectSchema = z.object({
  from: ethereumAddressSchema,
  to: ethereumAddressSchema.optional(),
  data: hexDataSchema.optional(),
  gas: z.union([gasSchema, z.number().positive()]).optional(),
  gasPrice: z.union([gasPriceSchema, z.number().nonnegative()]).optional(),
  maxFeePerGas: z.union([gasPriceSchema, z.number().nonnegative()]).optional(), // EIP-1559
  maxPriorityFeePerGas: z.union([gasPriceSchema, z.number().nonnegative()]).optional(), // EIP-1559
  value: z.union([valueSchema, z.number().nonnegative()]).optional(),
  nonce: z.union([nonNegativeIntegerSchema, z.string().regex(/^0x[a-fA-F0-9]+$/)]).optional(),
  chainId: z.union([positiveIntegerSchema, z.string().regex(/^0x[a-fA-F0-9]+$/)]).optional(),
  accessList: z.array(z.object({
    address: ethereumAddressSchema,
    storageKeys: z.array(ethereumHashSchema)
  })).optional(), // EIP-2930
  type: z.union([z.number().nonnegative(), z.string().regex(/^0x[a-fA-F0-9]+$/)]).optional()
});

// esquema transacción raw
export const rawTransactionSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]+$/, 'Formato de transacción raw inválido')
  .min(3, 'Transacción raw demasiado corta')
  .max(131072, 'Transacción raw demasiado larga'); // límite 64KB

// esquema recibo de transacción - ajgc: niquelao para validar todos los campos
export const transactionReceiptSchema = z.object({
  blockHash: ethereumHashSchema,
  blockNumber: z.string().regex(/^0x[a-fA-F0-9]+$/),
  contractAddress: ethereumAddressSchema.nullable(),
  cumulativeGasUsed: gasSchema,
  effectiveGasPrice: gasPriceSchema,
  from: ethereumAddressSchema,
  gasUsed: gasSchema,
  logs: z.array(z.object({
    address: ethereumAddressSchema,
    topics: z.array(ethereumHashSchema),
    data: hexDataSchema
  })),
  logsBloom: z.string().regex(/^0x[a-fA-F0-9]{512}$/),
  status: z.enum(['0x0', '0x1']),
  to: ethereumAddressSchema.nullable(),
  transactionHash: ethereumHashSchema,
  transactionIndex: z.string().regex(/^0x[a-fA-F0-9]+$/),
  type: z.string().regex(/^0x[a-fA-F0-9]+$/)
});

// esquema bloque - echarle un ojillo a que todos los campos estén bien
export const blockSchema = z.object({
  number: z.string().regex(/^0x[a-fA-F0-9]+$/),
  hash: ethereumHashSchema,
  parentHash: ethereumHashSchema,
  nonce: z.string().regex(/^0x[a-fA-F0-9]{16}$/),
  sha3Uncles: ethereumHashSchema,
  logsBloom: z.string().regex(/^0x[a-fA-F0-9]{512}$/),
  transactionsRoot: ethereumHashSchema,
  stateRoot: ethereumHashSchema,
  receiptsRoot: ethereumHashSchema,
  miner: ethereumAddressSchema,
  difficulty: z.string().regex(/^0x[a-fA-F0-9]+$/),
  totalDifficulty: z.string().regex(/^0x[a-fA-F0-9]+$/),
  extraData: hexDataSchema,
  size: z.string().regex(/^0x[a-fA-F0-9]+$/),
  gasLimit: gasSchema,
  gasUsed: gasSchema,
  timestamp: z.string().regex(/^0x[a-fA-F0-9]+$/),
  transactions: z.array(z.union([
    ethereumHashSchema, // hash cuando no son transacciones completas
    transactionObjectSchema // objetos de transacción completos
  ])),
  uncles: z.array(ethereumHashSchema)
});
