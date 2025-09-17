// src/validation/schemas/json-rpc.ts
// ajgc: esquemas de validación JSON-RPC para NodeGuard

import { z } from 'zod';

// esquema ID JSON-RPC
export const jsonRpcIdSchema = z.union([
  z.string().max(100, 'ID demasiado largo'),
  z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  z.null()
]).optional();

// esquema método JSON-RPC
export const jsonRpcMethodSchema = z
  .string()
  .min(1, 'El nombre del método no puede estar vacío')
  .max(100, 'Nombre del método demasiado largo')
  .regex(/^[a-zA-Z][a-zA-Z0-9_]*$/, 'Formato de nombre de método inválido')
  .refine(method => !method.startsWith('rpc.'), 'Los métodos que empiezan con "rpc." están reservados');

// esquema parámetros JSON-RPC  
export const jsonRpcParamsSchema = z.union([
  z.array(z.unknown()).max(50, 'Demasiados parámetros en array'),
  z.record(z.string(), z.unknown()).refine(
    obj => Object.keys(obj).length <= 50,
    'Demasiados parámetros en objeto'
  )
]).optional();

// esquema principal de petición JSON-RPC
export const jsonRpcRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  method: jsonRpcMethodSchema,
  params: jsonRpcParamsSchema,
  id: jsonRpcIdSchema
}).strict();

// esquema batch request - ajgc: echarle un ojillo a que no haya IDs duplicados
export const jsonRpcBatchSchema = z
  .array(jsonRpcRequestSchema)
  .min(1, 'El batch no puede estar vacío')
  .max(100, 'El tamaño del batch excede el máximo permitido (100)')
  .refine(
    batch => {
      const ids = batch.map(req => req.id).filter(id => id !== undefined);
      const uniqueIds = new Set(ids);
      return ids.length === uniqueIds.size;
    },
    'IDs duplicados encontrados en el batch'
  );

// esquemas de respuesta
export const jsonRpcSuccessResponseSchema = z.object({
  jsonrpc: z.literal('2.0'),
  result: z.unknown(),
  id: jsonRpcIdSchema
}).strict();

export const jsonRpcErrorResponseSchema = z.object({
  jsonrpc: z.literal('2.0'),
  error: z.object({
    code: z.number().int(),
    message: z.string().min(1),
    data: z.unknown().optional()
  }),
  id: jsonRpcIdSchema
}).strict();

export const jsonRpcResponseSchema = z.union([
  jsonRpcSuccessResponseSchema,
  jsonRpcErrorResponseSchema
]);

// validación de métodos específicos de Ethereum - esto está de locos la cantidad que hay
export const ethereumMethodSchema = z.enum([
  'eth_accounts',
  'eth_blockNumber',
  'eth_call',
  'eth_chainId',
  'eth_coinbase',
  'eth_estimateGas',
  'eth_gasPrice',
  'eth_getBalance',
  'eth_getBlockByHash',
  'eth_getBlockByNumber',
  'eth_getBlockTransactionCountByHash',
  'eth_getBlockTransactionCountByNumber',
  'eth_getCode',
  'eth_getFilterChanges',
  'eth_getFilterLogs',
  'eth_getLogs',
  'eth_getStorageAt',
  'eth_getTransactionByBlockHashAndIndex',
  'eth_getTransactionByBlockNumberAndIndex',
  'eth_getTransactionByHash',
  'eth_getTransactionCount',
  'eth_getTransactionReceipt',
  'eth_getUncleByBlockHashAndIndex',
  'eth_getUncleByBlockNumberAndIndex',
  'eth_getUncleCountByBlockHash',
  'eth_getUncleCountByBlockNumber',
  'eth_hashrate',
  'eth_mining',
  'eth_newBlockFilter',
  'eth_newFilter',
  'eth_newPendingTransactionFilter',
  'eth_protocolVersion',
  'eth_sendRawTransaction',
  'eth_sendTransaction',
  'eth_sign',
  'eth_signTransaction',
  'eth_syncing',
  'eth_uninstallFilter',
  'web3_clientVersion',
  'web3_sha3',
  'net_listening',
  'net_peerCount',
  'net_version'
]);
