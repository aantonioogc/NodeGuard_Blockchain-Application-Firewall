-- src/rate-limiting/lua-scripts/token_bucket.lua
-- Script Lua Token Bucket - NodeGuard TFG 2025
-- ajgc: token bucket mejorado con prioridades y métricas (atomico)

-- KEYS[1] = clave del bucket
-- ARGV[1] = capacity (max tokens)
-- ARGV[2] = refill_per_ms (tokens por milisegundo)  
-- ARGV[3] = now_ms (timestamp actual en milisegundos)
-- ARGV[4] = requested (tokens a consumir)
-- ARGV[5] = allow_partial (1 si se permite consumo parcial, 0 si no)
-- ARGV[6] = priority ('low', 'normal', 'high')
--
-- Devuelve: [granted, tokens_granted, remaining_tokens, next_refill_time, bucket_age]

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])
local allow_partial = tonumber(ARGV[5]) == 1
local priority = ARGV[6] or 'normal'

-- Validación básica
if capacity <= 0 or refill_per_ms <= 0 or requested <= 0 then
    return redis.error_reply("Args inválidos: capacity, refill_per_ms y requested deben ser positivos")
end

if requested > capacity then
    return redis.error_reply("Tokens solicitados exceden capacidad del bucket")
end

-- Obtener estado actual del bucket
local bucket_data = redis.call('HMGET', key, 'tokens', 'last', 'created')
local current_tokens = tonumber(bucket_data[1])
local last_refill = tonumber(bucket_data[2])
local bucket_created = tonumber(bucket_data[3])

-- Inicializar bucket nuevo si es necesario
local is_new_bucket = false
if current_tokens == nil then
    current_tokens = capacity
    last_refill = now
    bucket_created = now
    is_new_bucket = true
end

-- ajgc: calcular tiempo transcurrido desde último refill
local time_delta = math.max(0, now - last_refill)
local bucket_age = now - bucket_created

-- Calcular tokens a añadir según tasa de refill
local tokens_to_add = time_delta * refill_per_ms
local updated_tokens = math.min(capacity, current_tokens + tokens_to_add)

-- Sistema de prioridades básico
local priority_multiplier = 1.0
if priority == 'high' then
    priority_multiplier = 1.1
elseif priority == 'low' then
    priority_multiplier = 0.9
end

local effective_requested = math.ceil(requested * priority_multiplier)
local actual_requested = math.min(effective_requested, requested)

-- Determinar si la request puede ser satisfecha
local granted = 0
local tokens_granted = 0
local final_tokens = updated_tokens

if updated_tokens >= actual_requested then
    -- Request completa satisfecha
    granted = 1
    tokens_granted = requested  -- Siempre otorgar la cantidad original solicitada
    final_tokens = updated_tokens - actual_requested
elseif allow_partial and updated_tokens > 0 then
    -- Request parcial satisfecha
    granted = 1
    tokens_granted = math.min(requested, math.floor(updated_tokens))
    final_tokens = updated_tokens - tokens_granted
else
    -- Request denegada
    granted = 0
    tokens_granted = 0
    final_tokens = updated_tokens
end

-- ajgc: calcular siguiente tiempo de refill para estimación de espera
local next_refill_time = now
if granted == 0 or (granted == 1 and tokens_granted < requested) then
    local tokens_needed = requested - updated_tokens
    if tokens_needed > 0 then
        next_refill_time = now + math.ceil(tokens_needed / refill_per_ms)
    else
        next_refill_time = now + math.ceil(1 / refill_per_ms)  -- Siguiente token
    end
end

-- Actualizar estado del bucket solo si request fue procesada
if granted == 1 or is_new_bucket then
    redis.call('HMSET', key, 
        'tokens', final_tokens,
        'last', now,
        'created', bucket_created
    )
    
    -- Set TTL del bucket (2x tiempo necesario para llenar completamente + buffer)
    local ttl_seconds = math.max(60, math.ceil((capacity / (refill_per_ms * 1000)) * 2) + 30)
    redis.call('EXPIRE', key, ttl_seconds)
end

-- ajgc: tracking de rendimiento opcional (lo quito para simplificar)
-- Si necesitara métricas más adelante lo activo desde config

-- Devolver resultado completo
return {
    granted,                -- 1 si otorgado, 0 si denegado
    tokens_granted,         -- Tokens realmente otorgados
    final_tokens,           -- Tokens restantes en bucket
    next_refill_time,       -- Cuándo estará disponible siguiente token
    bucket_age,             -- Edad del bucket en ms (para monitoring)
    math.floor(updated_tokens * 1000) / 1000  -- Tokens precisos restantes antes de request
}
