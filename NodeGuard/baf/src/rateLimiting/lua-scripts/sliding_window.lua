-- src/rate-limiting/lua-scripts/sliding_window.lua
-- Script Lua Sliding Window - NodeGuard TFG BAF
-- ajgc: rate limiter de ventana deslizante (atomico en Redis)


-- KEYS[1] = clave del rate limit
-- ARGV[1] = tamaño de ventana en milisegundos
-- ARGV[2] = max requests en la ventana
-- ARGV[3] = timestamp actual
-- ARGV[4] = allowance para ráfagas (requests extra permitidas)
-- ARGV[5] = identificador único para esta request
--
-- Devuelve: [permitida, count_actual, restantes, tiempo_reset]

local key = KEYS[1]
local window_ms = tonumber(ARGV[1])
local max_requests = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local burst_allowance = tonumber(ARGV[4]) or 0
local identifier = ARGV[5]

-- ajgc: calcular límites de la ventana
local window_start = now - window_ms

-- Borrar entries expiradas (fuera de la ventana actual)
redis.call('ZREMRANGEBYSCORE', key, 0, window_start)

-- Contar requests actuales en la ventana
local current_count = redis.call('ZCARD', key)

-- Calcular límite efectivo (incluyendo burst allowance)
local effective_limit = max_requests + burst_allowance

-- Determinar si la request debe ser permitida
local allowed = 0
local remaining = effective_limit - current_count

if current_count < effective_limit then
    allowed = 1
    -- Añadir request actual a la ventana
    redis.call('ZADD', key, now, identifier)
    current_count = current_count + 1
    remaining = remaining - 1
end

-- Set TTL para limpieza (tamaño ventana + buffer)
local ttl_seconds = math.ceil(window_ms / 1000) + 10
redis.call('EXPIRE', key, ttl_seconds)

-- ajgc: calcular tiempo de reset (cuando expirará la request más vieja)
local reset_time = now + window_ms
local oldest_requests = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if #oldest_requests >= 2 then
    local oldest_timestamp = tonumber(oldest_requests[2])
    reset_time = oldest_timestamp + window_ms
end

-- Devolver resultado
return {
    allowed,                -- 1 si permitida, 0 si bloqueada
    current_count,          -- Count actual en la ventana
    remaining,              -- Requests restantes permitidas
    reset_time              -- Cuando se resetea la ventana
}
