local prefix = ARGV[1]
local sentinel_key = prefix .. ':alloc:init:v1'

if redis.call('EXISTS', sentinel_key) == 1 then
  return cjson.encode({ status = 'ok', state = 'already_initialized' })
end

local capacities = {
  [3] = 175615,
  [4] = 9834495,
  [5] = 550731775,
  [6] = 30840979455,
}

for _, code_len in ipairs({ 3, 4, 5, 6 }) do
  local starts_key = prefix .. ':alloc:' .. code_len .. ':starts'
  local ends_key = prefix .. ':alloc:' .. code_len .. ':ends'
  redis.call('DEL', starts_key)
  redis.call('DEL', ends_key)
  redis.call('ZADD', starts_key, 0, '0')
  redis.call('HSET', ends_key, '0', tostring(capacities[code_len]))
end

redis.call('SET', sentinel_key, '1')

return cjson.encode({ status = 'ok', state = 'initialized' })
