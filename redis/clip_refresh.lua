local prefix = ARGV[1]
local room_id = ARGV[2]
local now_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])
local use_expiry_index = tonumber(ARGV[5]) == 1

local clip_key = prefix .. ':clip:' .. room_id
local payload = redis.call('GET', clip_key)

if not payload then
  return cjson.encode({ status = 'err', error = 'not_found' })
end

local record = cjson.decode(payload)
local expires_at_ms = now_ms + ttl_ms

record.updated_at_ms = now_ms
record.expires_at_ms = expires_at_ms

redis.call('SET', clip_key, cjson.encode(record), 'PX', ttl_ms)

if use_expiry_index then
  redis.call('ZADD', prefix .. ':clip:expiring', expires_at_ms, room_id)
end

return cjson.encode({
  status = 'ok',
  room_id = room_id,
  expires_at_ms = expires_at_ms,
})
