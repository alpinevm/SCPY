local prefix = ARGV[1]
local now_ms = tonumber(ARGV[2])
local ttl_ms = tonumber(ARGV[3])
local record_json = ARGV[4]
local use_expiry_index = tonumber(ARGV[5]) == 1

for _, code_len in ipairs({ 3, 4, 5, 6 }) do
  local starts_key = prefix .. ':alloc:' .. code_len .. ':starts'
  local ends_key = prefix .. ':alloc:' .. code_len .. ':ends'
  local smallest = redis.call('ZRANGE', starts_key, 0, 0)

  if #smallest > 0 then
    local start_member = smallest[1]
    local start_value = tonumber(start_member)
    local end_value = tonumber(redis.call('HGET', ends_key, start_member))

    redis.call('ZREM', starts_key, start_member)
    redis.call('HDEL', ends_key, start_member)

    if start_value < end_value then
      local next_start = tostring(start_value + 1)
      redis.call('ZADD', starts_key, start_value + 1, next_start)
      redis.call('HSET', ends_key, next_start, tostring(end_value))
    end

    local clip_member = tostring(code_len) .. ':' .. tostring(start_value)
    local clip_key = prefix .. ':clip:' .. clip_member
    local expires_at_ms = now_ms + ttl_ms
    local record = cjson.decode(record_json)

    record.room_id = clip_member
    record.code_len = code_len
    record.local_id = start_value
    record.created_at_ms = now_ms
    record.updated_at_ms = now_ms
    record.expires_at_ms = expires_at_ms
    record.content_version = record.envelope.version

    redis.call('SET', clip_key, cjson.encode(record), 'PX', ttl_ms)

    if use_expiry_index then
      redis.call('ZADD', prefix .. ':clip:expiring', expires_at_ms, clip_member)
    end

    return cjson.encode({
      status = 'ok',
      room_id = clip_member,
      code_len = code_len,
      local_id = start_value,
      expires_at_ms = expires_at_ms,
    })
  end
end

return cjson.encode({ status = 'err', error = 'allocator_exhausted' })
