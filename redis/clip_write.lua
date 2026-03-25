local prefix = ARGV[1]
local room_id = ARGV[2]
local code_len = tonumber(ARGV[3])
local local_id = tonumber(ARGV[4])
local now_ms = tonumber(ARGV[5])
local ttl_ms = tonumber(ARGV[6])
local envelope_json = ARGV[7]
local use_expiry_index = tonumber(ARGV[8]) == 1

local clip_member = tostring(code_len) .. ':' .. tostring(local_id)
local clip_key = prefix .. ':clip:' .. clip_member
local payload = redis.call('GET', clip_key)

if not payload then
  return cjson.encode({ status = 'err', error = 'not_found' })
end

local record = cjson.decode(payload)
local next_envelope = cjson.decode(envelope_json)
local expected_version = tonumber(record.content_version) + 1

if tonumber(next_envelope.version) ~= expected_version then
  return cjson.encode({
    status = 'err',
    error = 'version_conflict',
    current_content_version = tonumber(record.content_version),
  })
end

local expires_at_ms = now_ms + ttl_ms
record.envelope = next_envelope
record.content_version = tonumber(next_envelope.version)
record.updated_at_ms = now_ms
record.expires_at_ms = expires_at_ms

redis.call('SET', clip_key, cjson.encode(record), 'PX', ttl_ms)

if use_expiry_index then
  redis.call('ZADD', prefix .. ':clip:expiring', expires_at_ms, clip_member)
end

return cjson.encode({
  status = 'ok',
  room_id = room_id,
  content_version = tonumber(record.content_version),
  expires_at_ms = expires_at_ms,
})
