local prefix = ARGV[1]
local room_id = ARGV[2]
local code_len = tonumber(ARGV[3])
local local_id = tonumber(ARGV[4])
local use_expiry_index = tonumber(ARGV[5]) == 1

local starts_key = prefix .. ':alloc:' .. code_len .. ':starts'
local ends_key = prefix .. ':alloc:' .. code_len .. ':ends'

local function interval_contains(id)
  local left = redis.call('ZREVRANGEBYSCORE', starts_key, id, '-inf', 'LIMIT', 0, 1)
  if #left == 0 then
    return false
  end

  local left_start = left[1]
  local left_end = tonumber(redis.call('HGET', ends_key, left_start))
  return tonumber(left_start) <= id and id <= left_end
end

local clip_member = tostring(code_len) .. ':' .. tostring(local_id)
local clip_key = prefix .. ':clip:' .. clip_member

if interval_contains(local_id) then
  redis.call('DEL', clip_key)
  if use_expiry_index then
    redis.call('ZREM', prefix .. ':clip:expiring', clip_member)
  end
  return cjson.encode({ status = 'ok', result = 'already_free' })
end

redis.call('DEL', clip_key)
if use_expiry_index then
  redis.call('ZREM', prefix .. ':clip:expiring', clip_member)
end

local left = redis.call('ZREVRANGEBYSCORE', starts_key, local_id, '-inf', 'LIMIT', 0, 1)
local left_start = nil
local left_end = nil
if #left > 0 then
  left_start = tonumber(left[1])
  left_end = tonumber(redis.call('HGET', ends_key, left[1]))
end

local right_start = local_id + 1
local right = redis.call('ZRANGEBYSCORE', starts_key, right_start, right_start, 'LIMIT', 0, 1)
local right_end = nil
if #right > 0 then
  right_start = tonumber(right[1])
  right_end = tonumber(redis.call('HGET', ends_key, right[1]))
end

local left_adjacent = left_start ~= nil and left_end + 1 == local_id
local right_adjacent = right_end ~= nil

if left_adjacent and right_adjacent then
  redis.call('HSET', ends_key, tostring(left_start), tostring(right_end))
  redis.call('ZREM', starts_key, tostring(right_start))
  redis.call('HDEL', ends_key, tostring(right_start))
elseif left_adjacent then
  redis.call('HSET', ends_key, tostring(left_start), tostring(local_id))
elseif right_adjacent then
  redis.call('ZREM', starts_key, tostring(right_start))
  redis.call('HDEL', ends_key, tostring(right_start))
  redis.call('ZADD', starts_key, local_id, tostring(local_id))
  redis.call('HSET', ends_key, tostring(local_id), tostring(right_end))
else
  redis.call('ZADD', starts_key, local_id, tostring(local_id))
  redis.call('HSET', ends_key, tostring(local_id), tostring(local_id))
end

return cjson.encode({ status = 'ok', result = 'freed' })
