local prefix = ARGV[1]
local now_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3]) or 1

local expiring_key = prefix .. ':clip:expiring'

local function interval_contains(starts_key, ends_key, id)
  local left = redis.call('ZREVRANGEBYSCORE', starts_key, id, '-inf', 'LIMIT', 0, 1)
  if #left == 0 then
    return false
  end

  local left_start = left[1]
  local left_end = tonumber(redis.call('HGET', ends_key, left_start))
  return tonumber(left_start) <= id and id <= left_end
end

local function merge_free_interval(starts_key, ends_key, local_id)
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
end

local reclaimed = 0
local cleaned = 0
local scanned = 0
local members = redis.call('ZRANGEBYSCORE', expiring_key, '-inf', now_ms, 'LIMIT', 0, limit)

for _, clip_member in ipairs(members) do
  scanned = scanned + 1

  local separator = string.find(clip_member, ':', 1, true)
  if separator == nil then
    redis.call('ZREM', expiring_key, clip_member)
    cleaned = cleaned + 1
  else
    local code_len = tonumber(string.sub(clip_member, 1, separator - 1))
    local local_id = tonumber(string.sub(clip_member, separator + 1))

    if code_len == nil or local_id == nil then
      redis.call('ZREM', expiring_key, clip_member)
      cleaned = cleaned + 1
    else
      local clip_key = prefix .. ':clip:' .. clip_member
      if redis.call('EXISTS', clip_key) == 0 then
        local starts_key = prefix .. ':alloc:' .. code_len .. ':starts'
        local ends_key = prefix .. ':alloc:' .. code_len .. ':ends'

        if interval_contains(starts_key, ends_key, local_id) then
          redis.call('ZREM', expiring_key, clip_member)
          cleaned = cleaned + 1
        else
          merge_free_interval(starts_key, ends_key, local_id)
          redis.call('ZREM', expiring_key, clip_member)
          reclaimed = reclaimed + 1
        end
      end
    end
  end
end

return cjson.encode({
  status = 'ok',
  reclaimed = reclaimed,
  cleaned = cleaned,
  scanned = scanned,
})
