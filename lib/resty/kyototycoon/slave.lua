local _M, OP = { _VERSION = 0.2 }, {}

local tcp = ngx.socket.tcp
local rawget = rawget
local format = string.format
local concat = table.concat
local byte = string.byte
local char = string.char
local floor = math.floor
local sub = string.sub
local band = bit.band
local lshift = bit.lshift

local worker_exiting = ngx.worker.exiting or function() return false end

local BMREPLICATION = char(0xb1)
local BMNOP = char(0xb0)

local SET, REMOVE, CLEAR = 0xa1, 0xa2, 0xa5

local callback_t = {
    [SET] = "set",
    [CLEAR] = "clear",
    [REMOVE] = "remove"
}

local function b2i(bytes, num_bytes, offset)
    offset = offset or 0
    local number = (num_bytes <= 4) and 0 or 0ULL

    for b=1, num_bytes do
        number = number + byte(bytes, offset + num_bytes - b + 1)*2^((b-1)*8)
    end

    return number, offset + num_bytes
end

local i2b do
    local result, b, m = {}
    i2b = function(number, num_bytes)
        for k = num_bytes - 1, 0, -1 do
            b, m = num_bytes - k, 2^(8 * k)
            result[b] = floor(tonumber(number)/m)
            number = number - result[b]*m
        end

        return char(unpack(result, 1, num_bytes))
    end
end

local function readvarnum(data, start)
    local num, pos, chr = 0, 0
    start = start or 1

    repeat
        chr = byte(data, start + pos)
        num = lshift(num, 7) + band(chr, 0x7f)
        pos = pos + 1
    until (chr < 0x80)

    return num, pos
end

OP[SET] = function(callback, data, size)
    if size < 7 then
        return nil, "invalid SET message size"
    end

    local ksize, kpos = readvarnum(data, 6)
    local vsize, vpos = readvarnum(data, 6 + kpos)

    if 5 + kpos + vpos + ksize + vsize ~= size then
        return nil, "invalid SET message"
    end

    local key = sub(data, 5 + kpos + vpos + 1, 5 + kpos + vpos + ksize)
    local ttl = b2i(data, 5, 5 + kpos + vpos + ksize)
    local val = sub(data, 5 + kpos + vpos + 1 + ksize + 1 + 4)

    return callback(key, val, ttl == 2^(5*8) - 1 and nil or ttl)
end

OP[REMOVE] = function(callback, data, size)
    if size < 6 then
        return nil, "invalid REMOVE message size"
    end

    local ksiz, kpos = readvarnum(data, 6)
    if 5 + kpos + ksiz ~= size then
        return nil, "invalid REMOVE message"
    end

    return callback(sub(data, 5 + kpos + 1))
end

OP[CLEAR] = function(callback, _, size)
    if size ~= 5 then
        return nil, "invalid CLEAR message size"
    end

    return callback()
end

function _M.new(id, ...)
    return setmetatable(
        { _id = id, _connect = {...}}, { __index = _M }
    )
end

function _M:replicate(callback, ts)
    local sock = tcp()

    if not sock then
        return nil, "socket not initialized"
    end

    if not callback or type(callback) ~= "table" then
        return nil, "callback table required"
    end


    self._ts = ts or 0ULL - 2

    local replication_request = {
        BMREPLICATION,
        i2b(0, 4),
        nil,
        i2b(rawget(self, "_id"), 2)
    }

    local function connect()
        local ok, err = sock:connect(unpack(rawget(self, "_connect")))
        if not ok then
            return nil, err
        end

        replication_request[3] = i2b(rawget(self, "_ts"), 8)

        local ok, err = sock:send(concat(replication_request))
        if not ok then
            return nil, err
        end

        local magic, err = sock:receive(1)
        if not magic then
            return nil, err
        end

        if magic ~= BMREPLICATION then
            return nil, "invalid response"
        end

        return true
    end

    local function get_replication_log(continue)
        if continue then
            ngx.sleep("0.02")
            local ok, err = sock:send(BMREPLICATION)
            if not ok then
                return nil, err
            end
        end

        local magic, data, size, op, id, cb, ok, err
        while not worker_exiting() do
            magic, err = sock:receive(1)

            if not magic then
                return nil, err
            end

            if magic == BMNOP then
                ok, err = sock:receive(8)
                if not ok then
                    return nil, err
                end

                return get_replication_log(true)
            end

            if magic ~= BMREPLICATION then
                return nil, "invalid magic from server"
            end

            data, err = sock:receive(12)
            if not data then
                return nil, err
            end

            ts, size = b2i(data, 8), b2i(data, 4, 8)

            data, err = sock:receive(size)
            if not data then
                return nil, err
            end

            if size > 4 then
                id = byte(data, 5)
                op = OP[id]

                if op then
                    cb = callback[callback_t[id]]
                    if cb then
                        ok, err = op(cb, data, size)
                        if not ok then
                            return nil, err or "callback failed"
                        end
                    end

                    self._ts = ts
                else
                    return nil, format("unsupported op: 0x%.2x", byte(data, 5))
                end
            elseif size < 4 then
                return nil, "invalid update log"
            end
        end

        -- worker is exiting
        return ngx.exit(ngx.OK)
    end

    while true do
        local ok, err = connect()

        if ok then
            ok, err = get_replication_log()
        end

        if not ok then
            ngx.log(ngx.ERR, err)
        end

        sock:close()

        ngx.sleep("0.5")
    end
end

return _M
