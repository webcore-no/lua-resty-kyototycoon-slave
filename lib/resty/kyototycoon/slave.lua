local _M = {_VERSION = 0.1}

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

local worker_exiting = ngx.worker_exiting

local BMREPLICATION = char(0xb1)
local BMNOP = char(0xb0)

local function b2i(bytes, num_bytes, offset)
	offset = offset or 0
	local number = 0

	for b = 1, num_bytes do
		number = number + byte(bytes, offset + num_bytes - b + 1)
			* 2 ^ ((b - 1) * 8)
	end

	return number, offset + num_bytes
end

local function i2b(number, num_bytes)
	local result = {}

	for k = num_bytes, 1, -1 do
		local b, mul = k % num_bytes + 1, 2 ^ (8 * (k - 1))
		result[b] = floor(number / mul)
		number = number - result[b] * mul
	end

	return char(unpack(result))
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

local OP = {
	[0xa1] = function(data, size, cmd)
		if size < 7 then
			return nil, "invalid SET message size"
		end

		local ksize, kpos = readvarnum(data, 6)
		local vsize, vpos = readvarnum(data, 6 + kpos)

		if 5 + kpos + vpos + ksize + vsize ~= size then
			return nil, "invalid SET message"
		end

		cmd.op = "set"
		cmd.key = sub(data, 5 + kpos + vpos + 1, 5 + kpos + vpos + ksize)
		cmd.ttl = b2i(data, 5, 5 + kpos + vpos + ksize)
		cmd.val = sub(data, 5 + kpos + vpos + 1 + ksize + 1 + 4)

		if cmd.ttl == 2 ^ (5 * 8) - 1 then
			cmd.ttl = nil
		end

		return cmd
	end,
	[0xa2] = function(data, size, cmd)
		if size < 6 then
			return nil, "invalid REMOVE message size"
		end

		local ksize, kpos = readvarnum(data, 6)
		if 5 + kpos + ksize ~= size then
			return nil, "invalid REMOVE message"
		end

		cmd.op = "remove"
		cmd.key = sub(data, 5 + kpos + 1)

		return cmd
	end,
	[0xa5] = function(data, size, cmd)
		if size ~= 5 then
			return nil, "invalid CLEAR message size"
		end

		cmd.op = "clear"

		return cmd
	end,
}

function _M.new(id, ...)
	local sock, err = tcp()
	if not sock then
		return nil, err
	end

	return setmetatable({_sock = sock, _id = id, _connect = {...}},
		{__index = _M})
end

function _M:replicate(callback, ts)
	local sock = rawget(self, "_sock")

	if not sock then
		return nil, "socket not initialized"
	end

	if not callback then
		return nil, "callback required"
	end

	self._ts = ts or 0

	local replication_request = {
		BMREPLICATION,
		i2b(0, 4),
		nil,
		i2b(rawget(self, "_id"), 2),
	}

	local function connect()
		local ok, err = sock:connect(table.unpack(
			rawget(self, "_connect")))
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

		while not worker_exiting() do
			local magic, err = sock:receive(1)
			if not magic then
				return nil, err
			end

			if magic == BMNOP then
				local ok, err = sock:receive(8)
				if not ok then
					return nil, err
				end

				return get_replication_log(true)
			end

			if magic ~= BMREPLICATION then
				return nil, "invalid magic from server"
			end

			local data, err = sock:receive(12)
			if not data then
				return nil, err
			end

			local ts, size = b2i(data, 8), b2i(data, 4, 8)

			local data, err = sock:receive(size)
			if not data then
				return nil, err
			end

			if size > 4 then
				local sidp, dbidp, op = b2i(data, 2),
					b2i(data, 2, 2), byte(data, 5)

				local parser = OP[op]

				if not parser then
					return nil,
					format("unknown operation: 0x%.2x", op)
				end

				self._ts = ts

				local cmd = {}
				callback(parser(data, size, cmd))
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
		ngx.sleep("0.01")
	end
end

return _M

