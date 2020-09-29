--[[---------------------------------------------------------------------------
--
-- author: PK <wolfganp@github>
-- Copyright (c) 2020, PK
-- This code is in the Public Domain, or the BSD (3 clause) license
-- if Public Domain does not apply in your country.
--
-- Version: 1.0
--
]]-----------------------------------------------------------------------------

--[[
    This code is a plugin for Wireshark, to dissect Reaper's Reastream protocol messages
    over UDP, as spec'd in https://github.com/niusounds/dart_reastream/blob/master/reastream_spec.txt
	

	Dissector dev guide (with quick Lua crash course): 
	https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
	Dissector official template: https://gitlab.com/wireshark/wireshark/-/wikis/Lua/Examples#a-dissector-tutorial-script
	And Wireshark Lua API:
	https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
]]-----------------------------------------------------------------------------

-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings = {
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 58710, -- protocol UDP port
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()

----------------------------------------

local proto = "reastream"

local p = Proto(proto, "UDP Reaper Reastream")

p.fields.pkttype = ProtoField.string(proto .. ".pkttype", "Pkt Type", base.ASCII)
-- , {"m"="midi", "M"="audio"} )
p.fields.pktsize = ProtoField.uint32(proto .. ".pktsize", "Pkt Size", base.DEC)
p.fields.id = ProtoField.string(proto .. ".id", "Identifier", base.ASCII)
p.fields.numchn = ProtoField.uint8(proto .. ".numchn", "Num Channels")
p.fields.samplerate = ProtoField.uint32(proto .. ".samplerate", "Sample Rate", base.DEC)
p.fields.sampledata = ProtoField.uint16(proto .. ".sampledata", "Samples Size", base.DEC)
p.fields.sample = ProtoField.float(proto .. ".sample", "Samples Count")

local data_dis = Dissector.get("data")

function p.dissector(buffer, pinfo, tree)

	length = buffer:len()
    if length <= 0 then return end	-- should be 47 for complete header?
	
	-- to make plural in subtree header msg
	local s = "s"
	if length == 1 then s = "" end

	pinfo.cols.protocol = p.name

	if buffer(0,1):string() == "M" then
		local subtree = tree:add(p, buffer(), "Reastream Audio Protocol Data", "(" .. length .. " byte" .. s .. ")")
		local header = subtree:add(p, buffer(0,47), "Header")
		pinfo.cols.info = "Audio Data"
		
		header:add_le(p.fields.pktsize, buffer(4,4))
		header:add(p.fields.id, buffer(8,32))
		header:add_le(p.fields.numchn, buffer(40,1))
		header:add_le(p.fields.samplerate, buffer(41,4))
		header:add_le(p.fields.sampledata, buffer(45,2))	
		
		datalen = length - 47
		local msgdata = subtree:add(p, buffer(47,datalen), "Data", "("  .. datalen .. " bytes), just first 10 samples decoded")
		samplescnt = datalen / 4
		if samplescnt > 10 then samplescnt = 10 end		-- just display 1st 10 samples
		if samplescnt > 0 then
			for i=0,samplescnt,1 do
				stfield = 47 + i * 4
				msgdata:add(p.fields.sample, buffer(stfield,4))
			end
		end		

	elseif buffer(0,1):string() == "m" then
		local subtree = tree:add(p, buffer(), "Reastream Midi Protocol Data", "(" .. length .. " byte" .. s .. ")")
		pinfo.cols.info = "Midi Data"

	end

--[[
    if buf(0,4):uint() == 1 then
        local t = tree:add(p, buf())
        t:add(p.fields.action, buf(0,4))

        local len = buf:len()
        local nums = (len - 20) / 6
        local peers = t:add(p.fields.peers, buf(20,len-20))
        for i=0,nums-1,1 do
            local subtree = peers:add(p.fields.peer, buf(20+i*6,6))
            subtree:add(p.fields.peeraddr, buf(20+i*6,4))
            subtree:add(p.fields.peerport, buf(24+i*6,2))
        end
        return
    end


]]--

end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(default_settings.port, p)
