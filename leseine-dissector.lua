leseine_proto = Proto("leseine","Leseine protocol")

leseine_proto.fields.len = ProtoField.uint16("leseine.len","Len")
leseine_proto.fields.is_encrypted = ProtoField.bool("leseine.is_encrypted","IsEncrypted?")
leseine_proto.fields.packet_id = ProtoField.uint32("leseine.packet_id","PacketId")
leseine_proto.fields.data = ProtoField.bytes("leseine.data","Data", base.SPACE)

local function decrypt(bytes)
    local key = ByteArray.new("71 6D 66 61 6B 74 6E 70 67 6A 73")
    local key_len = key:len()
    local b

    for i = 0, bytes:len() - 1 do
        b = bytes:get_index(i)
        if b == 0 then
            bytes:set_index(i, b)
        else
            bytes:set_index(i, bit.bxor(b, key:get_index(i % key_len)))
        end
    end
    return bytes:tvb():range()
end

-- create a function to dissect it
function leseine_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "LESEINE"
    local subtree = tree:add(leseine_proto, buffer(), "Leseine Protocol Data")

    local len = buffer(0,2):le_uint()
    local data = buffer(2,len-2)

    local is_encrypted = data(0, 2):le_uint() == 1
    if is_encrypted then
        data = decrypt(data(2, len-4):bytes())
    end

    local packet_id = data(0, 4):le_uint()
    
    subtree:add_le(leseine_proto.fields.len, buffer(0,2), len)
    subtree:add_le(leseine_proto.fields.is_encrypted, buffer(2,2), is_encrypted)
    subtree:add_le(leseine_proto.fields.packet_id, data(0,4), packet_id)
    subtree:add(leseine_proto.fields.data, data)

    pinfo.cols.info = string.format("[%d] %s", packet_id, data:bytes():tohex(false, " "))
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add("10000-10099", leseine_proto)