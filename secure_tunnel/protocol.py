import msgpack

MSG_DUMMY = 0
MSG_DATA = 1
MSG_CONTROL = 2
MSG_COVER = 3   # cover-traffic frame — random payload, discarded by receiver

def pack_plain(msg_type: int, session_id: int, seq_no: int, payload: bytes) -> bytes:
    obj = {"t": msg_type, "sid": session_id, "seq": seq_no, "p": payload}
    return msgpack.packb(obj, use_bin_type=True)

def unpack_plain(data: bytes):
    obj = msgpack.unpackb(data, raw=False)
    return obj["t"], obj["sid"], obj["seq"], obj["p"]
