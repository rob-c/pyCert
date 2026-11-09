"""Minimal BER/DER reader used for legacy PKCS#12 keystores.

Java's PKCS#12 writer emits BER with indefinite-length constructed objects,
whereas pyCert's own writer emits DER.  This module only implements the small
subset needed to inspect SafeBags; it is deliberately strict about boundaries
and nesting depth.
"""

MAX_DEPTH = 64
MAX_NODES = 100000


class BERError(ValueError):
    pass


class TLV:
    """One parsed BER element, retaining its original encoding."""

    __slots__ = ("tag_class", "constructed", "tag", "content", "children", "encoded")

    def __init__(self, tag_class, constructed, tag, content, children, encoded):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag = tag
        self.content = content
        self.children = children
        self.encoded = encoded

    def __repr__(self):
        return "TLV(tag=%d, constructed=%r, length=%d)" % (
            self.tag,
            self.constructed,
            len(self.encoded),
        )

    def require_constructed(self):
        if not self.constructed or not self.children:
            raise BERError("expected a constructed BER element")


def parse(data: bytes) -> TLV:
    if not isinstance(data, (bytes, bytearray)):
        raise BERError("BER input must be bytes")
    node, offset = _parse_one(bytes(data), 0, len(data), 0, [0])
    if offset != len(data):
        raise BERError("trailing bytes after BER element")
    return node


def decode_oid(content: bytes) -> str:
    if not content:
        raise BERError("empty object identifier")
    first = content[0]
    values = [str(first // 40), str(first % 40)]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(str(value))
            value = 0
    if value:
        raise BERError("truncated object identifier")
    return ".".join(values)


def _parse_one(data, offset, limit, depth, nodes):
    if depth > MAX_DEPTH:
        raise BERError("BER nesting is too deep")
    nodes[0] += 1
    if nodes[0] > MAX_NODES:
        raise BERError("BER contains too many elements")
    start = offset
    if offset >= limit:
        raise BERError("truncated BER element")
    first = data[offset]
    offset += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if offset >= limit:
                raise BERError("truncated high-tag-number element")
            byte = data[offset]
            offset += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break

    if offset >= limit:
        raise BERError("truncated BER length")
    length_byte = data[offset]
    offset += 1
    if length_byte == 0x80:
        if not constructed:
            raise BERError("indefinite length on a primitive element")
        children = []
        while True:
            if offset + 2 > limit:
                raise BERError("missing BER end-of-contents")
            if data[offset] == 0 and data[offset + 1] == 0:
                offset += 2
                return TLV(tag_class, True, tag, b"", children, data[start:offset]), offset
            child, offset = _parse_one(data, offset, limit, depth + 1, nodes)
            children.append(child)
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 8 or offset + count > limit:
            raise BERError("invalid BER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = length_byte
    end = offset + length
    if end > limit:
        raise BERError("truncated BER content")
    if constructed:
        children = []
        child_offset = offset
        while child_offset < end:
            child, child_offset = _parse_one(data, child_offset, end, depth + 1, nodes)
            children.append(child)
        return TLV(tag_class, True, tag, b"", children, data[start:end]), end
    return TLV(tag_class, False, tag, data[offset:end], [], data[start:end]), end


def octets(node: TLV) -> bytes:
    """Concatenate primitive OCTET STRING content, including BER fragments."""
    if not node.constructed:
        return node.content
    result = b""
    for child in node.children:
        if child.tag == 0x04 or child.constructed:
            result += octets(child)
    return result


def first_child(node: TLV, tag: "int | None" = None) -> TLV:
    node.require_constructed()
    for child in node.children:
        if tag is None or child.tag == tag:
            return child
    raise BERError("expected BER child tag %r" % (tag,))
