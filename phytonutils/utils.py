def hex_octets(data):
    """Renders data as groups of 8 octets in hex, space-separated (port of utils.HexOctets)."""
    result = ""
    for i in range(0, len(data), 8):
        if result:
            result += " "
        result += data[i : i + 8].hex()
    return result
