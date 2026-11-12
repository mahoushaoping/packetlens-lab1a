"""按双向端点聚合，以序列号排序、去重，缺口显式标注。"""
def reassemble(packets, key):
    result = []
    for source in key:
        selected = [p for p in packets if p.flow_key == key and (p.src, p.sport) == source]
        payloads = [p for p in selected if p.payload]
        target = key[1] if source == key[0] else key[0]
        title = f"{source[0]}:{source[1]} → {target[0]}:{target[1]}"
        if not payloads:
            result.append((title, b"", 0, 0))
            continue
        first_syn = next((p for p in selected if p.flags & 2), None)
        anchor = ((first_syn.seq + 1) if first_syn else (payloads[0].seq + bool(payloads[0].flags & 2))) & 0xFFFFFFFF
        segments = []
        for p in payloads:
            seq = (p.seq + bool(p.flags & 2)) & 0xFFFFFFFF
            offset = ((seq - anchor + 2**31) % 2**32) - 2**31
            segments.append((offset, p.number, p.payload))
        segments.sort(key=lambda s: (s[0], s[1]))
        cursor = 0 if first_syn else segments[0][0]
        chunks, duplicates, gaps = [], 0, 0
        for offset, _, data in segments:
            if offset > cursor:
                missing = offset - cursor
                chunks.append(f"\n[缺失 {missing} 字节]\n".encode())
                gaps += missing
                cursor = offset
            overlap = max(0, cursor - offset)
            duplicates += min(overlap, len(data))
            if overlap < len(data):
                chunks.append(data[overlap:])
                cursor += len(data) - overlap
        result.append((title, b"".join(chunks), duplicates, gaps))
    return result
