"""小型递归下降显示过滤器。绝不 eval 用户输入。"""
import ipaddress
import re

PROTOCOLS = {"ethernet", "arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "http", "dns", "tls", "vlan"}


def compile_filter(text):
    if len(text) > 2048:
        raise ValueError("过滤表达式过长（上限 2048 字符）")
    tokens = re.findall(r"\(|\)|[^\s()]+", text.lower())
    if len(tokens) > 128:
        raise ValueError("过滤表达式过复杂（上限 128 token）")
    if not tokens:
        return lambda p: True
    pos = 0

    def take():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("过滤表达式不完整")
        t = tokens[pos]
        pos += 1
        return t

    def atom():
        token = take()
        if token == "not":
            child = atom()
            return lambda p: not child(p)
        if token == "(":
            child = expr()
            if take() != ")":
                raise ValueError("缺少右括号")
            return child
        if token in PROTOCOLS:
            return lambda p: token in p.protocols
        if token in ("host", "src", "dst"):
            value = str(ipaddress.ip_address(take()))
            if token == "src":
                return lambda p: p.src == value
            if token == "dst":
                return lambda p: p.dst == value
            return lambda p: value in (p.src, p.dst)
        if token == "port":
            value = int(take())
            if not 0 <= value <= 65535:
                raise ValueError("端口必须在 0..65535")
            return lambda p: bool(p.protocols & {"tcp", "udp"}) and value in (p.sport, p.dport)
        if token == "contains":
            value = take().encode()
            return lambda p: value in p.payload.lower()
        raise ValueError(f"不支持的过滤项：{token}")

    def term():
        nonlocal pos
        left = atom()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            right, previous = atom(), left
            left = lambda p, a=previous, b=right: a(p) and b(p)
        return left

    def expr():
        nonlocal pos
        left = term()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            right, previous = term(), left
            left = lambda p, a=previous, b=right: a(p) or b(p)
        return left

    result = expr()
    if pos != len(tokens):
        raise ValueError(f"多余内容：{tokens[pos]}；条件之间请写 and/or")
    return result
