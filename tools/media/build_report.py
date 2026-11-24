"""从真实验收证据生成中文实验报告（可编辑生成源）。"""
from pathlib import Path
from xml.sax.saxutils import escape
import json
import sys
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, Preformatted
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence"
pdfmetrics.registerFont(TTFont("CJK", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"))
INK, BLUE, GREEN = colors.HexColor("#172b46"), colors.HexColor("#245da8"), colors.HexColor("#147c6b")
styles = {
    "body": ParagraphStyle("body", fontName="CJK", fontSize=10.5, leading=17, textColor=INK, spaceAfter=9),
    "small": ParagraphStyle("small", fontName="CJK", fontSize=8.5, leading=13, textColor=INK, spaceAfter=6),
    "title": ParagraphStyle("title", fontName="CJK", fontSize=30, leading=40, textColor=INK, spaceAfter=16),
    "h1": ParagraphStyle("h1", fontName="CJK", fontSize=20, leading=28, textColor=INK, spaceAfter=16),
    "h2": ParagraphStyle("h2", fontName="CJK", fontSize=12.5, leading=20, textColor=BLUE, spaceBefore=8, spaceAfter=7),
    "caption": ParagraphStyle("caption", fontName="CJK", fontSize=8.5, leading=13, textColor=colors.HexColor("#62738b"), alignment=TA_CENTER, spaceAfter=12),
    "code": ParagraphStyle("code", fontName="CJK", fontSize=8.4, leading=12, backColor=colors.HexColor("#f0f4f9"), borderPadding=9, spaceBefore=5, spaceAfter=13),
}
story = []


def p(text, style="body"):
    story.append(Paragraph(text, styles[style]))


def h(text): p(text, "h2")


def page(number, title):
    if story: story.append(PageBreak())
    p(f"{number:02d}  /  {title}", "h1")


def code(text): story.append(Preformatted(text, styles["code"]))


def table(rows, widths):
    values = [[Paragraph(escape(str(value)), styles["small"]) for value in row] for row in rows]
    t = Table(values, colWidths=widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e7eef8")),
                           ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f7f9fc")]),
                           ("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),9),
                           ("RIGHTPADDING",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),8),
                           ("BOTTOMPADDING",(0,0),(-1,-1),6),("LINEBELOW",(0,0),(-1,0),.7,colors.HexColor("#bacbe0"))]))
    story.append(t); story.append(Spacer(1,12))


def picture(name, caption, width=495, max_height=360):
    path = EVIDENCE/name
    if path.exists():
        from PIL import Image as PILImage
        with PILImage.open(path) as im: w, hh = im.size
        scale = min(width/w, max_height/hh)
        story.append(Image(str(path), width=w*scale, height=hh*scale))
        p(caption, "caption")


def architecture():
    d = Drawing(495, 130)
    labels = [("网卡 / lo0", "内核 BPF"),("libpcap", "抓包线程"),("Queue 2048", "传递报文"),("Tk 主线程", "解码与展示")]
    for i,(a,b) in enumerate(labels):
        x=i*128
        d.add(Rect(x,42,109,68,rx=8,fillColor=colors.HexColor("#eef3fa"),strokeColor=colors.HexColor("#c8d7e9")))
        d.add(String(x+54,83,a,fontName="CJK",fontSize=11,textAnchor="middle",fillColor=INK))
        d.add(String(x+54,60,b,fontName="CJK",fontSize=10,textAnchor="middle",fillColor=BLUE))
        if i<3:
            d.add(Line(x+111,76,x+123,76,strokeColor=BLUE))
            d.add(Polygon([x+123,76,x+118,79,x+118,73],fillColor=BLUE,strokeColor=BLUE))
    d.add(String(247,16,"PCAP 文件读取也进入同一解码、过滤、展示流程",fontName="CJK",fontSize=10,textAnchor="middle",fillColor=GREEN))
    story.append(d)


def footer(c, doc):
    c.setStrokeColor(colors.HexColor("#dce5f0")); c.line(48,43,A4[0]-48,43)
    c.setFont("CJK",8);c.setFillColor(colors.HexColor("#62738b"))
    c.drawString(48,29,"PacketLens | 软件与系统安全 · 实验 1A | 2026-11-19")
    c.drawRightString(A4[0]-48,29,str(doc.page))


def main():
    evidence=json.loads((ROOT/"evidence/live-result.json").read_text())
    assert evidence["passed"], "报告必须基于通过的自动化测试与回环捕获"
    p("SOFTWARE &amp; SYSTEM SECURITY", "small")
    story.append(Spacer(1,20))
    p("实验 1A<br/>网络嗅探器设计与实现", "title")
    p("PacketLens · macOS 桌面版", "h2")
    p("报告日期　2026 年 11 月 19 日　｜　许可证　MIT", "small")
    h("摘要")
    p("本实验实现一个具备真实网络捕获能力的图形化嗅探器。底层通过 ctypes 调用系统 libpcap，使用显式字节解析完成链路层、网络层、传输层与常见应用层协议分析。界面包含包列表、协议字段树、HEX/ASCII 字节视图，提供 BPF 抓包过滤、逻辑显示过滤、PCAP 保存与读取，以及双向 TCP 流追踪。")
    p("macOS 26.2（Apple Silicon）环境下，21 项自动化测试和 Tk 窗口集成测试通过。4 秒回环捕获保存 12 个报文，识别出 HTTP 请求和响应各 1 个，内核和程序队列的丢包计数均为 0。")
    table([["实验要求", "实现与证据"],["NPS 实时嗅探（必需）", "libpcap + lo0 实测；samples/live-loopback.pcap"],["图形交互", "Tk 三栏视图、网卡选择、开始/停止、导入导出"],["分层协议过滤", "HTTP、TCP/UDP、IPv4/IPv6、ICMP 等；and/or/not"],["NPA 协议分析", "Ethernet/VLAN/ARP/IP/TCP/UDP/ICMP、HTTP/DNS/TLS 记录头"],["TCP 流追踪（加分）", "双向端点聚合、序列排序、重传去重、缺口提示"]],[145,350])

    page(2,"环境与复现步骤")
    h("运行环境")
    p("实验环境为 macOS 26.2 arm64、Python 3.12 和 Tk 9.0.4。程序使用带 Tk 的 Python 3.10 或更高版本，以及系统 libpcap。应用依赖均由 Python 标准库和系统提供。")
    h("离线启动（普通账户）")
    code('cd packetlens-lab1a\npython3 main.py --demo\n# 或双击源码目录中的 启动.command')
    p("可通过 python3 -m tkinter 检查 Tk 是否可用。启动脚本支持用 PACKETLENS_PYTHON 指定解释器的绝对路径。[4]")
    h("离线分析步骤")
    p("“演示样本”载入 17 个合成报文。HTTP、DNS 和 IPv6 按钮可切换显示过滤。选中报文后，字段树和字节区显示该报文的内容。“追踪 TCP 流”按方向展示重组数据。“导出可见包”将当前筛选结果保存为 classic PCAP。")
    h("自动化测试与回环捕获")
    code('python3 -m unittest discover -s tests -v\npython3 tools/gui_smoke.py\n# macOS 回环捕获，时限 4 秒\nsudo /absolute/path/to/python3 tools/verify_live.py test-output')
    p("命令中的解释器参数使用实际 Python 路径。verify_live.py 启动绑定于 127.0.0.1:8765 的临时 HTTP 服务，禁用客户端代理，并使用 BPF 限定捕获范围。捕获结束后，脚本将 PCAP 和 JSON 写入指定目录。")
    p("图形界面的实时抓包功能要求进程具有 /dev/bpf 访问权限。图形界面捕获实验使用 lo0 及 BPF 表达式 tcp port 8765 and host 127.0.0.1，启动捕获后由 tools/local_traffic.py 生成回环流量。PCAP 离线分析可在普通账户下运行。")
    h("兼容范围")
    p("实验测试覆盖 macOS。源代码包含 Linux libpcap 和 Windows Npcap 加载路径，其他平台的运行结果未验证。")

    page(3,"架构与捕获生命周期")
    architecture()
    table([["模块", "职责"],["sniffer/pcap.py", "ctypes ABI、网卡枚举、BPF、捕获和 PCAP 文件格式"],["sniffer/capture.py", "非阻塞 worker、停止事件、有界队列和丢包统计"],["sniffer/decoder.py", "逐层长度检查、协议字段提取与载荷识别"],["sniffer/filtering.py", "受限语法的递归下降显示过滤器"],["sniffer/streams.py", "双向 TCP 载荷重组、去重与缺口统计"],["sniffer/gui.py", "原生 Tk 三栏界面、批量刷新与文件交互"]],[145,350])
    h("libpcap 调用链")
    code('pcap_findalldevs -> pcap_open_live\n  -> pcap_compile -> pcap_setfilter -> pcap_freecode\n  -> pcap_setnonblock(1) -> pcap_next_ex (bounded loop)\n  -> pcap_stats -> pcap_close')
    p("捕获句柄只由工作线程持有；主线程通过 stop_event 请求退出，不跨线程关闭句柄。每个有效数据包在下一次 libpcap 读取前复制成 Python bytes，避免保留失效指针。非阻塞读取无数据时等待 10 ms，兼顾停止响应和 CPU 占用。[1]")
    h("资源界限与界面响应")
    p("默认捕获 60 秒或 10000 包，允许配置 1..3600 秒；GUI 保存上限为 10000 包或 32 MiB 原始字节。工作队列容量 2048，满时丢弃新事件并计数；主线程每约 80 ms 最多消费 200 包。PCAP 读取也分批执行，防止长文件阻塞 UI。32 MiB 是原始字节上限，不含 Python 对象、控件和队列内存。")
    p("结束或出错时，finally 释放过滤器或句柄。窗口关闭先请求停止，等 worker 退出再销毁 Tk。界面区分 libpcap 内核统计与程序队列丢包；不同平台的 received 统计口径可能不同，不能直接当作 BPF 后的包数。")

    page(4,"协议解析与应用层识别")
    table([["层次", "主要解析与边界"],["链路层", "Ethernet、最多 4 层 VLAN；macOS NULL/LOOP 回环；Linux SLL/SLL2；Raw IP"],["网络层", "ARP 地址与操作；IPv4 IHL/总长度/分片/TTL；IPv6 地址、payload length、最多 16 个扩展头"],["传输层", "TCP 端口、Seq/Ack、标志、窗口、数据偏移；UDP 长度；ICMP/ICMPv6 类型与代码"],["HTTP", "根据请求方法及 HTTP/1.x 起始行或响应起始行识别，显示头部文本"],["DNS", "53 端口上解析报头、问题、应答；名称压缩指针和循环检查；A/AAAA 与部分名称 RDATA"],["TLS", "识别记录类型、记录版本、长度；TLS 加密载荷以原始字节显示"]],[95,400])
    h("解析顺序与安全边界")
    p("每次读取固定字段前执行 require(data, size)；可变长头部检查最小值与已捕获字节数。解析失败的报文保留已识别字段、原始字节和警告。IPv4/IPv6 分片解析止于网络层，避免将不完整传输层内容误判为完整报文。")
    p("HTTP 识别依据请求或响应起始行。测试覆盖端口 8765 上的有效请求和端口 80 上的非 HTTP 载荷。DNS 识别结合端口和结构检查。TLS 识别依据记录头特征，判定结果可能存在误报。")
    h("包与流的区别")
    p("一个 HTTP 头部可能被拆成多个 TCP 段，也可能多个应用消息合在一个段里。当前包列表按单包载荷识别；没有起始行的后续片段可能显示为 TCP。流追踪基于同一会话中已捕获的 TCP 段重组跨段内容。单独导出 HTTP 筛选结果可能遗漏后续片段。")
    h("解析范围")
    p("不校验实际捕获报文的 TCP/UDP 校验和（网卡卸载也会影响观察）；不支持 HTTP/2、HTTP/3、TLS 解密、完整 DNS 扩展记录、IPv6 jumbogram、Wi-Fi Radiotap 解码。未知链路或协议仍保留 HEX 视图。合成样本生成器会计算基本 IP/传输层校验和。")

    page(5,"双层过滤器与 TCP 流算法")
    h("抓包过滤（BPF）")
    p("BPF 交给 libpcap 编译并安装，在捕获开始时生效，例如 tcp port 8765、ip6 and udp port 53。它减少传入应用的数据量。例如，BPF 可限制 TCP 端口，应用层 HTTP 判定在显示过滤阶段完成。[1][2]")
    h("显示过滤语法")
    code('expr := term ("or" term)*\nterm := atom ("and" atom)*\natom := "not" atom | "(" expr ")" | predicate\n\ntcp and (port 80 or port 8765)\nhttp or dns\nipv6 and not udp\nhost 127.0.0.1 and contains get')
    p("支持协议名、host/src/dst IP、port、contains 单个 ASCII 词；优先级 not &gt; and &gt; or。最多 2048 字符、128 token，不调用 eval。contains 在单包 payload 上做不区分 ASCII 大小写的匹配，不支持带空格的引号短语。表达式错误时保留原过滤结果并显示错误。")
    h("双向 TCP 流追踪")
    p("流键是排序后的两个 (IP, port) 端点；分别处理两个发送方向。以 SYN 后一个序列号为锚点，缺少握手时使用首个观察到的载荷序号。将 32 位序号映射为相对有符号偏移，按偏移及包号排序，顺序拼接尚未覆盖的字节；重复或重叠部分计入去重数；缺失区间用文字标记，不用零填充伪造数据。[3]")
    code('relative = ((seq - anchor + 2**31) % 2**32) - 2**31\noverlap = max(0, cursor - relative)\nappend(payload[overlap:])')
    p("合成样本把响应后半段提前送达，并重复发送前 35 字节。重组后响应恢复为 HTTP/1.1 200 OK 与 Hello, PacketLens!，重复字节数为 35，缺失为 0。另有专门测试覆盖序号回绕、部分重叠与初始缺口。")
    p("限制：同一四元组的多次连接可能合并；相对偏移算法假设单方向观察跨度小于 2^31 字节；不是完整 TCP 状态机。冲突重叠按较早序列起点优先，同起点按首见包优先，不模拟各操作系统的重组策略。")

    page(6,"验证结果与可复核证据")
    table([["类别", "结果", "可复核入口"],["核心测试", "21 / 21 通过", "python3 -m unittest discover -s tests -v"],["健壮性", "逐字节截断 + 2000 个确定性随机输入", "tests/test_core.py"],["真实 BPF", "tcp port 80 命中 9；IPv6 DNS 命中 1", "test_real_libpcap_bpf"],["实际 Tk", "导入、过滤、详情、流窗口、导出、取消通过", "tools/gui_smoke.py"],["本机 lo0 捕获", f"{evidence['packets']} 包；HTTP {evidence['http_packets']} 个", "samples/live-loopback.pcap"],["捕获丢包", "内核 0，接口 0，队列 0", "evidence/live-result.json"]],[100,180,215])
    h("回环捕获记录（2026 年 11 月 12 日）")
    code('interface: lo0\nfilter: tcp port 8765 and host 127.0.0.1\nduration limit: 4 seconds\npackets: 12\nhttp_packets: 2\npassed: true\nlibpcap received: 216\nlibpcap dropped / interface_dropped: 0 / 0\nqueue_dropped: 0')
    p("2026 年 11 月 19 日离线复核上述捕获文件。第 5 包为 GET /lab1a HTTP/1.1，第 7 包为 HTTP/1.0 200 OK，服务器正文位于后续 TCP 载荷中。received=216 为 libpcap 平台统计，PCAP 文件包含 12 个过滤后的报文。")
    h("复核结果（2026 年 11 月 19 日）")
    p("项目源码通过语法检查、21 项单元测试及 Tk 集成测试，覆盖截断报文、异常长度、无效过滤式、TCP 序号回绕与重传等情况。17 个合成报文的显示过滤结果为 HTTP 3、TCP 10、UDP 4、IPv4 14、IPv6 2、ICMP 1、ICMPv6 1。协议标签可叠加，同一报文可命中多个条件。")
    p("随附的 evidence 目录包含单元测试和 Tk 集成测试日志，以及回环捕获的统计记录。", "small")

    page(7,"图形界面与使用示例")
    picture("gui-http.png","图 1　HTTP 显示过滤：17 个样本包中显示 3 个，底部保留分层字段与原始字节。",max_height=310)
    picture("gui-stream-response.png","图 2　服务端方向重组：乱序恢复、重复 35 字节去除，最终正文只出现一次。",max_height=250)
    p("Command+1/2/3/4 对应全部/HTTP/DNS/IPv6；Command+O 打开文件；Command+E 导出可见包；Command+F 追踪所选 TCP 流。协议按钮与快捷键调用同一过滤逻辑。", "small")

    page(8,"原理讨论与实验范围")
    h("OSI 模型与课件思考题")
    p("OSI 将网络功能划分为物理、数据链路、网络、传输、会话、表示、应用七层。本程序从链路层或回环伪链路抓取数据，自行向上解析；实际 TCP/IP 模型不必逐一对应 OSI 的所有层。抓取位置决定能观察到哪些信息，协议分析器决定怎样解释这些字节。")
    p("Thor 一类工具可通过代理或系统网络扩展观察应用请求，并在信任根证书且应用允许的条件下参与 TLS 连接，因此能够展示部分 HTTPS 明文。应用层代理可观察 HTTP 语义，链路层嗅探器可观察 TCP 字段和报文顺序。TLS 明文的可见性取决于密钥、信任配置及应用策略。证书固定等机制也会限制代理解密。")
    h("流追踪范围")
    p("TCP 流按 IP 地址与端口归组，提供双向载荷重组。进程归属、同四元组连接代次划分和 IP 分片重组均在实现范围之外。实验结果对应低流量回环环境，未测量高吞吐捕获性能。")
    h("材料索引")
    p("仓库的 docs 目录包含 PDF 报告和 MP4 演示。samples/demo.pcap 为合成协议样本，samples/live-loopback.pcap 为回环抓包样本。")
    p("2026 年 11 月 24 日重录的演示先运行验证脚本进行 4 秒本机回环抓包，捕获 14 个包，含 1 个 HTTP 请求和 1 个响应，丢包计数为 0。随后在 PacketLens 中导入本次 PCAP，演示协议筛选、字段查看、TCP 流重组和导出复核。源代码采用 MIT 许可证。")
    h("AI 辅助说明")
    p("实验实现、测试脚本及材料整理使用了 AI 辅助。报告结果来自自动化测试、Tk 界面测试及保存的本机回环捕获记录。")
    h("参考资料")
    for text,url in [
        ("[1] libpcap 官方源码与 pcap_setnonblock 文档", "https://github.com/the-tcpdump-group/libpcap"),
        ("[2] Npcap 官方开发指南与 libpcap API", "https://npcap.com/guide/npcap-devguide.html"),
        ("[3] RFC 9293: Transmission Control Protocol", "https://www.rfc-editor.org/rfc/rfc9293.html"),
        ("[4] Python 官方 macOS 下载页", "https://www.python.org/downloads/macos/")]:
        p(f'{text}<br/><link href="{url}" color="#245da8">{url}</link>',"small")
    p("课程材料　《实验 1 讲解 2026.pdf》，第 2–3、9、14–15 页。", "small")
    output=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT / "docs/report.pdf"
    output.parent.mkdir(parents=True,exist_ok=True)
    doc=SimpleDocTemplate(str(output),pagesize=A4,rightMargin=48,leftMargin=48,topMargin=45,bottomMargin=57,title="实验1A 网络嗅探器设计与实现",author="")
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    print(output)


if __name__=="__main__": main()
