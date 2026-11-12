"""将实际 GUI 截图和真实测试日志排版为字幕演示素材，不伪造连续录屏。"""
from pathlib import Path
import json
import sys
from PIL import Image, ImageDraw, ImageFont

ROOT=Path(__file__).resolve().parents[1]
EVIDENCE=ROOT.parent/"验证材料"
if not EVIDENCE.exists(): EVIDENCE=ROOT/"evidence"
OUT=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/"test-output/video-frames"
FONT="/System/Library/Fonts/Supplemental/Arial Unicode.ttf"
W,H=1920,1080


def font(size):return ImageFont.truetype(FONT,size)


def base(chapter,title,subtitle):
    im=Image.new("RGB",(W,H),"#f0f4f9");d=ImageDraw.Draw(im)
    d.rectangle((0,0,W,116),fill="#12253e")
    d.text((48,22),title,font=font(38),fill="white")
    d.text((50,76),subtitle,font=font(21),fill="#b9cbe2")
    d.rectangle((0,1004,W,H),fill="#12253e")
    d.text((48,1026),"PacketLens  |  软件与系统安全实验 1A  |  实际截图与验收日志演示",font=font(22),fill="#d1deed")
    d.text((1770,1026),chapter,font=font(22),fill="#86dfca")
    return im,d


def screenshot(chapter,title,subtitle,name,notes):
    im,d=base(chapter,title,subtitle)
    shot=Image.open(EVIDENCE/name).convert("RGB")
    shot.thumbnail((1440,850),Image.Resampling.LANCZOS)
    im.paste(shot,(28+(1440-shot.width)//2,136+(850-shot.height)//2))
    y=175
    for heading,lines in notes:
        d.text((1510,y),heading,font=font(29),fill="#245da8");y+=55
        for line in lines:
            d.text((1510,y),line,font=font(23),fill="#273a55");y+=40
        y+=42
    return im


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    scenes=[]
    im,d=base("01 / 10","实验 1A · 网络嗅探器设计与实现","macOS · Python + Tk · libpcap · MIT")
    d.text((110,225),"PacketLens",font=font(90),fill="#172b46")
    for y,line in zip([385,465,545,625],["真实捕获  →  分层解析  →  双层过滤  →  TCP 流追踪","21 项核心测试通过；实际 Tk 窗口集成测试通过","本机 lo0 实测：12 个包，2 个 HTTP 头部，丢包计数为 0","本视频由真实界面截图与验收日志构成，无配音，非连续录屏。"]):
        d.text((115,y),line,font=font(32 if y<625 else 27),fill="#34465f")
    d.text((115,790),"github.com/mahoushaoping/packetlens-lab1a",font=font(35),fill="#245da8")
    scenes.append((im,9))
    im,d=base("02 / 10","启动与测试","Python 无需编译链接；先做语法编译检查，再启动实际 GUI。")
    lines=["cd 实验1A_src","python3 -m compileall -q sniffer tools tests","python3 -m unittest discover -s tests -v","python3 tools/gui_smoke.py","python3 main.py --demo"]
    for i,line in enumerate(lines):d.text((100,190+i*70),line,font=font(32),fill="#172b46")
    log=(EVIDENCE/"unit-tests.txt").read_text()
    tail="\n".join(log.strip().splitlines()[-4:])
    d.rounded_rectangle((90,600,1810,910),radius=18,fill="#e1eceb")
    d.text((120,620),"实际自动化测试日志摘录",font=font(30),fill="#147c6b")
    d.multiline_text((120,690),tail,font=font(30),fill="#172b46",spacing=12)
    scenes.append((im,12))
    scenes.append((screenshot("03 / 10","三栏协议分析界面","载入 samples/demo.pcap：17 个合成报文，不含真实第三方流量。","gui-overview.png",[("包列表",["按捕获顺序展示","源/目的地址与摘要"]),("协议树",["字段按层次展开","异常报文保留警告"]),("HEX / ASCII",["保留完整捕获字节","支持横向与纵向滚动"])]),10))
    scenes.append((screenshot("04 / 10","HTTP 显示过滤","点击 HTTP 或 Command+2；内容识别，不把端口 80 直接当成 HTTP。","gui-http.png",[("17 → 3 包",["1 个请求头","2 个响应头样本","包含一次重传"]),("两种过滤",["BPF 控制捕获范围","显示过滤控制可见包"]),("完整会话",["后续 TCP 段可能","不带 HTTP 起始行","请使用流追踪"])]),10))
    scenes.append((screenshot("05 / 10","DNS 分析","点击 DNS 或 Command+3；解析问题、回答与名称压缩指针。","gui-dns.png",[("名称解析",["事务 ID / 应答标志","域名与记录类型","A / AAAA 地址"]),("边界检查",["检测压缩指针循环","限制问题/回答数量"])]),9))
    scenes.append((screenshot("06 / 10","IPv6 与分层过滤","点击 IPv6 或 Command+4；同一过滤结果包含 DNS 和 ICMPv6。","gui-ipv6.png",[("协议按层叠加",["IPv6 + UDP + DNS","IPv6 + ICMPv6"]),("逻辑表达式",["ipv6 and not udp","http or dns"])]),9))
    scenes.append((screenshot("07 / 10","TCP 流：请求方向","选中 HTTP 包，Command+F 或点击“追踪 TCP 流”。","gui-stream-request.png",[("双向端点键",["IP + Port 识别流","分别展示两个方向"]),("重组规则",["序列号排序","去除重复字节","缺口明确标注"])]),9))
    scenes.append((screenshot("08 / 10","TCP 流：乱序与重传","切换到服务器方向：从乱序片段恢复完整响应。","gui-stream-response.png",[("重组结果",["HTTP/1.1 200 OK","Hello, PacketLens!"]),("验证数据",["重复 35 字节","缺失 0 字节","正文仅出现一次"]),("已知边界",["同四元组多次连接","可能被聚合","TLS 不解密"])]),12))
    receipt=json.loads((EVIDENCE/"live-result.json").read_text())
    im,d=base("09 / 10","真实 lo0 捕获验收","用户在终端输入管理员密码后执行；此处显示实际生成的 JSON 收据。")
    receipt_text=json.dumps(receipt,ensure_ascii=False,indent=2)
    d.multiline_text((75,155),receipt_text,font=font(25),fill="#172b46",spacing=6)
    for y,line in zip([200,290,380,470,560,650,740],["捕获范围仅 127.0.0.1:8765","4 秒自动停止；等待 worker 退出","临时本机 HTTP 服务，禁用代理","第 5 包：GET /lab1a HTTP/1.1","第 7 包：HTTP/1.0 200 OK","received=216 是平台计数","PCAP 实际保存 12 个过滤后报文"]):
        d.text((1050,y),line,font=font(26),fill="#245da8")
    scenes.append((im,15))
    im,d=base("10 / 10","交付与复现入口","源码、实验报告、演示视频、样本 PCAP、验收日志均随 ZIP 提供。")
    items=[("运行", "双击 启动.command，或 python3 main.py --demo"),("真实捕获", "具备 BPF 权限后运行；本次仅授权一次有界验收"),("导出", "导出可见包；classic PCAP 可供其他分析工具读取"),("Git", "github.com/mahoushaoping/packetlens-lab1a"),("说明", "仓库当前私有；姓名学号留白；报告披露 AI 辅助"),("范围", "未实现 TLS 解密、IP 分片重组与进程级流归属")]
    for i,(a,b) in enumerate(items):
        y=185+i*120;d.text((90,y),a,font=font(33),fill="#147c6b");d.text((330,y),b,font=font(30),fill="#172b46")
    scenes.append((im,10))
    manifest=[]
    for i,(im,duration) in enumerate(scenes):
        path=OUT/f"scene-{i+1:02}.png";im.save(path)
        manifest.append(dict(path=str(path.resolve()),seconds=duration))
    (OUT/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    print(json.dumps(dict(scenes=len(scenes),seconds=sum(x[1] for x in scenes),manifest=str(OUT/"manifest.json")),ensure_ascii=False))


if __name__=="__main__":main()
