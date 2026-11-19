# PacketLens

PacketLens 是《软件与系统安全》实验 1A 的桌面网络嗅探器。程序通过 libpcap 捕获报文，在图形界面显示协议字段和原始字节，支持 BPF 抓包过滤、协议显示过滤、PCAP 导入导出和双向 TCP 流重组。

[实验报告](docs/report.pdf) · [演示视频](docs/demo.mp4) · [验证记录](evidence/validation.json)

## 运行

macOS 需要带 Tk 的 Python 3.10 或更高版本，抓包使用系统 libpcap。项目的应用代码使用标准库。

```sh
python3 -m tkinter
python3 main.py --demo
```

`--demo` 加载随附的 17 个合成报文。过滤表达式可使用 `http or dns`、`ipv6 and not udp`、`tcp and port 8765`。选中 TCP 报文后可查看两个传输方向的重组载荷。离线分析可在普通账户下运行，实时抓包要求进程具备 BPF 设备访问权限。

## 目录

| 路径 | 内容 |
| --- | --- |
| [sniffer/](sniffer/) | 抓包后端、协议解析、显示过滤、TCP 流重组及 Tk 界面 |
| [tests/](tests/) | 单元测试 |
| [samples/](samples/) | 合成协议样本与本机回环 PCAP |
| [tools/](tools/) | 样本生成、本机流量生成、抓包与 GUI 验证脚本 |
| [tools/media/](tools/media/) | 报告、视频素材生成及视频校验脚本 |
| [docs/](docs/) | PDF 报告与 MP4 演示 |
| [evidence/](evidence/) | 统计记录、测试日志和界面截图 |

## 验证

```sh
python3 -m unittest discover -s tests -v
python3 tools/gui_smoke.py
```

2026 年 11 月 19 日在 macOS 上复核，21 项单元测试及 Tk 界面测试通过。2026 年 11 月 12 日的回环捕获记录包含 12 个报文，其中 HTTP 请求和响应各一条。详细记录见 [回环统计](evidence/live-result.json) 和 [实验报告](docs/report.pdf)。

实验覆盖 macOS。应用层解析范围包括 HTTP/1.x、DNS 与 TLS 记录头。TCP 流按端点归组，进程归属和连接代次划分超出实现范围。

## 生成报告和视频

材料生成脚本在 macOS 上运行，使用系统 Arial Unicode 字体。生成目录 `test-output/` 由 Git 忽略。

```sh
python3 -m pip install -r requirements-dev.txt
mkdir -p test-output
python3 tools/media/build_report.py test-output/report.pdf
python3 tools/media/build_video_frames.py test-output/video-frames
swift tools/media/encode_video.swift test-output/video-frames/manifest.json test-output/demo.mp4
swift tools/media/check_video.swift test-output/demo.mp4 test-output/video-frames
```

[MIT 许可证](LICENSE)
