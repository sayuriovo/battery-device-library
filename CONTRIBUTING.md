# 添加设备 / Adding a device

[English below](#english)

## 中文

### 你需要

- Windows 电脑、这个设备、厂商的官方软件（能显示电量的那个）
- [Wireshark](https://www.wireshark.org/)，安装时勾选 USBPcap
- Python 3，以及 BatterySenti 的源码（里面的 `tools/` 有下面用到的脚本）

### 步骤

1. **抓包**：打开 Wireshark，选 USBPcap 接口，开始抓包。打开厂商软件，等它显示电量，**不要改任何设置**。停止抓包，存成 `.pcapng`。
   - 抓包期间别打字：抓包可能录到键盘输入。后面的步骤只会保留读电量的几帧，但原始文件请自己保管好，**不要上传**。
   - 最好抓两次，电量不同（或者一次充电、一次没充电），方便核对电量在回复的哪一位。
2. **解析**：用 BatterySenti 源码里的工具找出电量报文：
   ```
   python tools\extract_reports.py 你的抓包.pcapng --list-devices
   python tools\extract_reports.py 你的抓包.pcapng --device 1.5 --find 85
   ```
   `--find` 后面填厂商软件显示的电量。
3. **写定义**：在 BatterySenti 源码的 `protocol/devices.json` 里加一项（格式参考里面已有的设备），先在本机确认程序能正确读到电量。`author` 写你的 GitHub 用户名，`notes` 写型号、固件版本、厂商软件名和版本。
4. **导出**：
   ```
   python tools\make_library.py 这个仓库的文件夹 你的设备id
   ```
   它会把定义和证据复制过来，证据只保留引用的帧。
5. **检查**：在这个仓库的文件夹里运行
   ```
   python tools/check_library.py --fix
   ```
   通过以后再提交。
6. **提交 PR**：只改 `devices/`、`captures/` 和 `library.json`。按 PR 模板填写说明。

### 不收的内容

- 任何会改设备设置的命令（灯效、DPI、回报率、按键映射、固件……）。只收**读取**命令。
- 原始抓包（`.pcap` / `.pcapng`）。
- 禁止列表里的设备、BatterySenti 已经内置支持的设备。
- 证据里多余的帧。

---

## English

### You need

- A Windows PC, the device, and the vendor's official software (the one that shows battery level)
- [Wireshark](https://www.wireshark.org/) with USBPcap
- Python 3 and the BatterySenti source code (its `tools/` folder has the scripts used below)

### Steps

1. **Capture**: start Wireshark on the USBPcap interface. Open the vendor software and wait until it shows the battery level. **Don't change any settings.** Stop and save as `.pcapng`.
   - Don't type while capturing — the capture can record keystrokes. Later steps keep only the battery frames, but keep the raw file to yourself and **never upload it**.
   - Two captures at different battery levels (or charging vs. not charging) make it easier to confirm where the value sits.
2. **Parse** with the BatterySenti tool:
   ```
   python tools\extract_reports.py capture.pcapng --list-devices
   python tools\extract_reports.py capture.pcapng --device 1.5 --find 85
   ```
   Put the level shown by the vendor software after `--find`.
3. **Write the definition** in BatterySenti's `protocol/devices.json` (use the existing entries as a template) and confirm the app reads the right level on your PC. Set `author` to your GitHub username; put the model, firmware version and vendor software name/version in `notes`.
4. **Export**:
   ```
   python tools\make_library.py path\to\this\repo your_device_id
   ```
   This copies the definition and the evidence, keeping only the referenced frames.
5. **Check** from this repository's folder:
   ```
   python tools/check_library.py --fix
   ```
6. **Open a PR** that changes only `devices/`, `captures/` and `library.json`, and fill in the PR template.

### Not accepted

- Any command that changes device settings (lighting, DPI, polling rate, key mapping, firmware…). **Read commands only.**
- Raw captures (`.pcap` / `.pcapng`).
- Devices on the deny list, or devices BatterySenti already supports.
- Extra frames in the evidence.
