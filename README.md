# BatterySenti 社区设备库 / Community Device Library

[中文](#中文) · [English](#english)

---

## 中文

这是 [BatterySenti](https://github.com/sayuriovo) 的社区设备库。BatterySenti 是一个 Windows 托盘小程序，显示无线鼠标、耳机、键盘的电量。

程序内置支持的设备不需要这里。这里收集的是**程序还不认识的设备**：别人用抓包整理出"发哪几个字节、电量在回复第几位"，提交到这里以后，所有用户点一下"更新设备库"就能用，不用等程序发新版本。

### 这里放的是什么

- 只有**数据**，没有代码。程序不会执行这个仓库里的任何东西。
- 每个设备一个定义文件（`devices/<id>.json`），加上抓包证据（`captures/<id>/*.extracted.csv`）。
- 证据只保留读电量用到的那几帧，不含按键、序列号等其他数据。

### 安全设计

BatterySenti 下载这个库时会：

1. 固定到某一次提交，下载后内容不会悄悄变化；
2. 按 `library.json` 校验每个文件的 SHA-256；
3. 核对请求字节和证据里电脑发给设备的那一帧一字不差；
4. 跳过禁止列表里的设备和程序已经内置支持的设备；
5. 新下载的定义**默认不启用**，用户在设置窗口里逐个确认后才使用；定义一改，需要重新确认。

每个提交（PR）都会自动运行 `tools/check_library.py`，再经过人工审核才合并，见 [REVIEW.md](REVIEW.md)。

**局限：** 程序和脚本只能证明"请求字节确实出现在提交者给的抓包里"，不能证明抓包本身是真的，也不能自动判断一条报文是不是只读。所以人工审核是最后一道关。

### 想添加设备

见 [CONTRIBUTING.md](CONTRIBUTING.md)。不会抓包的话，也可以开一个 Issue，写上设备型号和厂商软件名，等有人来做。

### 许可证

见 [LICENSE](LICENSE)。提交内容即表示你同意按这个许可证发布。

---

## English

This is the community device library for [BatterySenti](https://github.com/sayuriovo), a Windows tray app that shows the battery level of wireless mice, headsets and keyboards.

Devices the app already supports don't need to be here. This library collects **devices the app doesn't know yet**: someone captures the USB traffic, works out which bytes to send and where the battery value sits in the reply, and submits it here. Every user can then click "Update library" in the app — no new app release needed.

### What's in here

- **Data only, no code.** The app never executes anything from this repository.
- One definition per device (`devices/<id>.json`) plus capture evidence (`captures/<id>/*.extracted.csv`).
- Evidence keeps only the frames used to read the battery — no keystrokes, serial numbers or other data.

### Safety

When BatterySenti downloads this library it:

1. pins to a specific commit, so the content can't change silently afterwards;
2. checks every file's SHA-256 against `library.json`;
3. checks that the request bytes match, byte for byte, a host-to-device frame in the evidence;
4. skips devices on its deny list and devices it already supports;
5. leaves new definitions **disabled** until the user turns each one on; a changed definition must be confirmed again.

Every pull request runs `tools/check_library.py` automatically and is reviewed by hand before merging — see [REVIEW.md](REVIEW.md).

**Limitation:** the checks prove that the request bytes appear in the submitter's capture. They cannot prove the capture is genuine, and they cannot tell automatically whether a command is read-only. Human review is the last line of defence.

### Adding a device

See [CONTRIBUTING.md](CONTRIBUTING.md). If you can't capture traffic yourself, open an Issue with the device model and the vendor software name.

### License

See [LICENSE](LICENSE). By submitting content you agree to release it under this license.
