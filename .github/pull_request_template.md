## 设备 / Device

- 型号 / Model:
- 厂商软件和版本 / Vendor software & version:
- 接收器或连接方式 / Receiver or connection:

## 抓包时做了什么 / What you did while capturing

<!-- 例：打开厂商软件，等电量显示出来，没有改任何设置。 / e.g. Opened the vendor software and waited for the battery level; changed no settings. -->

## 厂商软件显示的电量 / Battery level shown by the vendor software

<!-- 每次抓包各写一个，例：第一次 85%，第二次 60%（充电中） / One per capture, e.g. 85% and 60% (charging) -->

## 确认 / Checklist

- [ ] 只包含读取命令，抓包时没有改任何设置 / Read commands only; no settings were changed while capturing
- [ ] 在我自己的电脑上，BatterySenti 用这个定义读到了正确的电量 / BatterySenti read the correct level with this definition on my PC
- [ ] 本地运行 `python tools/check_library.py` 已通过 / `python tools/check_library.py` passes locally
- [ ] 没有上传原始抓包 / No raw captures uploaded
- [ ] 同意按本仓库的许可证发布 / I agree to release this under the repository license
