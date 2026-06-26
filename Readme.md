# 洛克王国协议解析器

- 项目名称： Roco-Kingdom-Protocol-Parser
- 项目简称： RKPP
- 版本： Rock Kingdom Battle Protocol Parser-Ver2.3(Gebetserhörung)

- RKPP 是一个面向学习、协议研究和离线复现的洛克王国战斗协议解析器。

---
## 当前能力

- 抓取 0x1002 会话 key，并用于 0x4013 报文解密。
- 自动持久化最新 key 到 `Key\latest.key`，收到新的 `0x1002` 时自动刷新当前 flow key。
- 支持 live 抓包、离线 pcap 回放、协议实时解析和 opencode relay server。
- 支持列出、显示和设置默认网卡；也可以在命令行中显式指定网卡。
- 支持 `Ivdecoder` 单路径 0x4013 解密：AES-CBC 固定 IV、完整 plaintext、TSF4G trailer 校验。
- 支持 TGCP internal header、payload 原文保留和 schema/payload 双路径解码。
- 继续保留高语义战斗 opcode 的手写摘要，用于回合、技能、伤害、能量、换人、道具和战斗结束分析。

---

## 文件说明

- `rkpp_live_tools.py`：命令行入口，提供抓 key、实时解码、协议分析和 opencode relay。
- `rkpp_analyzer.py`：抓包流重组、解密调度、协议解析和摘要分发。
- `rkpp_proto.py`：TGCP、protobuf wire、TSF4G trailer 与记录解析。
- `rkpp_network.py`：网络流识别、key 处理和 0x4013 解密。
- `rkpp_analysis.py`：opcode/schema 查询、字段树解码、payload codec fallback 和名称增强。
- `rkpp_codec.py`：从 RocoMITMServer 接入的通用 protobuf codec。
- `rkpp_opcode_payload.py`：从 RocoMITMServer 接入的 opcode payload decoder。
- `rkpp_io.py`：CSV、opencode summary、离线 pcap 输入与会话日志。
- `rkpp_reporter.py`：协议实时摘要输出。
- `rkpp_relay.py`：本地 HTTP NDJSON relay server。
- `Data.py`：数据加载入口，优先读取 `rkpp_data.sqlite`。
- `rkpp_data.sqlite`：统一运行时数据包
---

## 依赖安装

建议使用 Python 3.11 或更新版本：

```powershell
python -m pip install -r requirements.txt
```

实时抓包还需要系统侧抓包驱动与权限，例如 Windows 上的 Npcap。离线 pcap 回放和数据刷新不需要打开实时抓包接口。

---

## 基本使用

列出网卡：

```powershell
python rkpp_live_tools.py --list-ifaces
```

设置默认网卡：

```powershell
python rkpp_live_tools.py --set-default-iface WLAN
python rkpp_live_tools.py --show-default-iface
```

抓取 key：

```powershell
python rkpp_live_tools.py capture-key --iface 以太网 --port 8195 --out-dir runs\key_capture
```

抓到的 `0x1002` 会话 key 会同时写入本次输出目录的 `key.txt`，以及项目根目录下的 `Key\YYYYMMDD_HHMMSS.key` 和 `Key\latest.key`。实时解码、协议解析和 relay 命令在未提供 `--key` 时会优先读取 `Key\latest.key`，后续收到新的 `0x1002` 时自动刷新当前 flow key 并更新 Key 目录。

实时协议解析：

```powershell
python rkpp_live_tools.py analyze --iface 以太网 --port 8195 --out-dir runs\analyze
```

离线 pcap 回放：

```powershell
python rkpp_live_tools.py analyze --read-pcap capture.pcap --key <16字节ASCII或32位hex> --out-dir runs\offline
```

## 许可协议

本项目采用 **GNU Affero General Public License v3.0 only（AGPL-3.0-only）** 发布。

这意味着：

1. 任何人都可以在遵守 AGPL-3.0-only 的前提下使用、复制、修改和再发布本项目；
2. 如对本项目进行修改并再次分发，必须继续以 AGPL-3.0-only 开源，并提供对应源码；
3. 如将修改后的版本部署为网络服务、在线接口、远程解析平台或其他可供他人通过网络交互使用的形式，亦必须按 AGPL-3.0-only 向相关用户提供对应源码；
4. 再发布或衍生版本必须保留原作者署名、版权声明、`LICENSE` 文件与 `NOTICE` 文件。

---

## 重要用途声明

**作者不支持将本项目用于外挂、作弊、破坏游戏环境、绕过安全机制、恶意攻击、数据滥用或其他损害游戏生态及第三方合法权益的行为。**

本项目发布的主要目的仅为：

- 学习研究
- 协议结构分析
- 教学示例
- 互操作性研究
- 安全研究与数据格式理解

请在使用前自行确认你的行为是否符合适用法律法规、服务条款、用户协议、EULA、第三方知识产权与相关权利要求。

**如你基于本项目实施任何违反法律法规、违反服务条款、破坏游戏环境或侵害第三方权益的行为，相关风险与责任均由你自行承担。**

---

## 免责声明

本项目按“**原样**”（**AS IS**）提供，不附带任何明示或默示担保，包括但不限于可用性、适销性、特定用途适用性、不侵权、安全性、正确性和稳定性担保。

作者不保证本项目适用于任何生产环境，不保证本项目一定符合任何游戏、平台或服务商的规则，也不保证本项目不存在缺陷、错误、兼容性问题或法律风险。

因使用、修改、分发、部署本项目所导致的任何直接或间接后果，包括但不限于账号处罚、服务封禁、数据丢失、系统损坏、第三方索赔、合同争议、行政责任、民事责任或刑事风险，均由使用者自行承担，**原作者不承担任何责任**。

---

## 侵权与联系说明

如果你认为本项目中的内容存在侵权、权利冲突或其他不适宜公开的问题，请联系作者处理。作者在核实后会尽快处理相关问题；如情况属实，将尽快删除、修改或下线相关内容。

---

## 作者

**花吹雪又一年**
