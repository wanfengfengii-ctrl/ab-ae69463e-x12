# X12 信封审计服务

供应链集成平台的准入网关：在接纳合作方 X12 批次前，校验交换（ISA/IEA）、
功能组（GS/GE）与事务集（ST/SE）三级信封的完整性，防止截断、拼接或错误
计数的报文进入后续结算流程。

## 快速启动

```bash
docker compose up --build api          # 启动 API（默认宿主机端口 8000）
API_PORT=9000 docker compose up api    # 通过 API_PORT 环境变量配置宿主机端口
```

一次性验证服务 `verify` 会等待 API 健康检查通过后，依次执行代码测试
（pytest）、应用构建检查（字节编译 + ASGI 导入 + 路由断言）以及有效与
损坏信封的 HTTP 冒烟，并以退出码汇总结果（全部通过为 0，否则为 1）：

```bash
docker compose up --build --exit-code-from verify --abort-on-container-exit verify
echo $?   # 0 = 全部通过
```

## API

### `POST /api/x12/audit`

- 请求体：`application/octet-stream`，ASCII 报文，不超过 2 MiB
  （2 097 152 字节）。
- 元素分隔符、组件分隔符与段终止符取自固定长度（106 字符）ISA 段的
  第 4、105、106 个字符，并校验 ISA 各固定分隔位。

成功响应 `200`：

```json
{
  "ok": true,
  "interchangeControlNumber": "000000001",
  "groups": 2,
  "transactions": 3,
  "sha256": "<原始报文字节的 SHA-256，十六进制>"
}
```

失败响应 `400`（超限为 `413`）：

```json
{
  "ok": false,
  "error": {
    "code": "SEGMENT_COUNT_MISMATCH",
    "message": "SE01 declares 9 segment(s) but 3 were counted from ST through SE",
    "segment": 5
  }
}
```

`segment` 为首个可定位的段序号（1 起，ISA 为第 1 段）；无法在段级定位时
为 `null`。校验按报文顺序进行，内层信封的错误不会被外层汇总段（GE/IEA）
掩盖。

### `GET /health`

就绪探针，返回 `{"status": "ok"}`；容器健康检查与 `verify` 的健康门均
依赖该端点。

## 信封规则

- 报文须形成唯一 ISA/IEA 交换：ISA 之后不得再出现 ISA，IEA 之后不得
  出现任何段。
- 交换内含 1–64 个 GS/GE 功能组；每组内含 1–500 个 ST/SE 事务集。
- 层级不得交错：ST 只能出现在 GS 内，SE/GE/IEA 逐级闭合，数据段只能
  出现在 ST 与 SE 之间。
- 成对控制号必须吻合：ISA13=IEA02、GS06=GE02、ST02=SE02。
- 计数必须吻合：SE01=ST..SE 实际段数、GE01=组内实际事务数、
  IEA01=交换内实际组数。

## 稳定错误码

| 错误码 | 含义 |
| --- | --- |
| `PAYLOAD_EMPTY` | 请求体为空 |
| `PAYLOAD_TOO_LARGE` | 超过 2 MiB（HTTP 413） |
| `NON_ASCII_PAYLOAD` | 含非 ASCII 字节 |
| `MISSING_ISA` | 报文未以 ISA 段起始 |
| `ISA_TRUNCATED` | ISA 段不足 106 字符 |
| `ISA_MALFORMED` | ISA 固定分隔位/元素数/终止位置不符 |
| `INVALID_DELIMITERS` | 三个分隔符非可打印、为字母数字或彼此相同 |
| `NO_GROUPS` | 交换内没有任何功能组 |
| `EMPTY_GROUP` | 功能组内没有任何事务集 |
| `GROUP_LIMIT_EXCEEDED` | 功能组超过 64 个 |
| `TRANSACTION_LIMIT_EXCEEDED` | 单组事务集超过 500 个 |
| `UNEXPECTED_SEGMENT` | 层级交错或位置非法的段 |
| `TRAILING_DATA` | IEA 之后仍存在段 |
| `MISSING_SE` / `MISSING_GE` / `MISSING_IEA` | 信封被截断，缺少闭合段 |
| `MALFORMED_SEGMENT` | 必需元素缺失或计数元素非整数 |
| `SEGMENT_COUNT_MISMATCH` | SE01 与实际段数不符 |
| `TRANSACTION_COUNT_MISMATCH` | GE01 与实际事务数不符 |
| `GROUP_COUNT_MISMATCH` | IEA01 与实际组数不符 |
| `CONTROL_NUMBER_MISMATCH` | 成对控制号不吻合 |

## 本地开发

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests -q                 # 代码测试
.venv/bin/uvicorn app.main:app --port 8000 &        # 本地启动
API_BASE_URL=http://127.0.0.1:8000 .venv/bin/python verify.py
```

## 项目结构

```
app/x12.py        纯解析器：分隔符提取、状态机校验、计数与控制号核对
app/main.py       FastAPI HTTP 层：/api/x12/audit 与 /health
tests/            pytest 单元测试（44 例）
verify.py         一次性验证：健康门 → 代码测试 → 构建检查 → HTTP 冒烟
Dockerfile        单一镜像：API 与 verify 共用
docker-compose.yml  api（端口可配、健康检查）+ verify（一次性）
```
