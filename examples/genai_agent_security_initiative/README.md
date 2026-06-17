# PoC: GenAI Agent Security Initiative (LangGraph samples)

対象: <https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative>
（`code_samples/top_10_for_llms/frameworks/langgraph/*` の意図的に脆弱な LangGraph エージェント）

この PoC は、上記リポジトリの **LangGraph 脆弱サンプル**を本ツールで診断できることを示します。
2 通りの使い方があります。

- **(A) オフライン PoC（すぐ動く / APIキー不要）**: サンプルの構成を本ディレクトリの
  インベントリ YAML としてモデル化し、サンプル実行を模した **LangGraph/OpenInference 形式の
  OTLP トレース**（[`langgraph_trace.json`](langgraph_trace.json)）を取り込んで診断します。
- **(B) ライブ PoC（実際の LangGraph アプリを計装）**: 対象サンプルを OpenTelemetry で計装し、
  実行時トレースを本ツールの受信先へ送って診断します（[`langgraph_runner.py`](langgraph_runner.py)）。

---

## モデル化したサンプル → 資産マッピング

| 初期化リポジトリのサンプル | 本 PoC のエージェント | ツール | 主な狙いの ASI |
| --- | --- | --- | --- |
| `unrestricted_agent` (bash RCE) | `unrestricted-bash-agent` | `execute_command` (shell/critical) | ASI05 / ASI02 / ASI09 |
| `Excessive Db Agency` (任意 Cypher) | `excessive-db-agent` | `run_cypher` (database/high) | ASI03 / ASI02 / ASI09 |
| `multi_agent` (ALS 臨床試験推薦) | `als-supervisor` / `patient-db-agent` / `web-scraper-agent` | `query_patients` / `web_fetch` | ASI06 / ASI07 |

---

## (A) オフライン PoC の実行手順（Windows + Git Bash）

リポジトリのルートで実行します。診断用 DB をこの PoC 専用に分けるため `AAEA_DB_PATH` を使います。

```bash
export AAEA_DB_PATH=data/poc.db    # PoC 専用 DB（既定の data/app.db と分離）

python -m agentic_ai_exposure_assessor.cli ingest-config \
  --fixtures ./examples/genai_agent_security_initiative/inventory
python -m agentic_ai_exposure_assessor.cli ingest-otlp \
  --file ./examples/genai_agent_security_initiative/langgraph_trace.json
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report \
  --format html --output ./reports/poc_report.html
```

> activate していない場合は `python` を `./.venv/Scripts/python.exe` に置き換えてください。

### 期待される主な Finding（13 件・抜粋）

| Rule | Severity | 対象 | 内容 |
| --- | --- | --- | --- |
| ASI05-001 | critical | unrestricted-bash-agent | `execute_command` が承認なしで実行 |
| ASI05-002/003 | medium | unrestricted-bash-agent | サンドボックス証跡なし / 危険なコマンドパターン |
| ASI09-001 | high | unrestricted-bash-agent, excessive-db-agent | 承認必須ツールが承認なしで実行 |
| ASI03-001 | high | excessive-db-agent | 過剰スコープ `graph.*` |
| ASI03-003 | high | excessive-db-agent | `graph.write` が `allowed_scopes` 外 |
| ASI02-003 | medium | 各エージェント | 危険な引数（shell / URL / file path / SQL書込） |
| ASI06-001 | high | web-scraper-agent | 信頼できない Web 由来コンテンツのメモリ書き込み |
| ASI07-001/002 | high/medium | als-supervisor | TLS なし & 高信頼→低信頼へのデータ流通 |

---

## (B) ライブ PoC：実際の LangGraph アプリを計装する

1. 追加依存をインストール（OpenTelemetry + OpenInference）:

   ```bash
   python -m pip install -e ".[langgraph]"
   ```

2. 受信サーバを起動（別ターミナル）:

   ```bash
   python -m agentic_ai_exposure_assessor.cli serve
   # OTLP/HTTP 受信: http://127.0.0.1:8000/v1/traces
   ```

3. [`langgraph_runner.py`](langgraph_runner.py) を編集し、対象サンプル（例:
   `unrestricted_agent/agent.py`）の**コンパイル済みグラフを import して `invoke`** します。
   `instrument_langgraph()` が LangChain/LangGraph を計装し、各 LLM/ツール/ノードの span を
   OpenInference 形式で受信先へ送ります。

4. 診断とレポート:

   ```bash
   python -m agentic_ai_exposure_assessor.cli assess
   python -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/poc_report.html
   ```

> 本ツールは **OpenInference 属性**（`openinference.span.kind=TOOL`、`tool.name`、`input.value`、
> `langgraph.node` 等）を自動認識するため、追加のマッピングは不要です。ライブ実行でも攻撃は行わず、
> あなたが実行したグラフを**観測するだけ**です。

---

## OWASP 分類について

本ツールの ASI コード（`owasp.py`）は OWASP Agentic Top 10 の **Sprint 1 ドラフト**
（例: ASI02 Tool Misuse / ASI05 Unexpected Code Execution / ASI07 Insecure Inter-Agent
Communication）に整合しています。初期化リポジトリの `0.5-initial-candidates` は番号体系が
異なる版（ASI11 RCE など）ですが、`owasp.py` を編集すれば容易に対応付けを変更できます。
