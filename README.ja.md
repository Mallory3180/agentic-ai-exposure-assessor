# Agentic AI Exposure Assessor（日本語版）

[English](README.md) | **日本語**

Agentic AI アプリケーション向けの **防御的（defensive）** な診断・可視化ツールです。以下を組み合わせています。

- **Tenable AI Exposure 型のインベントリ／エクスポージャ管理** — エージェント、ユーザー、ツール、
  権限、データソース、連携を *資産（asset）* として扱い、設定ミスや危険な組み合わせを
  *Finding* として **エクスポージャ／リスクスコア**付きで可視化します。
- **OpenTelemetry / OTLP 型のランタイムトレース収集** — OTLP 風のトレース JSON を取り込み、
  span / ツール呼び出し / エージェント間メッセージ / メモリ・RAG 操作へ正規化します。
  これにより「設定上どうなっているか」だけでなく「実際に何が実行されたか」を可視化できます。
- **Promptfoo tracing 型のトラジェクトリ評価** — 最終出力だけでなく、*ツール呼び出しシーケンス*、
  *ツール引数*、*承認イベント* をルールで評価します。

Finding は **OWASP Top 10 for Agentic Applications 2026**（ASI01〜ASI10）にマッピングされます。

> 本ツールは **診断専用・読み取り専用** です。実システムへの攻撃、認証回避、権限昇格、
> 攻撃コード生成は一切行いません。提供された設定・トレースデータを取り込んでリスクを報告するだけです。

> ⚙️ **動作モデルについて（重要）**: 本ツールは Promptfoo / Garak のような「能動的にプロンプトを
> 送り込むプロービング型」ではなく、**「資産インベントリ（構成）＋ OTLP ランタイムトレース」を
> 取り込んで評価する Tenable AI Exposure + OpenTelemetry 型**です。対象に接続して動的に診断する
> ライブ運用（インベントリ取得 ＋ OTLP 受信）の設計・設定は
> **[ライブ診断設計ガイド](docs/LIVE_ASSESSMENT.ja.md)** を参照してください。

---

## なぜ Docker を使わないのか

Docker Desktop は **企業利用で有料ライセンスが必要になる可能性がある**ため、この MVP は
**意図的に Docker 非依存**で実装しています。

- Docker Desktop なし、Docker Compose なし、Dockerfile なし。
- WSL 前提なし、Linux 専用シェルスクリプトなし、PowerShell 専用スクリプトなし、`make` なし。
- すべて **ローカルの Python 仮想環境**だけで動作します。

**Windows + Git Bash** での動作を最優先に構築・テストしており、パス処理はすべて `pathlib.Path`
を使用しているため Windows パス（`C:\...`）と POSIX 風パス（`C:/...`）の両方に対応します。
出力先は相対パス（`./reports`、`./data/app.db`）で、存在しないディレクトリは Python 側で作成します。

---

## 前提環境

- **OS**: Windows PC
- **ターミナル**: Git Bash / MINGW64
- **Python**: 3.12 以上
- Docker は不要です。

> 🔰 **コマンド操作に不慣れな方へ**: ソフトのインストールから実行・結果確認まで、画面イメージ付きで
> 1 ステップずつ解説した **[はじめてのセットアップ・実行ガイド（初心者向け）](docs/GETTING_STARTED.ja.md)**
> を用意しています。まずはこちらを参照してください。

---

## セットアップ（Windows + Git Bash）

```bash
py -3.12 -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m agentic_ai_exposure_assessor.cli init-fixtures
python -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report --format markdown --output ./reports/report.md
python -m agentic_ai_exposure_assessor.cli serve
```

### `py -3.12` が使えない場合

PATH 上の Python 3.12 以上をそのまま使ってください。

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -e ".[dev]"
```

### Git Bash で `source .venv/Scripts/activate` がうまくいかない場合

仮想環境内の Python を直接実行できます（activate 不要）。

```bash
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli init-fixtures
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli assess
./.venv/Scripts/python.exe -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
```

---

## アーキテクチャ

```
 fixtures (*.yml)                 OTLP trace (*.json)
        |                                 |
        v                                 v
 config_loader.py                  trace_ingest.py
        |                                 |
        +-------------> SQLite (./data/app.db) <----------- models.py / db.py
                              |
                              v
                   risk_engine.py  --uses-->  rules/owasp_agentic.py (ASI01..ASI10)
                              |                          + scoring.py + redaction.py
                              v
                          Findings
                          /      \
                  report.py       app.py (FastAPI Web UI + JSON API)
              (JSON/MD/HTML)      graph.py (Mermaid)
```

- **インベントリ層**（Tenable 型）: `Agent`, `User`, `Tool`, `Permission`,
  `DataSource`, `ApprovalPolicy`
- **ランタイム証跡層**（OTLP 型）: `RuntimeSpan`, `RuntimeToolCall`,
  `InterAgentMessage`, `MemoryOperation`
- **評価層**: `Finding`, `AssessmentRun`（スコア付与・OWASP タグ付け済み）

コネクタはプラグイン構造（`connectors/`）です。MVP では **fixture** 設定コネクタと
**OTLP file** トレースコネクタを同梱し、クラウド系コネクタ（Copilot Studio、ChatGPT Enterprise、
および類推で Dify / Bedrock / MCP）はドキュメント付きのスタブとして用意しています。

---

## 対象データ

| ファイル | 用途 |
| --- | --- |
| `fixtures/agent_inventory.yml` | エージェント、オーナー、公開範囲、許可ツール、データソース |
| `fixtures/tool_registry.yml` | ツール、カテゴリ、危険度、承認要否、スコープ、サンドボックス |
| `fixtures/permissions.yml` | プリンシパル→ツールの権限付与（スコープ・レベル） |
| `fixtures/approval_policies.yml` | ツールごとの人間による承認要件 |
| `fixtures/data_sources.yml` | RAG / メモリ / DB / ファイル / Web ソース、PII、信頼度 |
| `fixtures/users.yml` | 人間プリンシパル（任意） |
| `fixtures/otlp_trace_sample.json` | OTLP 風ランタイムトレース（ネイティブ OTLP 形式） |
| `fixtures/promptfoo_eval_sample.json` | 簡易フラット span 形式トレース（代替形式） |

OTLP インジェスターは以下の span 属性などを読み取ります: `service.name`, `agent.name`,
`agent.id`, `gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.*`, `tool.name`,
`tool.arguments`, `tool.output`, `function.name`, `mcp.server.name`, `mcp.tool.name`,
`approval.required`, `approval.status`, `approval.approver`, `network.peer.address`,
`network.peer.port`, `network.protocol.name`, `tls.protocol.name`, `tls.cipher`,
`data.source.name`, `memory.operation`, `rag.query`, `rag.source`, `user.id`。

---

## OWASP Top 10 for Agentic Applications 2026 マッピング

| コード | カテゴリ |
| --- | --- |
| ASI01 | Agent Goal and Instruction Manipulation（目標・指示の操作） |
| ASI02 | Tool Misuse and Exploitation（ツールの誤用・悪用） |
| ASI03 | Identity and Privilege Abuse（ID・権限の濫用） |
| ASI04 | Agentic Supply Chain and Dependency Risks（サプライチェーン・依存関係リスク） |
| ASI05 | Unexpected or Unauthorized Code Execution（予期しない・未承認のコード実行） |
| ASI06 | Memory, RAG, and Context Poisoning（メモリ・RAG・コンテキスト汚染） |
| ASI07 | Insecure Inter-Agent Communication（安全でないエージェント間通信） |
| ASI08 | Cascading Failures and Uncontrolled Autonomy（連鎖障害・制御不能な自律性） |
| ASI09 | Human-Agent Trust and Approval Exploitation（人間とエージェントの信頼・承認の悪用） |
| ASI10 | Rogue or Unmanaged Agents（不正・未管理エージェント） |

> カテゴリのコード／名称は `owasp.py` に定数として定義しているため、最終的に公開される
> 分類体系と異なる場合でも容易にリネームできます。

### 実装済みルール

| ルール ID | OWASP | 検知内容 |
| --- | --- | --- |
| ASI02-001 | ASI02 | エージェントの `allowed_tools` に無いツールが実行された |
| ASI02-002 | ASI02 | ツールレジストリに無いツール（未知ツール）が実行された |
| ASI02-003 | ASI02 | 危険な引数（shell、URL、ファイルパス、認証情報、SQL 書き込み、外部宛メール） |
| ASI03-001 | ASI03 | 過剰に広い／ワイルドカードの権限スコープ |
| ASI03-002 | ASI03 | ツールの危険度に対して権限レベルが過剰 |
| ASI03-003 | ASI03 | 実行時の認証情報スコープがツールの `allowed_scopes` の範囲外 |
| ASI05-001 | ASI05 | shell / code_execution / file_system 系ツールが承認なしで実行 |
| ASI05-002 | ASI05 | `sandbox_required=true` なのにトレース上にサンドボックス証跡が無い |
| ASI05-003 | ASI05 | コード実行系ツールの引数に危険なコマンド／パス／URL パターン |
| ASI06-001 | ASI06 | 信頼できないソースからのメモリ書き込み（汚染） |
| ASI06-002 | ASI06 | サニタイズ証跡なしに信頼できない RAG コンテキストを使用 |
| ASI07-001 | ASI07 | TLS が確認できないエージェント間メッセージ |
| ASI07-002 | ASI07 | 高信頼エージェントから低信頼エージェントへのデータ流通 |
| ASI08-001 | ASI08 | 1 トレース内のツール呼び出し回数が閾値超過 |
| ASI08-002 | ASI08 | 同一ツールのリトライ回数が閾値超過 |
| ASI08-003 | ASI08 | 失敗したツール呼び出しの直後に高リスクツールが実行 |
| ASI09-001 | ASI09 | `requires_approval=true` のツールが承認なしで実行 |
| ASI09-002 | ASI09 | 承認ステータスが `approved` 以外（skipped/timeout/bypass/denied）で実行 |
| ASI10-001 | ASI10 | トレース上に未知・未管理エージェントが出現 |
| ASI10-002 | ASI10 | インベントリ上のエージェントにオーナー未設定 |
| ASI10-003 | ASI10 | 公開エージェントが高リスクツールを保有 |

ASI01・ASI04 は `owasp.py` に拡張ポイントとして予約しています（MVP ではデフォルトルールなし）。

### スコアリング

`risk_score = likelihood × impact × confidence`（各 1〜5、範囲 1〜125）。深刻度（severity）は
スコアから導出します: `critical >= 75`、`high >= 45`、`medium >= 20`、`low >= 8`、それ未満は
`info`。エージェント単位・Run 単位の合計は `scoring.py` で集計します。

---

## CLI

```bash
python -m agentic_ai_exposure_assessor.cli init-fixtures
python -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report --format markdown --output ./reports/report.md
python -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
python -m agentic_ai_exposure_assessor.cli export-report --format json --output ./reports/report.json
python -m agentic_ai_exposure_assessor.cli serve
```

`reset-db` で全テーブルを削除・再作成してクリーンな状態に戻せます。SQLite のパスは環境変数
`AAEA_DB_PATH` で上書きできます。

| コマンド | 説明 |
| --- | --- |
| `init-fixtures` | サンプル fixture（YAML + トレース JSON）を生成 |
| `ingest-config` | インベントリ YAML を DB に取り込み |
| `ingest-otlp` | エクスポート済みトレースを取り込み（OTLP / Jaeger / LangSmith / NDJSON を `--format auto` で自動判定、`--append` 対応）。[A-1の詳細](docs/LIVE_ASSESSMENT.ja.md#4-bis-実トレースのオフライン取り込みa-1) |
| `ingest-live` | `targets.yml` のライブ対象からインベントリを取得（[ライブ診断ガイド](docs/LIVE_ASSESSMENT.ja.md)） |
| `assess` | ルールエンジンを実行して Finding を生成 |
| `export-report` | JSON / Markdown / HTML でレポート出力 |
| `serve` | FastAPI Web UI ＋ OTLP/HTTP 受信エンドポイント（`/v1/traces`）を起動 |
| `reset-db` | DB をリセット |

---

## Web UI

```bash
python -m agentic_ai_exposure_assessor.cli serve
# または Uvicorn を直接:
python -m uvicorn agentic_ai_exposure_assessor.app:app --reload --host 127.0.0.1 --port 8000
```

<http://127.0.0.1:8000> を開いてください。ダッシュボードでは、エージェント別リスクスコア、
OWASP カテゴリ別件数、高リスクツール、承認なしで実行されたツール、未知エージェント／ツール、
上位 Finding、Mermaid によるトレースグラフを確認できます。エンドポイント:

`GET /`, `GET /agents`, `GET /tools`, `GET /traces`, `GET /findings`, `GET /owasp`,
`GET /reports/latest`, `GET /api/findings`, `POST /ingest/config`, `POST /ingest/traces`,
`POST /assess`。

---

## Fixture（意図的に脆弱なサンプル）

- **customer-support-agent** — 承認なしで外部宛にメール送信。PII を含む `customer_db` に接続。
  過剰に広い `mail.*` スコープを付与。
- **devops-agent** — 承認なしで shell コマンドを実行。`sandbox_required` だがサンドボックス証跡なし。
  未知の外部 IP へ危険な引数で通信（Windows パス `C:\Users\diag\Downloads\sample.txt` および
  `C:/Users/diag/...` を含む）。
- **rogue-agent** — インベントリに無いがトレース上に出現し、未知ツールを実行。
- **public-web-agent** — 公開状態で高リスクの `run_shell` を保有。サニタイズなしの信頼できない
  RAG コンテンツを使用。
- **analytics-agent** — `allowed_scopes` 外の `db.admin` スコープで `query_database` を実行。
- **legacy-batch-agent** — オーナー未設定でインベントリに登録。
- エージェント間メッセージ: TLS なし（高信頼→低信頼）のものと、TLS ありのものを各 1 件。
- 信頼できないソースからのメモリ書き込み。

---

## LangGraph 対応 と PoC

- **LangGraph / LangChain（OpenInference）トレースを自動認識**します。OTLP インジェスターは
  `openinference.span.kind=TOOL`、`tool.name`、`input.value`、`langgraph.node` などの属性から
  ツール呼び出しを正規化します（追加マッピング不要）。
- 実際の LangGraph アプリを計装してライブ診断するには、オプション依存を入れて計装ヘルパーを使います。

  ```bash
  python -m pip install -e ".[langgraph]"
  ```
  ```python
  from agentic_ai_exposure_assessor.integrations import langgraph as lg
  lg.instrument_langgraph(endpoint="http://127.0.0.1:8000/v1/traces",
                          service_name="my-langgraph-agent")
  # 以後、通常どおり LangGraph アプリを実行すると span が assessor へ送られます
  ```

- **PoC**: [GenAI Agent Security Initiative](https://github.com/GenAI-Security-Project/GenAI-Agent-Security-Initiative)
  の LangGraph 脆弱サンプル（bash RCE / 任意 Cypher / マルチエージェント ALS）を診断する一式を
  [`examples/genai_agent_security_initiative/`](examples/genai_agent_security_initiative/README.md)
  に用意しています（APIキー不要のオフライン PoC ＋ 実アプリ計装のライブ PoC）。

---

## プライバシー・秘匿化（Redaction）

- 秘密情報らしき値（API キー、ベアラートークン、パスワード、秘密鍵、プロバイダのキー接頭辞）は
  レポートや保存される証跡を含め、あらゆる箇所でマスクします。
- 生のプロンプトや生のツール出力は **そのまま保存しません**。取り込み時に秘匿化のうえ短く要約します。
- メールアドレスは必要に応じてマスクできます。

---

## レポート

レポートは `./reports` 配下に出力されます（自動作成）。

- `report.md` — 必須の章立て（エグゼクティブサマリー、スコープ、エージェントインベントリ、
  ツール・権限マトリクス、ランタイムトレース分析、承認ゲート分析、OWASP マッピング、Findings、
  推奨事項、付録: 証跡）を含む Markdown（Mermaid グラフ付き）。
- `report.html` — Mermaid グラフをレンダリングするスタイル付き HTML。
- `report.json` — 完全な機械可読データ。

---

## テスト

```bash
python -m pytest
# venv を activate しない場合:
./.venv/Scripts/python.exe -m pytest
```

Lint / 型チェック（任意）:

```bash
python -m ruff check .
python -m mypy src
```

---

## 既知の制限

- MVP は fixture ベースで、ライブのクラウドコネクタは未実装（スタブのみ）。
- 単一 Run の意味論: `assess` のたびに過去の Finding を置換し、各取り込みは同種の既存データを置換
  （`ingest-otlp` の `--append` でランタイムデータを保持可能）。
- ヒューリスティック検出（危険な引数、秘密情報）は過検知寄り。閾値は `rules/base.py`
  （`AssessmentContext`）で調整可能。
- ASI01 / ASI04 のデフォルトルールは未実装。
- SQLite + インプロセス FastAPI のため、高並行の本番用途は想定外。

---

## 今後の拡張

- コネクタ: Microsoft Copilot Studio、ChatGPT Enterprise、Dify、Amazon Bedrock Agents、MCP サーバー。
- Promptfoo トレースの正式インポート、より高度なトラジェクトリルール（`tool-used`、
  `tool-args-match`、`tool-sequence`）。
- OpenTelemetry Collector 経由（gRPC/HTTP）での OTLP 取り込み（JSON ファイルに加えて）。
- グラフ DB バックエンド（Neo4j）によるエージェント／ツール／データフローグラフ。
- PDF レポート出力。
- ASI01 / ASI04 ルールパック（目標・指示の操作、サプライチェーン・依存関係リスク）。
