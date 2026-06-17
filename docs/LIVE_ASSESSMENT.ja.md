# 対象 Agentic AI への実行（ライブ診断）設計ガイド

[← README（日本語）に戻る](../README.ja.md)

このドキュメントは、「**対象の Agentic AI に接続して動的に診断・可視化したい**」というユースケース
に対する、本ツールの**動作モデル**と**必要な接続設定**、および実装状況を説明します。

---

## 1. 重要な前提：本ツールの立ち位置

本ツールは **Promptfoo / Garak のような「能動的プロービング型」ではありません**。
対象にプロンプトを送り込んで攻撃的に揺さぶるのではなく、

> **「資産インベントリ（構成）」＋「OTLP ランタイムトレース（実際の実行証跡）」** を取り込み、
> OWASP Top 10 for Agentic Applications 2026 の観点で**リスクを可視化・採点する**

という **Tenable AI Exposure + OpenTelemetry 型**の防御的診断ツールです。

| | Promptfoo / Garak | 本ツール |
| --- | --- | --- |
| 主な評価対象 | LLM のテキスト出力（脱獄/有害出力など） | エージェント構成 ＋ ツール呼び出し/承認/A2A/メモリ等の実行証跡 |
| 動作 | 対象にプロンプトを能動送信 | 構成を棚卸し ＋ 実行トレースを受信・解析 |
| 接続情報の意味 | 推論エンドポイント＋プロンプト | 管理API（資産列挙）＋ OTLP受信先 |

### なぜテキストAPIを叩くだけでは不十分か

「どのツールが承認なしで実行されたか」「高信頼→低信頼エージェントへ機密が渡ったか」などは、
**対象が内部挙動を露出していなければ外から観測できません**。本ツールはその露出手段として
**OpenTelemetry / OTLP** を採用します（後述）。

---

## 2. ライブ診断の 2 つのデータ経路

```
                ┌─────────────────────────────────────────────┐
   ① 構成       │ 対象プラットフォーム                          │
   インベントリ │  (Dify / Azure OpenAI / Bedrock / MCP / 独自) │
   取得 ◀───────┤  - 管理API（エージェント/ツール/権限を列挙）  │
                │  - OpenTelemetry 計装（実行時に span を出力） ├──┐
                └─────────────────────────────────────────────┘  │
                                                                  │ ② OTLP push
        ┌──────────────────────────────────────────────┐         │
        │ agentic-ai-exposure-assessor                  │ ◀───────┘
        │  ingest-live  → インベントリを取得・保存       │
        │  /v1/traces   → OTLPトレースを受信・正規化     │
        │  assess       → ルール評価 → Finding/レポート  │
        └──────────────────────────────────────────────┘
```

- **① インベントリ取得（`ingest-live`）**: `targets.yml` に宣言した各対象から、エージェント/
  ツール/権限/データソースを**読み取り専用**で列挙して取り込みます。
- **② OTLP トレース受信（`serve` の `/v1/traces`）**: 計装済みの対象（または OpenTelemetry
  Collector）から実行時 span を受信し、ツール呼び出し等へ正規化します。

この 2 経路で集めた情報を、既存の `assess`（ルールエンジン）→ レポート/Web UI にそのまま流します。

---

## 3. 接続情報の設定（`targets.yml`）

`init-fixtures` で生成される [`fixtures/targets.example.yml`](../fixtures/targets.example.yml)
を `./targets.yml` にコピーして編集します。

```yaml
targets:
  - id: internal-agent-registry
    platform: generic_http          # generic_http / dify / azure_openai / bedrock / mcp
    enabled: true
    inventory:
      base_url: https://agent-registry.internal.example/api/inventory
      token_env: AGENT_REGISTRY_TOKEN   # ← 環境変数名（値は書かない）
    telemetry:
      mode: otlp_push
```

> 🔐 **秘密情報はファイルに書きません。** `token_env` には**環境変数の名前**だけを書き、値は
> 実行前にシェルで `export` します（例: `export AGENT_REGISTRY_TOKEN=...`）。
> 本ツールはログ・レポートでも秘密情報をマスクします。

実行例（Git Bash）:

```bash
export AGENT_REGISTRY_TOKEN=xxxxx
python -m agentic_ai_exposure_assessor.cli ingest-live --targets ./targets.yml
python -m agentic_ai_exposure_assessor.cli assess
```

---

## 4. OTLP トレースの受信設定

`serve` を起動すると、OTLP/HTTP（JSON）受信エンドポイントが立ち上がります。

```bash
python -m agentic_ai_exposure_assessor.cli serve
# → OTLP/HTTP trace receiver listening at http://127.0.0.1:8000/v1/traces
```

対象アプリ（または OpenTelemetry Collector）側で、OTLP エクスポート先を本受信先に向けます。

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:8000/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json
```

> 本 MVP は **OTLP/JSON** のみ対応（protobuf 非対応）。protobuf で出力する場合は、間に
> OpenTelemetry Collector を置き、JSON で本エンドポイントへ転送してください。

受信した span が認識されるよう、対象側で以下の属性を付与すると診断精度が上がります（抜粋）:
`agent.name`, `tool.name` / `mcp.tool.name` / `function.name`, `tool.arguments`,
`approval.required` / `approval.status`, `credential.scope`, `tls.protocol.name`,
`network.peer.address`, `memory.operation`, `rag.source`, `source.trust`。
（完全な一覧は [README（日本語）](../README.ja.md#対象データ) を参照）

---

## 4-bis. 実トレースのオフライン取り込み（A-1）

ライブ受信（②）の常時接続が難しい企業環境では、**顧客が既に持っているテレメトリをエクスポート
してファイルで取り込む**方が現実的なことが多いです。`ingest-otlp` は複数フォーマットを
**自動判定**して取り込みます（`--format` で明示も可能）。

```bash
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./export.json            # 自動判定
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./jaeger.json --format jaeger
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./langsmith.json --format langsmith
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./otel.ndjson --append    # NDJSON 追記
```

| 形式 (`--format`) | エクスポート元の例 | 取得方法の目安 |
| --- | --- | --- |
| `otlp` | OpenTelemetry Collector の **`file` exporter**、OTLP/JSON 出力 | Collector に file exporter を追加 → JSON/NDJSON を回収 |
| `jaeger` | Jaeger / Tempo / Grafana | Jaeger クエリAPI `GET /api/traces?...` の JSON を保存 |
| `langsmith` | LangSmith（LangChain/LangGraph） | runs を API/UI でバルクエクスポート（`{"runs":[...]}` または配列） |
| `simplified` | 本ツール独自のフラット span | 既存サンプル形式 |

> 💡 顧客は、本ツール固有の属性（`approval.status`、`credential.scope`、`tls.protocol.name`、
> `memory.operation`、`source.trust` など）を **Jaeger のタグ** や **LangSmith の metadata**
> に載せておけば、そのまま診断に反映されます。

### A-1 が現実的になる条件・限界（正直な整理）

- ✅ **計装済み**（OTel / OpenInference / LangSmith）なら、エクスポート→取り込みは現実的で、
  ライブ常時接続より企業環境で採用しやすい。
- ⚠️ **未計装の独自アプリ**は、一度きりの計装（OpenInference 自動計装で数行）が必要。
- ⚠️ **非OTLP独自形式**（Bedrock/Azure/Dify の独自ログ等）は、本アダプタに変換ルールの追加実装が必要。
- ⚠️ **カバレッジ**は「実際に通った経路」しか見えない。代表的な業務シナリオを流した記録が前提。
- ❌ **手書きの模擬トレース**は実システムを保証しない（デモ/受け入れ確認専用）。

---

## 5. プラットフォーム別・必要接続情報

| platform | インベントリ取得 | 必要な接続情報 | 実装状況 |
| --- | --- | --- | --- |
| `generic_http` | 任意の JSON エンドポイント（fixtures 形状を返す） | `base_url`、任意で `token_env` | ✅ 実装済み（動作） |
| `dify` | アプリ/エージェント・有効ツール・ナレッジを列挙 | `base_url`、`token_env`(Dify APIキー) | 📝 拡張ポイント（要件明文化済み） |
| `azure_openai` | デプロイ/Assistants・関数ツール・On Your Data を列挙 | `endpoint`、`api_version`、`token_env`(APIキー/AADトークン) | 📝 拡張ポイント |
| `bedrock` | bedrock-agent の ListAgents/ActionGroups・KB を列挙 | `region`、AWS標準資格情報(環境/ロール)、読み取り専用IAM | 📝 拡張ポイント |
| `mcp` | MCP `tools/list` / `resources/list` を列挙 | `server_url`(HTTP/SSE) または `command`(stdio)、任意 `token_env` | 📝 拡張ポイント |

> 📝 の各コネクタは `src/agentic_ai_exposure_assessor/connectors/live.py` に**必要設定とAPIの
> 当たり**を明記したクラスとして用意してあり、`load()` を実装すれば有効化できます（テナント固有の
> 資格情報・APIが必要なため MVP では未実装。実行すると `ConnectorNotConfigured` で要件を表示）。
>
> **OTLP トレース受信（②）はプラットフォーム非依存**です。対象が OpenTelemetry で計装されていれば、
> `generic_http` 以外でも実行時の挙動を可視化できます。

---

## 6. 観測可否マトリクス（何が見えるか）

| データ経路 | 構成（Agent/Tool/権限/承認ポリシー） | 実行時のツール呼び出し/承認/A2A/メモリ |
| --- | --- | --- |
| ① インベントリ取得のみ | ✅ 見える | ❌ 見えない（静的な設定ミスの検出に限定） |
| ② OTLP トレースのみ | △ トレースに現れた範囲 | ✅ 見える |
| ①＋② 併用（推奨） | ✅ | ✅ → **設計と実態の突合**（例: 許可外ツールの実行、承認なし実行）が可能 |

最も価値が出るのは **①＋② の併用**です。構成だけ・トレースだけでも一部のルールは動作します。

---

## 7. 既存機能との関係（再利用）

- 取り込んだインベントリ／トレースは、**既存の正規化・ルール・スコアリング・レポート・Web UI**
  をそのまま通ります（`assess` / `export-report` / `serve`）。
- fixtures（オフラインのサンプル）での動作確認も従来どおり可能です。ライブ機能は前段の
  「データ収集元」を増やしたものであり、診断ロジックは共通です。

---

## 8. 実装状況とロードマップ

**実装済み（このリリース）**
- `targets.yml` による接続宣言（秘密情報は環境変数）
- `ingest-live`（汎用 HTTP コネクタは動作。クラウドは要件明文化済みスタブ）
- OTLP/HTTP（JSON）ライブ受信 `POST /v1/traces`

**今後**
- Dify / Azure OpenAI / Bedrock / MCP の各インベントリコネクタ実装
- OTLP protobuf 対応、OpenTelemetry Collector 連携の手順整備
- 任意の能動シナリオ実行（Promptfoo 連携・trajectory 取り込み）モードの追加検討

---

## 9. まとめ（最短手順）

```bash
# 1) 受信サーバを起動（別ターミナル）
python -m agentic_ai_exposure_assessor.cli serve

# 2) 対象の OTLP エクスポート先を本ツールへ
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:8000/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json
#    → 対象を通常運用 or テスト実行すると、トレースが流れ込む

# 3) 構成インベントリを取得（対象プラットフォームから）
export AGENT_REGISTRY_TOKEN=...
python -m agentic_ai_exposure_assessor.cli ingest-live --targets ./targets.yml

# 4) 診断とレポート
python -m agentic_ai_exposure_assessor.cli assess
python -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
```
