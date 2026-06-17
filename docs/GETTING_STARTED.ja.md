# はじめてのセットアップ・実行ガイド（初心者向け・日本語）

[← README（日本語）に戻る](../README.ja.md)

このガイドは、**プログラミングやコマンド操作に慣れていない方**でも、Windows PC 上で
`agentic-ai-exposure-assessor` を最後まで動かせることを目標に、1 ステップずつ丁寧に説明します。

- 想定 OS: **Windows 10 / 11**
- 使うターミナル: **Git Bash**
- 所要時間: 初回はおよそ **20〜40 分**（ダウンロード時間を含む）

> 💡 **このツールは何をするもの？**
> AI エージェント（自律的にツールを使う AI）の構成と「実際の動作ログ」を読み込み、
> セキュリティ上の問題点（OWASP の観点）を一覧化・採点してレポートにするツールです。
> **攻撃はせず、診断・可視化だけ**を行います。

---

## 目次

1. [全体の流れ（地図）](#1-全体の流れ地図)
2. [事前準備: 必要なソフトのインストール](#2-事前準備-必要なソフトのインストール)
3. [Git Bash を開く](#3-git-bash-を開く)
4. [プロジェクトを入手する](#4-プロジェクトを入手する)
5. [仮想環境を作る](#5-仮想環境を作る)
6. [ツール本体をインストールする](#6-ツール本体をインストールする)
7. [実際に動かす（5 つのステップ）](#7-実際に動かす5-つのステップ)
8. [レポートを見る](#8-レポートを見る)
9. [Web 画面（ダッシュボード）で見る](#9-web-画面ダッシュボードで見る)
10. [最初からやり直したいとき](#10-最初からやり直したいとき)
11. [困ったとき（よくあるエラーと対処）](#11-困ったときよくあるエラーと対処)
12. [用語の超ミニ辞典](#12-用語の超ミニ辞典)

---

## 1. 全体の流れ（地図）

最終的に行う作業はこの順番です。まず全体像をつかんでください。

```
[準備] Python と Git をインストール
   ↓
[入手] プロジェクトをダウンロード（git clone）
   ↓
[環境] 仮想環境 .venv を作成
   ↓
[導入] ツール本体をインストール（pip install）
   ↓
[実行] ① fixture 生成 → ② 設定取込 → ③ トレース取込 → ④ 診断 → ⑤ レポート出力
   ↓
[確認] レポートファイル / Web 画面で結果を見る
```

> 一度環境を作ってしまえば、2 回目以降は「[実行]」だけで OK です。

---

## 2. 事前準備: 必要なソフトのインストール

### 2-1. Python 3.12 以上

1. ブラウザで <https://www.python.org/downloads/windows/> を開きます。
2. **「Python 3.12」以上**のインストーラー（Windows installer 64-bit）をダウンロードします。
3. インストーラーを起動したら、**最初の画面の下にある
   「Add python.exe to PATH」に必ずチェック**を入れてください（これが最重要）。
4. 「Install Now」を押して完了まで待ちます。

> ✅ 既に Python が入っているか分からない場合は、後述の確認コマンドで確かめられます。
> このプロジェクトは **3.12 以上**であれば 3.13 などでも動きます。

### 2-2. Git（Git Bash 付き）

1. ブラウザで <https://git-scm.com/download/win> を開きます。
2. ダウンロードした **Git for Windows** のインストーラーを起動します。
3. 設定は基本的に**すべて「Next（既定のまま）」で問題ありません**。最後に「Install」。

これで **「Git Bash」**というターミナルが一緒にインストールされます。

---

## 3. Git Bash を開く

1. Windows の検索バー（画面左下）に **`Git Bash`** と入力します。
2. 出てきた **「Git Bash」**アイコンをクリックして起動します。
3. 黒い（または白い）文字入力画面が出れば成功です。これが「ターミナル」です。

> 💡 **ターミナルの使い方の基本**
> - コマンド（命令文）を入力して **Enter** で実行します。
> - コピペは **右クリック → Paste**、またはマウスの**中ボタンクリック**でも貼り付けられます
>   （`Ctrl + V` は効かないことがあります）。
> - 画面に文字がたくさん流れても、エラーでなければ正常です。落ち着いて次へ進みましょう。

### 3-1. まず確認（Python と Git が使えるか）

Git Bash に次を 1 行ずつ貼り付けて Enter してください。

```bash
python --version
```

```bash
git --version
```

- `Python 3.12.x`（または 3.13.x など）と `git version 2.x...` のように表示されれば OK です。
- `command not found` と出た場合は、インストール時の **PATH 追加**ができていない可能性があります。
  → [11. 困ったとき](#11-困ったときよくあるエラーと対処)を参照してください。

---

## 4. プロジェクトを入手する

ここでは、PC の「ドキュメント」フォルダの中にダウンロードする例で説明します。

```bash
cd ~/Documents
```

> `cd` は「フォルダを移動する」コマンドです。`~` はあなたのユーザーフォルダを表します。

続いて、プロジェクトをダウンロード（クローン）します。

```bash
git clone https://github.com/Mallory3180/agentic-ai-exposure-assessor.git
```

ダウンロードが終わったら、そのフォルダの中に入ります。

```bash
cd agentic-ai-exposure-assessor
```

中身を確認してみましょう。

```bash
ls
```

`README.md` や `pyproject.toml`、`src`、`fixtures` などが表示されれば成功です。

> 📌 **これ以降のコマンドは、すべてこの `agentic-ai-exposure-assessor` フォルダの中で実行**します。
> ターミナルを開き直したときは、もう一度 `cd ~/Documents/agentic-ai-exposure-assessor` で
> 戻ってきてください。

---

## 5. 仮想環境を作る

「仮想環境（venv）」とは、このプロジェクト専用の Python 部屋のようなものです。
PC 全体に影響を与えず、必要なライブラリだけをここに入れられます。

```bash
python -m venv .venv
```

数秒〜十数秒で、`.venv` という隠しフォルダが作られます（画面には何も出ないことがあります）。

次に、この仮想環境を「有効化（activate）」します。

```bash
source .venv/Scripts/activate
```

成功すると、入力行の左側に **`(.venv)`** と表示されます。これが「部屋に入った」合図です。

> ⚠️ **`source ... activate` でエラーが出る／`(.venv)` が出ない場合**
> 慌てなくて大丈夫です。**有効化しなくても**、仮想環境の Python を直接指定すれば動きます。
> 以降のコマンドで `python` の代わりに `./.venv/Scripts/python.exe` と書けば OK です。
> 例: `python -m pytest` → `./.venv/Scripts/python.exe -m pytest`

---

## 6. ツール本体をインストールする

仮想環境の中で、必要なライブラリとこのツールをインストールします。

まずインストーラー（pip）を最新にします。

```bash
python -m pip install --upgrade pip
```

続いて、ツール本体と開発用ツール（テスト等）をインストールします。

```bash
python -m pip install -e ".[dev]"
```

> ⏳ ここは少し時間がかかります（1〜3 分程度）。たくさんの行が流れますが、
> 最後にエラーが出ていなければ成功です。`Successfully installed ...` と表示されることが多いです。

（`(.venv)` が出せなかった人向け・代替）

```bash
./.venv/Scripts/python.exe -m pip install --upgrade pip
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
```

---

## 7. 実際に動かす（5 つのステップ）

ここからが本番です。**上から順番に**、1 つずつ実行してください。
それぞれ「何のためのコマンドか」と「成功時に出る目安」を書いています。

### ステップ① サンプルデータ（fixture）を生成

```bash
python -m agentic_ai_exposure_assessor.cli init-fixtures
```

- **意味**: 動作確認用の「お手本データ」（わざと問題のある AI 設定とログ）を `fixtures` に作ります。
- **成功の目安**: `Wrote 8 fixture file(s) to fixtures` のような表示。

### ステップ② 設定（インベントリ）を取り込む

```bash
python -m agentic_ai_exposure_assessor.cli ingest-config --fixtures ./fixtures
```

- **意味**: エージェント・ツール・権限などの「構成情報」をデータベースに読み込みます。
- **成功の目安**: `Ingested 27 inventory record(s) ...`（Agent: 6 / Tool: 7 ... など）。

### ステップ③ 実行トレース（動作ログ）を取り込む

```bash
python -m agentic_ai_exposure_assessor.cli ingest-otlp --file ./fixtures/otlp_trace_sample.json
```

- **意味**: 「実際に何が実行されたか」のログ（OTLP トレース）を読み込みます。
- **成功の目安**: `RuntimeSpan: 9 / RuntimeToolCall: 5 ...` のような表示。

### ステップ④ 診断（リスク評価）を実行

```bash
python -m agentic_ai_exposure_assessor.cli assess
```

- **意味**: 構成情報とログを突き合わせ、OWASP の観点で問題点（Finding）を検出・採点します。
- **成功の目安**: `Findings: 24  Aggregate risk score: 1110` のように、検出件数とスコアが出ます。
  続けて `ASI02: 5`, `ASI05: 6` のようにカテゴリ別件数が並びます。

### ステップ⑤ レポートを出力

```bash
python -m agentic_ai_exposure_assessor.cli export-report --format markdown --output ./reports/report.md
```

- **意味**: 診断結果を読みやすいレポートファイルにします。
- **成功の目安**: `Report written to reports\report.md`。

HTML 版や JSON 版も出せます（任意）。

```bash
python -m agentic_ai_exposure_assessor.cli export-report --format html --output ./reports/report.html
python -m agentic_ai_exposure_assessor.cli export-report --format json --output ./reports/report.json
```

> ✅ ここまでで「診断 → レポート出力」が一通り完了です。お疲れさまでした！

（`(.venv)` が出せなかった人向け・代替: 各行の `python` を `./.venv/Scripts/python.exe` に置き換えてください）

---

## 8. レポートを見る

出力したレポートは `reports` フォルダの中にあります。

### 方法 A: エクスプローラーで開く（おすすめ）

Git Bash で次を実行すると、`reports` フォルダがエクスプローラーで開きます。

```bash
explorer reports
```

- `report.html` を**ダブルクリック**すると、ブラウザで色付きのレポート（グラフ付き）が見られます。
- `report.md` はメモ帳や VS Code で開けます。
- `report.json` はプログラムで再利用するためのデータ形式です。

### 方法 B: HTML を直接ブラウザで開く

```bash
start reports/report.html
```

> 💡 レポートには「どのエージェントが危険か」「承認なしで実行された危険な操作は何か」
> 「OWASP のどのカテゴリに該当するか」「どう直すべきか（推奨対応）」が章ごとに整理されています。

---

## 9. Web 画面（ダッシュボード）で見る

ブラウザ上のダッシュボードでインタラクティブに確認することもできます。

```bash
python -m agentic_ai_exposure_assessor.cli serve
```

- 実行すると `Starting web UI at http://127.0.0.1:8000` と表示されます。
- **ブラウザ**を開き、アドレス欄に **`http://127.0.0.1:8000`** と入力してアクセスします。
- 画面では、エージェント別リスクスコア、OWASP カテゴリ別件数、高リスクツール、
  承認なしで実行されたツール、未知エージェント／ツール、トレースのグラフなどが見られます。

### サーバーの止め方

- Git Bash の画面に戻り、**`Ctrl + C`**（コントロールキーを押しながら C）を押すと停止します。

> 💡 画面のボタン（Ingest fixtures / Ingest sample trace / Run assessment）を押すと、
> Web からも取り込み・診断を実行できます。

---

## 10. 最初からやり直したいとき

データを全部消してまっさらな状態に戻したい場合:

```bash
python -m agentic_ai_exposure_assessor.cli reset-db
```

これでデータベース（`data/app.db`）の中身がリセットされます。
そのあと [ステップ②](#ステップ-設定インベントリを取り込む) からやり直してください。

> 完全に消したいときは、`data` フォルダと `reports` フォルダの中身を手動で削除しても構いません
> （これらは Git 管理対象外なので消しても安全です）。

---

## 11. 困ったとき（よくあるエラーと対処）

| 症状・メッセージ | 原因 | 対処 |
| --- | --- | --- |
| `python: command not found` | Python が PATH に入っていない | Python を再インストールし、最初の画面で **「Add python.exe to PATH」にチェック**。または `py --version` を試す |
| `git: command not found` | Git が未インストール／PATH 未設定 | [2-2](#2-2-gitgit-bash-付き) を参照して Git for Windows を入れ、Git Bash を開き直す |
| `source .venv/Scripts/activate` でエラー、`(.venv)` が出ない | 環境差異 | 有効化せず、`python` を `./.venv/Scripts/python.exe` に置き換えて実行する |
| `No such file or directory` が出る | 違うフォルダにいる | `pwd` で現在地を確認。`cd ~/Documents/agentic-ai-exposure-assessor` でプロジェクト内へ戻る |
| `ModuleNotFoundError` / `command not found`（cli 実行時） | インストール未完了、または仮想環境の外 | [6. インストール](#6-ツール本体をインストールする)を再実行。`(.venv)` 表示を確認 |
| `ingest-otlp` で `Trace file not found` | ファイルパスの間違い | [ステップ①](#ステップ-サンプルデータfixtureを生成) を先に実行。`ls fixtures` でファイルがあるか確認 |
| 文字化け・`UnicodeEncodeError`（画面表示） | Windows コンソールの文字コード | レポートファイル（md/html）には影響しません。画面表示だけの問題なので無視して構いません |
| `pip install` が途中で失敗する | ネットワーク／一時的な問題 | もう一度同じコマンドを実行。社内プロキシ環境では管理者に確認 |
| ポート 8000 が使用中で `serve` が起動しない | 既に何かが使用中 | `python -m agentic_ai_exposure_assessor.cli serve --port 8001` のように別ポートを指定 |

### 動作確認（自己診断）

うまくいっているか不安なときは、テストを実行すると環境が正しいか確認できます。

```bash
python -m pytest
```

`24 passed`（数字は変わることがあります）と出れば、環境は正常です。

---

## 12. 用語の超ミニ辞典

| 用語 | かんたんな説明 |
| --- | --- |
| ターミナル / Git Bash | コマンド（命令文）を打って PC を操作する黒い画面 |
| コマンド | PC への命令文。1 行打って Enter で実行 |
| リポジトリ | プロジェクトのファイル一式（GitHub 上の保管場所） |
| クローン (clone) | リポジトリを自分の PC にコピーすること |
| 仮想環境 (venv) | このプロジェクト専用の Python 部屋。PC 全体を汚さない |
| インストール (pip) | 必要な部品（ライブラリ）を取り込むこと |
| fixture | 動作確認用のお手本データ |
| エージェント (Agent) | 自律的にツールを使う AI のこと |
| ツール (Tool) | エージェントが使える機能（メール送信、シェル実行など） |
| トレース (trace) | 「実際に何が実行されたか」の動作ログ |
| Finding | 検出された問題点（リスク） |
| OWASP / ASI01〜10 | AI エージェントのセキュリティ上の代表的リスク分類 |
| リスクスコア | 問題の重大さを数値化したもの（高いほど危険） |

---

これで一通りの流れは完了です。詳しい機能やルールの一覧は
[README（日本語版）](../README.ja.md) を参照してください。
