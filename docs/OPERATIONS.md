# 運用・設計ガイド

[README](../README.md) の補足です。処理仕様の詳細、運用上の制約、トラブルシューティングをまとめます。

## 目次

- [処理仕様](#処理仕様)
- [全量性を担保する仕組み](#全量性を担保する仕組み)
- [処理時間と高速化の設計](#処理時間と高速化の設計)
- [履歴・ログ](#履歴ログ)
- [送信結果と手動再実行](#送信結果と手動再実行)
- [呼び出し元の制限](#呼び出し元の制限)
- [パラメーター](#パラメーター)
- [Portal でのパラメーター変更（再デプロイ不要）](#portal-でのパラメーター変更再デプロイ不要)
- [メール送信（Office 365 Outlook コネクタ）](#メール送信office-365-outlook-コネクタ)
- [受理後の NDR と配達](#受理後の-ndr-と配達)
- [開発・検証](#開発検証)

## 処理仕様

| 項目 | 動作 |
|---|---|
| 開始時刻 | 毎日 09:00 JST。取得・整形に時間がかかるため、09:00 に届くことの保証ではありません |
| 対象日 | 前日 JST の NVD `published`。更新日や「実行時から遡る 24 時間」ではありません |
| 条件 | CVSS 4.0 または 3.1 の、**いずれかの評価元**が `CRITICAL` |
| 件数 | CVE ID 単位。両条件に一致しても二重に数えません |
| 内容 | CVE、description（全言語・全文）、両 CVSS の全評価元の baseScore / baseSeverity、Vendor / Product / Version と完全な適用条件。各 CVE の区切り行は `{対象日} #{連番} {CVE ID} ----…` |
| 未提供 | `Not provided by NVD` 等を明示。製品・バージョン・スコアを推測しません |
| メール | Office 365 Outlook「Send an email (V2)」、1 通、添付なし。**本文は HTML**（`<pre>` 内に本文を格納し、`& < > "` をエスケープ） |
| 0 件 | 全ページ取得・照合を完了した場合だけ、0 件を記した 1 通を送ります |
| 容量超過 | `MAIL_TOO_LARGE` として失敗。省略・分割・添付化はしません。準備済み本文は当該実行履歴に残ります |
| LLM | 使用しません。LLM のトークン超過は対象外です（実際の処理・サイズ上限の失敗は記録します） |

対象期間の例: 2026-10-21 の実行の対象は 10/20 JST です。UTC 範囲は
`2026-10-19T15:00:00.000Z` から `2026-10-20T14:59:59.999Z` で、最後の 999 ミリ秒も落としません。

## 全量性を担保する仕組み

- サーバー側の `cvssV3Severity` / `cvssV4Severity` は使わず、公開日の全件を取得します。
  実測では、CRITICAL の Secondary 評価を持つ CVE がサーバー側フィルターでは返りませんでした。
- ページサイズ（既定 200）は総件数の上限ではありません。返却配列の実長でオフセットを進めます。
- `totalResults`、取得数、ユニーク ID、ページ位置、公開日範囲を検証し、不整合は失敗にします。
- ID でソートした全フィールドの CVE 配列が、**連続 2 走査で一致した場合だけ確定**します。
  最大 3 走査で一致しない場合や Until の上限到達時は失敗します。
- GET の前に 7 秒待機し（NVD のレート制限対策）、一時的な取得失敗は再試行します。部分応答を成功扱いしません。
- CVSS 4.0 / 3.1 の全評価を調べます。Primary のみ、配列の先頭のみには限定しません。
  CVSS 3.0 だけ、HIGH だけ、対象評価が未掲載の CVE は対象外です。
- CPE のエスケープされたコロン、バックスラッシュ、元のパーセント表現を保護して解析します。
  AND / OR / negate、環境条件、バージョンの包含・除外境界を含む完全な適用条件 JSON と `cve.affected` も保持します。
- NVD は時点固定の API ではありません。対象は取得時点の評価で、後日の評価追加や公開日訂正は自動では遡及しません。

## 処理時間と高速化の設計

2026-10-20（公開 516 件・対象 37 件）の実測は、最適化前が約 10 分、最適化後が約 **278 秒**でした。
Logic Apps は 1 アクションごとに数百ミリ秒の内部オーバーヘッドがかかるため、**件数ごとのループを減らす**ことで短縮しています。

| 工程 | 最適化前 | 最適化後 |
|---|---|---|
| NVD 取得 | 約 250 秒 | 約 200 秒 |
| CRITICAL の絞り込み | 約 216 秒 | 約 18 秒 |
| TEXT 整形 | 約 141 秒 | 約 53 秒 |

- 絞り込みは、`Candidate_Critical_CVEs`（Filter）で「評価のどこかに `CRITICAL` を含む CVE」だけを候補にし、
  候補にだけ厳密な判定（version が 4.0 / 3.1 かつ baseSeverity が CRITICAL）をかけます。
  候補は必要な CVE を必ず含む上位集合のため、結果は変わりません。
- 整形は、description・CVSS・CPE の 1 件ごとのループを Select + join の一括生成に置き換えています。
- 変更前後で、**7 日分 393 件の本文がバイト単位で一致**することをテスト（`tests/replay_baseline.json`）で固定しています。
- 公開数が多い日（例: 2,202 件の日）は、これより長くかかります。

## 履歴・ログ

**実行履歴は台帳・アウトボックスの代替ではありません。** 次は保証しません。

- 停止中・失敗日の自動補完（scheduler は実行時の前日だけを処理します）
- 実行をまたぐ厳密な重複送信防止（同じ日を再実行すると再送される可能性があります）
- 無期限の原本保管（実行履歴・ログには保持期間・サイズ・プラットフォーム上限があります）

worker の実行履歴で、対象日の `ReportDate` と次のアクションを確認します。

| アクション | 記録 |
|---|---|
| `Record_Complete_Source` | 確定した全公開 CVE、取得時刻、検索範囲、走査数と一致方法 |
| `Record_TEXT_Report` | 完全な TEXT 本文。ここに到達していなければ本文作成は未完了です |
| `Record_Submission_Attempt` | メール送信試行番号、対象日、要求バイト数、実行 ID |
| `Record_Audit_Event` | 状態、件数、要求バイト数、メール送信結果、失敗理由、`MailSendingEnabled`、`NvdKeyConfigured`、実行 ID |

`Record_Audit_Event` の非秘密メタデータは tracked properties にも記録されます。
`logAnalyticsWorkspaceId` を指定すると、各ワークフローの `WorkflowRuntime` ログを既存の Log Analytics に転送します
（Log Analytics の取り込み・保持料金は別途発生します）。**完全な CVE 原本やメール本文の参照先は実行履歴**です。
NVD リクエストと失敗情報は secure inputs / outputs で保護され、NVD キーはログに出力されません。

## 送信結果と手動再実行

| 状態 | 意味 |
|---|---|
| `mail_accepted` | コネクタが送信を受け付けた状態（HTTP 200 / 202）。**宛先への到達保証ではありません** |
| `ready` / `MAIL_SENDING_DISABLED` | 取得・整形済みだが送信していない（preview）。実行は失敗表示になります |
| `blocked` | サイズ超過や明示的な送信拒否。理由を解消するまで再実行しません |
| `delivery_uncertain` | 送信の受付が不明。**自動再送しません** |
| `retry_wait` | 明示的な 429 拒否。`Retry-After` に従い同じ実行内で最大 4 回試行（ヘッダーがなければ 900 秒待機） |
| `configuration_required` / `preparation_failed` | キー未設定、または取得・照合・整形の失敗。完全な日次メールを送れた状態とは扱いません |

**手動再実行の手順**

1. 同じ日付の worker 実行履歴、送信元の Sent Items、必要なら Exchange の message trace を確認します。結果が不明なまま再実行しないでください。
2. 同じ日の別実行が動いていないことを確認します。
3. Portal で `<prefix>-worker` を開き、「トリガーの実行（Run with payload）」で `{"ReportDate":"2026-10-20"}` のように指定します。

`FirstReportDate` は手動実行を含む最古の許可日で、補完カーソルではありません。
未来日と当日 JST は許可されません（実行時の前日まで）。
HTTP のタイムアウト後もワークフローは継続している可能性があるため、**応答がないことを未送信の根拠にしてはいけません**。

## 呼び出し元の制限

worker と formatter の Request トリガーには
`accessControl.triggers.allowedCallerIpAddresses = 0.0.0.0-0.0.0.0`（Portal の「他の Logic Apps のみ」）を設定しています。
署名付き URL が漏えいしても、Logic Apps 以外（curl / Postman / アプリ）からの呼び出しは HTTP 401 で拒否されます。
scheduler → worker → formatter の組み込み Workflow アクションは通ります。

- Logic Apps からの呼び出しまで防ぐものではありません（署名付き URL は引き続き必要）。
  URL の取得には `listCallbackUrl` 権限（Contributor / Logic App Contributor 相当）が必要です。
- 手動実行やキー確認は、Portal の「トリガーの実行」を使います（curl / REST の直接 POST は拒否されます）。
- 再デプロイすると、この設定もテンプレートで再適用されます。
- 署名（SAS）の無効化と Entra OAuth 専用化は、組み込み Workflow アクションからの呼び出しへの影響を未検証のため採用していません。

## パラメーター

| パラメーター | 用途 |
|---|---|
| `nvdApiKey` | worker の SecureString `NvdApiKey` に設定。Key Vault は使用しません |
| `senderMailbox` / `recipientEmail` | 送信元（`From (Send as)`。承認するアカウントのアドレス）、宛先 1 アドレス |
| `createOffice365Connection` | Office 365 Outlook の API 接続を作成するか。**初回は `true`、承認後の再デプロイでは `false`**（再デプロイで承認が失われる場合があるため） |
| `firstReportDate` | 最古の許可公開日（`yyyy-MM-dd`）。自動補完の開始日ではありません |
| `firstScheduleLocalTime` | スケジュールの開始日時（JST、Z / オフセットなし）。既定は翌日の **08:00**。毎日の実行は 09:00。開始時刻をちょうど 09:00 にすると、その日の 09:00 が実行されず翌日が初回になるため、09:00 より前を指定します |
| `scheduleState` / `mailSendingEnabled` | 既定は `Disabled` / `false`（安全側）。 |
| `maxMailRequestBytes` | メール要求（UTF-8 換算）の設計上限。既定 3,000,000 バイト（コネクタの上限は 1 通 49 MB） |
| `nvdPageSize` | NVD のページサイズ。既定 200 |
| `logAnalyticsWorkspaceId` | 既存ワークスペースの完全な Azure リソース ID。空なら診断設定を作成しません |

- Microsoft.Logic、Microsoft.Web、Microsoft.Insights が利用可能であることを確認します。
- NVD キーは安全な入力経路で設定し、コマンド履歴・パラメーターファイル・Git に残しません。
  空値、仮値、空白・改行を含むキーは、NVD 呼び出し前に拒否されます。
- コネクタの認証方式 `NoAuth` は輸送接続の設定です。NVD へは SecureString の `apiKey` ヘッダーで認証します。
- 再デプロイは incremental です。テンプレートから除いた旧リソースは自動削除されません。

[infra/main.bicep](../infra/main.bicep) は、リソースグループ作成を含めて subscription スコープでデプロイするための薄いラッパーです。
誤送信を防ぐため、schedule は `Disabled`、メール送信は `false` に固定しています。

## Portal でのパラメーター変更（再デプロイ不要）

次の非秘密パラメーターは、ワークフロー定義の**既定値（Default value）**として保持されます。
ロジックアプリデザイナーの「パラメーター」画面で値を変更して保存します。ARM の再デプロイは不要です。

| ワークフロー | パラメーター |
|---|---|
| `<prefix>-worker` | `MailSendingEnabled`, `SenderMailbox`, `RecipientEmail`, `FirstReportDate`, `MaxMailRequestBytes`, `NvdPageSize` |
| `<prefix>-scheduler` | `FirstReportDate`（worker と同じ値にそろえる） |

- 変更は worker の次回実行から有効です。実行中の処理には影響しません。
- **`NvdApiKey`（SecureString）はデザイナーで編集せず、変更が必要なときは再デプロイしてください。**
- 再デプロイすると、これらの既定値はデプロイ時の入力値で上書きされます。現在値を入力してください。

**デザイナーで保存したら、キーが保持されているかを確認してください。**

1. 受理前の日付（例: `{"ReportDate":"2026-10-19"}`。`FirstReportDate` より前の日付）で worker を 1 回だけ実行します（Run with payload）。NVD 取得もメール送信も行わず、即時に失敗します。
2. 実行履歴の `Record_Audit_Event` で、`NvdKeyConfigured` が `true`、`MailSendingEnabled` が意図した値であることを確認します。
3. `NvdKeyConfigured` が `false` の場合は、キーが失われています。再デプロイでキーを再入力してください。

## メール送信（Office 365 Outlook コネクタ）

- **本文は HTML です。** このアクションにはプレーンテキストの指定がありません。
  本文を `<pre>` 内に格納し `& < > "` をエスケープして、等幅のレイアウトと内容を保ちます。
  CVE の本文に含まれる `<script>` 等も、そのまま表示される文字列として扱われます。
- **認証はユーザー（委任）です。** このコネクタはサービスプリンシパルとマネージド ID に対応していません。
  承認したアカウントの委任権限で送信されます。**承認用の専用アカウントを使い、アクセスできる人を限定してください。**
- **接続が切れると送信できません。** パスワード変更、MFA、条件付きアクセスの変更などで無効になることがあります。
  日次送信の前に、API 接続の状態を定期的に確認してください。
- `From (Send as)` には `senderMailbox` を指定します。承認アカウント以外の場合は「Send as」権限が必要です。
- コネクタの自動再試行は無効です。結果が不明な場合（タイムアウト、5xx）は再送しません。

### 初回の承認手順

1. `createOffice365Connection=true` でデプロイします。
2. Portal で `<prefix>-office365-connection`（API 接続）を開きます。
3. 「API 接続の編集」→「承認」で、送信元アカウントでサインインして保存します。状態が「接続済み」になることを確認します。
4. 以後の再デプロイでは `createOffice365Connection=false` にして、承認を保持します。
5. 承認後、`MailSendingEnabled=false` のままメールなしの preview 実行を行い、その後に 1 通の実送信テストを行います。

稼働前に、preview、本文とログの確認、**実受信の確認**を終えてから、scheduler とメール送信を有効にしてください。
コネクタの成功（200 / 202）、Logic Apps の成功、宛先への到達は、それぞれ別に確認する必要があります。

## 受理後の NDR と配達

コネクタが受け付けた後に、Exchange Online 側で配送が拒否されることがあります。
例: `550 5.7.708 Service unavailable. Access denied, traffic not accepted from this IP`。
これは送信元テナントの送信 IP レピュテーションによるブロックで、ワークフローや本文の不具合ではありません。
新しいテナントやトライアルで起きやすく、解除には Microsoft サポートへの IP 除外の依頼が必要です
（[公式手順](https://learn.microsoft.com/troubleshoot/exchange/email-delivery/ndr/fix-error-codes-550-5-7-703-550-5-7-705-550-5-7-708-550-5-7-750)）。

このワークフローは、送信後の NDR を検知しません。**初回は必ず実受信を確認してから日次を有効化**してください。
外部ドメインへ送る場合は、特に注意してください。

## 開発・検証

[tools/build_template.py](../tools/build_template.py) が ARM テンプレート（`azuredeploy.json`）、`workflows/*.json`、`infra/` 用の入力を生成します。
**生成済みの ARM をデプロイするだけなら Python は不要**で、Azure 上でも実行しません。

```powershell
python .\tools\build_template.py          # azuredeploy.json / workflows/*.json を再生成
python -m unittest tests.test_native -v   # ネイティブテスト
```

- ローカル評価器（`tests/wdl_local.py`）は Azure ランタイムそのものではありません。
  Bicep のビルド、Azure の provider validation、what-if、デプロイ後の実リソース検証も別途行ってください。
- 7 日分の NVD データ（日別 157 / 96 / 46 / 40 / 6 / 11 / 37 件、計 393 件）で全文を再生検証するテストは、
  アーカイブデータがない環境ではスキップされます。
- ARM-TTK は [Test-Template.ps1](../Test-Template.ps1) に公式モジュールのパスを渡して実行します。
  埋め込み OpenAPI の `operationId` を ARM リソース ID と誤認する `IDs Should Be Derived From ResourceIDs` と、
  有効な空配列・任意設定を誤認する `Template Should Not Contain Blanks` は除外しています。
  対応する構造・既定値は、独立したネイティブテストで検証しています。

### 実装上の注意

- Parse JSON は `pattern` / `patternProperties` を含むスキーマをサポートしません（`ActionSchemaNotSupported`）。
  そのため、CVE ID・日付・メールアドレス・Retry-After の検証は標準アクションで行い、ローカル評価器も該当キーワードを拒否します。
- Azure はワークフロー定義だけの PATCH を `PatchWorkflowPropertiesNotSupported` で拒否します。
  worker は SecureString を含むため、定義の更新は実キーを再入力する再デプロイで行います。
- 長時間の親子処理には、通常の HTTP 呼び出しではなく組み込み Workflow アクションを使います。
  子呼び出しの自動再試行も無効にし、親からの再呼び出しによる二重送信を避けます。
  同期 Response を返す子の Request トリガーには、Azure の制約で同時実行制御を設定できないため、
  手動の worker 実行を日次処理や同じ日の別実行と並行させないでください。
- worker を REST の同期呼び出しで実行すると、約 4〜10 分の処理が応答待ちの上限を超え、
  `Return_Day_State` が `ActionResponseTimedOut` になって実行が Failed 表示になることがあります
  （取得・整形・送信自体は完了している場合があります）。**再 POST で再実行しないでください。**
