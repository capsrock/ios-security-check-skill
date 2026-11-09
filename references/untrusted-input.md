# 外から入ってくるデータ（B1〜B6）

ここにある観点は、入口が違うだけで、どれも同じ問いです。アプリの外から値が届き、アプリがそれにもとづいて動く、という場面を見ます。スキャンが「そのアプリはこの機能を使っている」と示したときだけ確認します。

OWASP のテストのページは、`https://mas.owasp.org/MASTG/tests/ios/MASVS-<分類>/MASTG-TEST-<番号>/` の形をしています。

## 目次

- [B1. 外からアプリを開く入口](#b1-外からアプリを開く入口)
- [B2. アプリ内のウェブ表示](#b2-アプリ内のウェブ表示)
- [B3. ファイルの取り込み](#b3-ファイルの取り込み)
- [B4. 外から来た zip の展開](#b4-外から来た-zip-の展開)
- [B5. 保存したオブジェクトの復元](#b5-保存したオブジェクトの復元)
- [B6. データベース](#b6-データベース)

## B1. 外からアプリを開く入口

カスタム URL スキーム、ユニバーサルリンク、Spotlight や Handoff からの呼び出し、ウィジェットのリンク、リモート通知の中身は、どれも、ほかの誰かが決めた値をアプリに渡します。

App Intents は、この観点から外しています。そのパラメータを決めるのは、Siri やショートカットを通じて端末を使っている本人です。スキャンは、インテントを定義しているファイルの数を知らせます。読むのは、確認なしでデータを変えたり消したりするインテントがあるときだけです。

- **見るところ**: スキャンが挙げた、受け取る処理のすべて。届いた値が使われる場所まで、1つずつ追います。
- **問題になる場合**:
  - その値が、確かめられないまま、ファイルのパスを決める、アプリが読み込む URL を組み立てる、レコードを選ぶ、のどれかに使われている。
  - リンクだけで、変更・削除・送信・購入が起きる。アプリを使っている人の確認がありません。
  - コードが、そのリンクを送れるのはアプリ自身のサイトやウィジェットだけだ、と決めつけている。
- **知っておくこと**: カスタム URL スキームは、どのアプリからでも開けます。ユニバーサルリンクでシステムが確かめるのはドメインだけで、パスとクエリは送る側が書いたままです。呼び出し元のアプリが何かも、当てにはできません。システムがそれを教えるのは、同じ開発チームのアプリのときだけだからです。
- **問題にならない場合**: 値を、決まった範囲のものに変換している。列挙の値や、あとで検索に使う整数の ID などです。それ以外は捨てています。
- **直す方向**: 行き先を、型のついた決まった範囲に変換します。形の崩れた URL は捨てます。何かを消したり壊したりする操作の前には、確認を挟みます。Apple は、カスタムスキームよりユニバーサルリンクを勧めています。テストには、形の崩れた URL も入れます。
- **出どころ**: [Defining a custom URL scheme for your app](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app) · [Allowing apps and websites to link to your content](https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content) · [sourceApplication](https://developer.apple.com/documentation/uikit/uiscene/connectionoptions/sourceapplication)。呼び出し元が分かるのは同じチームのアプリだけ、という制限の根拠です · MASTG-TEST-0370, 0371, 0395（PLATFORM）

## B2. アプリ内のウェブ表示

ウェブ表示は、誰かの HTML と JavaScript を、アプリの中で動かします。問うのは、それが誰のものかと、何に手が届くかです。

- **見るところ**: 何を読み込んでいるか（同梱のファイルか、開発者自身のサイトか、何でもか）。URL や HTML のどこかが外から来ていないか。スクリプトからのメッセージを受ける処理。許しているファイルへのアクセス。リンクを押したときに行ける先。
- **問題になる場合**:
  - URL や HTML の文字列を、外から来た値で組み立てている。
  - `loadFileURL(_:allowingReadAccessTo:)` で、内容に必要な範囲より広いフォルダーを許している。
  - `allowFileAccessFromFileURLs` か `allowUniversalAccessFromFileURLs` を有効にしている。Apple はこの2つを文書にしていません。キー値コーディングで設定するもので、ここでの意味は OWASP のテストによります。
  - スクリプトからのメッセージを受ける処理が、ネイティブの機能やデータを見せていて、しかもその表示が、アプリの管理していない内容を読み込める。
  - 信頼できないページから `evaluateJavaScript` で値を読み取り、それを信用している。
  - 同梱の内容を出すための表示なのに、リンクを押すと任意のサイトへ移動できる。
  - ナビゲーションのデリゲートが、サーバーの証明書を評価せずに受け入れている。
  - `UIWebView` をまだ使っている。
- **問題にならない場合**: 同梱の静的なページを出していて、スクリプトとの橋渡しが無く、外へのリンクはブラウザで開いている。
- **直す方向**: 読み込む内容を、固定のもの、同梱のもの、許可した一覧にあるものに限ります。ほかに何も要らないときは、読み取りを許す URL にそのファイル自身を渡します。移動できる先を、想定したホストに絞ります。橋渡しは狭くし、メッセージはすべて検証します。
- **出どころ**: [loadFileURL(_:allowingReadAccessTo:)](https://developer.apple.com/documentation/webkit/wkwebview/loadfileurl%28_:allowingreadaccessto:%29) · [WebPage.NavigationDeciding](https://developer.apple.com/documentation/webkit/webpage/navigationdeciding) と [WKNavigationDelegate](https://developer.apple.com/documentation/webkit/wknavigationdelegate)。表示が移動できる先を絞る方法の根拠です · MASTG-TEST-0331, 0332, 0333, 0335, 0376, 0379（PLATFORM） · MASTG-TEST-0397（NETWORK）。ナビゲーションのデリゲートでの証明書の扱いの根拠です

## B3. ファイルの取り込み

ファイルの選択、ドロップ、共有シート、「このアプリで開く」、iCloud Drive を通じて届くファイルは、ほかの誰かが作ったものです。

- **見るところ**: スキャンが挙げた取り込みの経路。URL が届いた時点から、内容を保存して開くところまでを追います。
- **問題になる場合**:
  - `startAccessingSecurityScopedResource()` が true を返したのに、すべての経路で終了の呼び出しと対になっていない。エラーの経路も含みます。false を返した呼び出しには、終了は要りません。
  - ファイルから取った名前やパスを使って、保存先を組み立てている。細工した名前で、意図したフォルダーの外に書き込めます。
  - 内容を、その中身を実行したり辿ったりするウェブ表示や解析処理に渡している（B2、B4、B5 を参照）。
- **問題にならない場合**: ファイルを、アプリが生成した名前でコピーしている。アクセスを `defer` で解放している。内容は、システムの表示の仕組みに渡すだけ。
- **直す方向**: 保存先の名前は、アプリが生成します。コピーが済んだら、すぐにアクセスを解放します。そのあとのすべての段階で、内容を信頼できないものとして扱います。
- **出どころ**: [startAccessingSecurityScopedResource()](https://developer.apple.com/documentation/foundation/nsurl/startaccessingsecurityscopedresource%28%29) · [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)。ファイルの名前とコピーについての点は、このスキル独自の指針です。出どころの資料が扱っているのは、アクセスの呼び出しと、入力の検証の一般論です。

## B4. 外から来た zip の展開

書庫には、展開先のフォルダーの外へ出ていくパスを持つ項目が、入っていることがあります。

- **見るところ**: それぞれの書庫がどこから来たかと、どう展開しているか。
- **問題になる場合**: アプリのバンドルの外から来た書庫（ダウンロードしたもの、取り込んだもの）を、すべての項目が展開先の中に収まるかを確かめずに展開している。または、外へ出られることが知られている版のライブラリで展開している。
- **問題にならない場合**: 書庫が、アプリのバンドルに同梱されている。その中身は、アプリをビルドしたときに決まっています。
- **直す方向**: `..` を含む項目、絶対パス、外を指すリンクを拒みます。新しく作った一時フォルダーに展開してから、結果を移します。ダウンロードしたものは、ハッシュか署名を確かめます。
- **出どころ**: [mobsfscan の Swift 用ルール](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep/swift)。`ios_ssziparchive_unzip` というルールが、SSZipArchive という1つのライブラリを対象にしていて、2.1.4 より前の版は展開先の外に出られるとしています · [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)。「直す方向」の手順は、このスキル独自の指針です。

## B5. 保存したオブジェクトの復元

キーつきのアーカイブは、オブジェクトを丸ごと組み立て直します。そのデータに外から手を加えられるなら、戻ってくるオブジェクトの種類にも手を加えられます。

- **見るところ**: `NSKeyedUnarchiver` を使っているすべての箇所と、そのデータの出どころ。ファイル、ペーストボード、ネットワーク、拡張などです。
- **問題になる場合**: そのようなデータを、安全な復元の方式と、想定するクラスの明示的な一覧なしで復元している。
- **問題にならない場合**: アプリが、具体的な型を指定して `Codable` を使っている。`Codable` は、コードが名指しした型に復元します。そのためこのスキルは、クラスのすり替えが起きないものとして扱います。これはこのスキル独自の推論で、出どころの資料はどちらも `Codable` を扱っていません。外から来たデータなら、復元した値が妥当な範囲にあるかは確かめます。
- **直す方向**: `NSSecureCoding` を採用し、安全な復元を必須にして、許すクラスを名指しします。または、形式を `Codable` に移します。
- **出どころ**: [NSSecureCoding](https://developer.apple.com/documentation/foundation/nssecurecoding) · MASTG-TEST-0386（CODE）

## B6. データベース

- **見るところ**: SQL の文や、述語の書式文字列を組み立てているすべての箇所。
- **問題になる場合**: 外から来た値を、文字列の埋め込みや連結で SQL に入れている。または `NSPredicate(format:)` で、引数としてではなく、書式文字列の一部として入れている。
- **問題にならない場合**: 文は固定の文字列で、すべての値をパラメータとしてバインドしている。
- **直す方向**: パラメータをバインドします。述語の値は、引数として渡します。
- **出どころ**: [NSPredicate init(format:_:)](https://developer.apple.com/documentation/foundation/nspredicate/init%28format:_:%29)。引数を書式文字列に差し込んで述語を作る、と説明されています · [Semgrep の Swift 用ルール](https://github.com/semgrep/semgrep-rules/tree/develop/swift)（SQLite のインジェクションの検査）と [secure-ios-app-dev](https://github.com/felixgr/secure-ios-app-dev)。どちらも SQLite だけを扱っています · [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)
