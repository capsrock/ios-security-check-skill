# 信頼と本人確認（B18〜B23）

ここにある観点は、アプリが誰を信頼し、何をどう証明するかについてのものです。サーバー、共有しているクラウドのデータ、アプリ自身が本物であること、暗号、サインインする人、Mac の保護を扱います。スキャンが「そのアプリはこの機能を使っている」と示したときだけ確認します。

OWASP のテストのページは、`https://mas.owasp.org/MASTG/tests/ios/MASVS-<分類>/MASTG-TEST-<番号>/` の形をしています。

## 目次

- [B18. サーバー証明書の独自の検証](#b18-サーバー証明書の独自の検証)
- [B19. CloudKit の公開データベース](#b19-cloudkit-の公開データベース)
- [B20. 正規のアプリかを確かめる仕組み](#b20-正規のアプリかを確かめる仕組み)
- [B21. 暗号の処理](#b21-暗号の処理)
- [B22. ログイン・生体認証・課金](#b22-ログイン生体認証課金)
- [B23. Mac 向けのアプリ](#b23-mac-向けのアプリ)

## B18. サーバー証明書の独自の検証

既定では、システムがサーバーの証明書を確かめます。認証の要求を受けるデリゲートのメソッドを実装したアプリは、その確認を、自分のものに置き換えられます。

それがどこまで及ぶかについて、資料の説明は一致していません。Apple の文書は、App Transport Security で守られたドメインでは、アプリがこの方法で要件を緩めることはできず、厳しくすることだけができる、としています。OWASP のテストは、どんな証明書も受け入れるコードを、その確認を迂回するものとして説明しています。このスキルは、どちらの説明に立っても、そのようなコードを報告します。App Transport Security が適用されない場所（A1）では明らかに誤りですし、それ以外の場所でも、そう書く正当な理由がありません。

- **見るところ**: すべての `urlSession(_:didReceive:completionHandler:)`、そのタスク単位の版、ウェブ表示のナビゲーションのデリゲートにある同等のメソッド。セッションの最低の TLS の版を設定している場所は、別に見ます。
- **問題になる場合**: デリゲートが、サーバーの信頼の情報を評価せずに受け入れている。または、ホスト名の確認を飛ばしている。セッションの設定で最低の TLS の版を下げている場合も問題です。これは設定の側の指定で、デリゲートがすることではありません。
- **問題にならない場合**: メソッドが、既定の処理に任せている。または、証明書の固定のように、システムより「多く」を拒むだけ。開発用のプロキシのための例外は、`#if DEBUG` の中にあるときだけ認められます。
- **重要度**: App Transport Security が適用される場所では、小さいです。Apple が、そこでは要件を緩められないとしているためです。適用されない場所では、大きくなります。低い層の通信や、例外を指定したドメインです（A1）。指摘の順位は、これに合わせて決めます。
- **直す方向**: 理由が無いかぎり、独自の処理を消します。Apple の案内は、ほとんどの場合、サーバーの信頼の評価を既定の処理に任せることです。
- **出どころ**: [Performing manual server trust authentication](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication) · [Preventing Insecure Network Connections](https://developer.apple.com/documentation/security/preventing-insecure-network-connections) · MASTG-TEST-0343, 0396, 0397（NETWORK）

## B19. CloudKit の公開データベース

公開データベースのレコードの型は、スキーマが権限を与えてはじめて使えます。Apple の文書が公開用の型に示している権限は、全員に読み取り、**サインイン済みのすべての iCloud 利用者に作成**、そのレコードを作った人に書き込み、です。この権限のまま反映されたスキーマでは、サインイン済みの利用者なら誰でも、その型のレコードを足せます。

利用者が作るコンテンツには、これで合っています。アプリが「開発者から来たもの」として扱うものには、合いません。

- **見るところ**: 公開データベースから読んでいる、すべてのレコードの型。アプリが、使うレコードをどう選んでいるか。項目の値を何に使っているか。
- **問題になる場合**:
  - アプリ全体の設定（最低の版、機能の切り替え、お知らせ、リンク）を運ぶ型を、サインイン済みの利用者なら誰でも作れる。
  - アプリが、その型の決まった1件ではなく、「最初の1件」を取り出している。
  - 項目の値を、確かめずに使っている。たとえば、届いた URL をそのまま開いている。
- **リポジトリからは確かめられません。** 権限は、CloudKit Console のスキーマの一部です。Apple の文書によれば、3つのロールは、そこで Creator、World、Authenticated として表示されます。大事なのは本番環境です。`xcrun cktool export-schema` はスキーマを出力します。保存したトークンなしで実行すると、止まって、管理用のトークンを求めます。見られないときは、この観点を、型の名前を添えて「持ち主が確かめること」として報告します。
- **直す方向**: 設定の型では、全員への読み取りは残し、サインイン済みの利用者からは作成を外します。最初に一致した1件ではなく、決まったレコードを取り出します。項目の値はすべて検証し、URL を開く前に、スキームとホストを、許可した一覧と照らします。
- **確かめていないこと**: アプリの外にいる人が、そのコンテナにどれだけ簡単に書き込めるかは、このスキルでは確かめていません。直す手間は小さいので、その答えを待つ必要はありません。
- **出どころ**: [Integrating a Text-Based Schema into Your Workflow](https://developer.apple.com/documentation/cloudkit/integrating-a-text-based-schema-into-your-workflow)（ロールと権限）。OWASP の iOS 向けテストは、CloudKit を扱っていません。この観点は、Apple の文書だけにもとづいています。

## B20. 正規のアプリかを確かめる仕組み

App Attest は、サーバーが、本物のアプリと偽物を見分けられるようにする仕組みです。そうなるのは、サーバーが確かめるときだけです。Apple の文書は、結果の検証をアプリ自身の処理に任せることはできない、と明記しています。結果をサーバーに送るのは、そのためです。

- **見るところ**: 証明や App Check のトークンを作っている場所と、それで守るはずの宛先が、トークンを必須にしているか。
- **問題になる場合**: アプリはトークンを送っているのに、サーバーがトークンなしの要求も受け入れている。必須にする設定が、それを必要とする宛先で切ってある。または、アプリがデバッグ用の提供元を持つ補助ライブラリを使っていて、その提供元が配布版でも有効になりうる。最後の点は、そのようなライブラリについてのもので、それぞれの文書では確かめていません。
- **問題にならない場合**: 必須にする設定が有効で、対応していない端末は、意図して決めた代わりの扱いにしている。すべての端末が、この仕組みを使えるわけではありません。
- **直す方向**: サーバーで、必須にします。トークンを送らない古い版のアプリは拒まれるようになるので、先に使えなくします（A6）。サーバーは、一度きりのチャレンジを発行します。捕まえた応答を、使い回されないようにするためです。
- **出どころ**: [Establishing your app's integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) · [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)

## B21. 暗号の処理

- **見るところ**: 使っているそれぞれの方式と、それが何を守っているか。鍵がどこから来るか。セキュリティのための乱数を、どう作っているか。
- **問題になる場合**:
  - MD5 か SHA-1 が、改ざんの検知、本物であることの確認、パスワードのどれかを守っている。CryptoKit は、この理由で、どちらも `Insecure` の下に置いています。
  - DES、3DES、RC4、ECB モードのどれかを使っている。
  - 鍵を、ソースコードに書いている。または、リソースに入れて配っている。
  - `rand()`、`random()`、`*rand48` の関数で、トークン、鍵、一度きりの値を作っている。
- **問題にならない場合**: 古いハッシュを、セキュリティ上の意味が無いことに使っている。キャッシュのキーや、アプリ自身のファイルの重複の検出などです。
- **直す方向**: ハッシュには SHA-2 を使います。暗号化には、改ざんの検知も備えた方式を使います。鍵は端末の上で作り、キーチェーンに持ちます。セキュリティに関わる乱数には `SecRandomCopyBytes` を使います。
- **出どころ**: [CryptoKit Insecure](https://developer.apple.com/documentation/cryptokit/insecure) · MASTG-TEST-0209, 0210, 0211, 0213, 0214, 0311, 0317（CRYPTO）

## B22. ログイン・生体認証・課金

このスキルを作るのに使ったアプリの中に、アカウント、生体認証によるロック、課金を持つものはありませんでした。下の点は資料から引いたもので、実際のコードで試していません。報告する前に、それぞれを、リンク先の資料で確かめます。

- **キーチェーンの項目**: 項目ごとに選んでいる、読み取りの条件を確かめます。ロック中や別の端末で読む必要のない項目は、そう指定します。
- **キーチェーンの同期**: 同期の指定（`kSecAttrSynchronizable`）を付けた項目は、iCloud を通じて、本人のほかの端末に同期されます。Apple の文書は、同期させる前に、すべての端末で同じ値を使うことが理にかなっているかを確かめるよう書いています。その端末だけのためのトークンや、端末の登録に使う鍵のように、端末に結びつけるべき値に、この指定を付けていないかを見ます。この指定は、「この端末だけ」の読み取りの条件とは併用できません。
- **キーチェーンの共有**: アクセスグループに入れた項目は、同じ開発チームの、そのグループに属するすべてのアプリと拡張が読めます。OWASP の解説は、それらが項目を更新したり消したりもできるとして、共有する項目を最小限にするよう書いています。Apple の文書によれば、App Group の名前も、アクセスグループの名前として使えます。共有する必要のない項目を、共有のグループに入れていないかを見ます。
- **生体認証**（MASTG-TEST-0266, 0268, 0270）: `LAContext` だけで行う確認は、単純な可否を返すだけで、改造されたアプリなら飛ばせます。秘密の値は、アクセスの制御を付けたキーチェーンの項目に結びつけます。そうすれば、システムは認証のあとでしか、それを渡しません。今登録されている生体情報に限る指定が無いと、パスコードを知っている人が、自分の顔や指を登録して通れます。
- **サインインの戻り先**: カスタム URL スキームで届ける OAuth の戻り先は、同じスキームを登録した別のアプリに横取りされえます。システムのウェブ認証のセッションか、ユニバーサルリンクを使います。Apple の文書によれば、このセッションは、始めたアプリにだけ戻り先を届けます。
- **課金**: 検証済みの取引でだけ、機能を解放します。StoreKit は、取引を検証の結果で包んでいます。検証されていない中身を読むコードは、その確認を無意味にします。Apple は、サーバーで検証するのがいちばん確実だ、としています。
- **権限の判断**: あるアカウントに何ができるかは、サーバーで決めます。アプリの中にしかない確認は、確認になっていません。
- **出どころ**: [Keychain services](https://developer.apple.com/documentation/security/keychain-services)。認証情報の置き場としての根拠です · [kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable) · [Sharing access to keychain items among a collection of apps](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) · [MASTG-KNOW-0126](https://mas.owasp.org/MASTG/knowledge/ios/MASVS-PLATFORM/MASTG-KNOW-0126/)。キーチェーンのアクセスグループの解説です · [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) · [ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession) · [VerificationResult](https://developer.apple.com/documentation/storekit/verificationresult) · MASTG-TEST-0266, 0268, 0270（AUTH） · [mobsfscan の Swift 用ルール](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep/swift)（認証のルール） · OWASP Mobile Top 10 2024 の M3 Insecure Authentication/Authorization

## B23. Mac 向けのアプリ

Mac では、アプリの手が届く範囲を App Sandbox が制限し、実行中の完全性を Hardened Runtime が守ります。どちらも設定で、どちらも例外を1つずつ足して緩められます。

- **見るところ**: スキャンが、サンドボックスの権限と Hardened Runtime の設定を見つけたか。そのうえで、有効になっているサンドボックスの権限と、実行時の例外のすべて。
- **問題になる場合**: 理由が書かれないまま、サンドボックスが切ってある。Hardened Runtime が切ってある。または、アプリのどこも必要としていない、ファイル・ネットワーク・デバイス・実行時の例外が有効になっている。Apple は、Mac App Store には App Sandbox を、公証には Hardened Runtime を求めています。どちらが必須になるかは、アプリの配り方で決まります。
- **問題にならない場合**: アプリを Mac App Store の外で配っていて、サンドボックスでは許せないアクセスが必要で、それが記録された決定になっている。
- **直す方向**: 両方を有効にします。動く範囲で、いちばん狭い権限を与えます。まとめて許すより、本人がファイルの選択画面で選んだものへのアクセスを優先します。
- **出どころ**: [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox) · [Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)
