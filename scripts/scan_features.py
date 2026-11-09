#!/usr/bin/env python3
"""Apple のプラットフォーム向けのアプリが使っている、セキュリティに関わる機能を一覧にします。

読み取り専用です。標準ライブラリだけで動きます。鍵らしいものを見つけても、
値は表示しません。表示するのは、ファイル・行・代入先の名前だけです。

見つかった箇所は「ここを見る」という意味で、「ここが問題」という意味ではありません。
ID（A1〜A7、B1〜B23、C1〜C3）が指す観点は、../references/ に書いてあります。

鍵は、テスト用のターゲットを含む、すべてのテキストファイルで探します。機能は、
ソースファイルで探します。テスト用のターゲットと、道具のフォルダー（scripts、tools、
fastlane など）は、--include-tests を付けないかぎり除きます。

使い方:  python3 scan_features.py [プロジェクトのルート] [--include-tests] [--samples N]
"""
import argparse
import os
import plistlib
import re
import shutil
import subprocess
import sys

SKIP_DIRS = {
    ".git", ".build", ".swiftpm", "DerivedData", "Pods", "Carthage", "node_modules",
    "build", "xcuserdata", "worktrees", "vendor", ".venv", "venv", "__pycache__",
}
TEST_DIR = re.compile(r"(Tests|UITests|TestSupport|Fixtures)$")
TOOLING_DIRS = {"scripts", "Scripts", "tools", "Tools", "ci_scripts", "fastlane", "docs", "Docs"}
SOURCE_EXT = {".swift", ".m", ".mm"}
C_FAMILY_EXT = {".m", ".mm", ".c", ".cc", ".cpp"}
# Files whose content is searched for *named* secrets (`token = "..."`). Known key shapes are searched in every text file.
ASSIGN_EXT = SOURCE_EXT | {".h", ".plist", ".xcconfig", ".json", ".yml", ".yaml", ".sh", ".js", ".ts", ".py", ".rb",
                           ".toml", ".ini", ".cfg", ".conf", ".properties", ".gradle", ".kts"}
ASSIGN_NAMES = {"Fastfile", "Appfile", "Matchfile", "Podfile", "Gemfile", "Rakefile", "Makefile", "Dockerfile"}
LOOSE_ASSIGN_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xcconfig"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".heic", ".webp", ".pdf", ".zip", ".gz", ".tar", ".mp3", ".m4a", ".wav",
              ".aiff", ".caf", ".mov", ".mp4", ".ttf", ".otf", ".woff", ".woff2", ".car", ".icns", ".ico", ".sqlite",
              ".db", ".realm", ".metallib", ".nib", ".a", ".o", ".dylib", ".xcuserstate", ".bin", ".dat"}
# Files that are credentials by their name. Listed by name; their content is never read.
SECRET_FILE = re.compile(
    r"(\.p8|\.p12|\.pfx|\.pem|\.key|\.mobileprovision|\.keystore|\.jks)$"
    r"|(^|/)\.env(\.|$)"
    r"|(^|/)id_(rsa|dsa|ecdsa|ed25519)([._-][^/]*)?$"
    r"|(^|/)[._]netrc$|(^|/)\.git-credentials$|(^|/)\.pypirc$")
MAX_BYTES = 1_500_000

# id, title, reference file, needs-judgement, patterns
FEATURES = [
    ("B1", "外からアプリを開く入口（URL・ユニバーサルリンク・Spotlight・通知）", "untrusted-input.md", False, [
        r"\.onOpenURL\b", r"openURLContexts", r"application\([^)]*open\s+url", r"onContinueUserActivity",
        r"continue\s+userActivity", r"didReceive\s+response:\s*UNNotificationResponse", r"handlesExternalEvents"]),
    ("B2", "アプリ内のウェブ表示", "untrusted-input.md", False, [
        r"\bWKWebView\b", r"\bWebView\(", r"\bWebPage\(", r"\bUIWebView\b", r"evaluateJavaScript", r"callJavaScript",
        r"WKUserScript", r"WKScriptMessageHandler", r"loadHTMLString", r"loadFileURL",
        r"allowFileAccessFromFileURLs", r"allowUniversalAccessFromFileURLs", r"javaScriptCanOpenWindowsAutomatically"]),
    ("B3", "ファイルの取り込み", "untrusted-input.md", False, [
        r"\.fileImporter\(", r"UIDocumentPickerViewController", r"startAccessingSecurityScopedResource", r"\.onDrop\(",
        r"\.dropDestination\(", r"\bNSItemProvider\b", r"\bPhotosPicker\(", r"PHPickerViewController",
        r"NSExtensionContext", r"bookmarkData"]),
    ("B4", "外から来た zip の展開", "untrusted-input.md", False, [
        r"import\s+ZIPFoundation", r"import\s+Zip\b", r"SSZipArchive", r"\bunzipItem\(", r"\bArchive\(url:",
        r"\.unzipFile\(", r"import\s+(SWCompression|Gzip)\b"]),
    ("B5", "保存したオブジェクトの復元", "untrusted-input.md", False, [
        r"NSKeyedUnarchiver", r"\bNSUnarchiver\b", r"\bNSCoding\b", r"unarchiveTopLevelObjectWithData",
        r"unarchiveObject\(", r"requiresSecureCoding"]),
    ("B6", "データベース（入力から組み立てるクエリ）", "untrusted-input.md", False, [
        r"\bsqlite3_(exec|prepare)", r"import\s+GRDB\b", r"import\s+SQLite\b", r"\bFMDatabase\b",
        r"NSPredicate\(format:", r"\bexecuteQuery\(", r"\bexecuteUpdate\("]),
    ("B7", "設定の保存（UserDefaults）", "data-exposure.md", False, [
        r"\bUserDefaults\b", r"@AppStorage\b", r"@SceneStorage\b", r"NSUbiquitousKeyValueStore"]),
    ("B8", "ログの出力", "data-exposure.md", False, [
        r"privacy:\s*\.public", r"%\{public\}", r"(?<![\w.])print\(", r"\bNSLog\(", r"\bdebugPrint\(",
        r"(?<![\w.])dump\("]),
    ("B9", "個人情報を含むファイルやデータベース", "data-exposure.md", True, [
        r"\bModelConfiguration\(", r"\bNSPersistentContainer\(", r"\bNSPersistentCloudKitContainer\(",
        r"FileProtectionType", r"completeFileProtection", r"\.completeUnlessOpen\b"]),
    ("B10", "ウィジェットなどとのデータ共有", "data-exposure.md", False, [
        r"UserDefaults\(suiteName:", r"forSecurityApplicationGroupIdentifier", r"kSecAttrAccessGroup"]),
    ("B11", "コピーとペースト", "data-exposure.md", False, [r"\bUIPasteboard\b", r"\bNSPasteboard\b"]),
    ("B12", "認証情報・お金・健康の情報を出す画面", "data-exposure.md", True, [
        r"\bHKHealthStore\b", r"\bPKPayment", r"\bLAContext\b", r"\bSecureField\(", r"isSecureTextEntry",
        r"\.privacySensitive\(", r"sceneCaptureState"]),
    ("B13", "パスワードや確認コードの入力欄", "data-exposure.md", False, [
        r"\bSecureField\(", r"isSecureTextEntry", r"\.oneTimeCode\b", r"\.creditCardNumber\b",
        r"textContentType\(\.(password|newPassword)\)",
        r"\b(TextField|TextEditor)\([^)\n]*(?i:passw|passcode|パスワード|暗証|確認コード|認証コード)"]),
    ("B14", "クラッシュ報告や利用状況の送信", "data-exposure.md", False, [
        r"\bCrashlytics\b", r"Analytics\.(logEvent|setUserProperty|setUserID)", r"\bSentrySDK\b", r"\bBugsnag\b",
        r"\bMixpanel\b", r"\bAmplitude\b", r"\bDatadog\b", r"TelemetryDeck", r"PostHogSDK", r"\.setUserID\(",
        r"setCustomValue\("]),
    ("B15", "通信の応答のキャッシュとクッキー", "data-exposure.md", True, [
        r"forHTTPHeaderField:\s*\"Authorization\"", r"\"Bearer\s", r"\bURLCache\b", r"requestCachePolicy",
        r"\bHTTPCookie(Storage)?\b", r"WKWebsiteDataStore", r"willCacheResponse"]),
    ("B16", "ロック画面に出る通知やウィジェット", "data-exposure.md", False, [
        r"UNMutableNotificationContent", r"UNNotificationServiceExtension", r"\.accessory(Rectangular|Circular|Inline)\b",
        r"\bActivityAttributes\b", r"\bActivityConfiguration\("]),
    ("B17", "端末内の検索や Handoff に出す内容", "data-exposure.md", False, [
        r"\bCSSearchableItem\b", r"\bCSSearchableIndex\b", r"isEligibleFor(Search|Handoff|PublicIndexing|Prediction)",
        r"NSUserActivity\(activityType:", r"\.userActivity\(", r"\bIndexedEntity\b"]),
    ("B18", "サーバー証明書の独自の検証", "trust-and-identity.md", False, [
        r"didReceive\s+challenge", r"URLAuthenticationChallenge", r"\.serverTrust\b", r"URLCredential\(trust:",
        r"SecTrustEvaluate", r"tlsMinimumSupportedProtocol", r"sec_protocol_options_set_(min_tls|verify_block)"]),
    ("B19", "CloudKit の公開データベース", "trust-and-identity.md", False, [
        r"publicCloudDatabase", r"database\(with:\s*\.public\)", r"CKDatabase\.Scope\.public"]),
    ("B20", "正規のアプリかを確かめる仕組み（App Attest・DeviceCheck・App Check）", "trust-and-identity.md", False, [
        r"DCAppAttestService", r"\bDCDevice\b", r"\bAppCheck\b", r"AppAttestProvider", r"DeviceCheckProvider"]),
    ("B21", "暗号の処理と乱数", "trust-and-identity.md", False, [
        r"import\s+CryptoKit", r"import\s+CommonCrypto", r"\bCC_(MD2|MD4|MD5|SHA1)\b", r"Insecure\.(MD5|SHA1)",
        r"kCCOptionECBMode", r"kCCAlgorithm(DES|3DES|RC4)", r"\bCCCrypt\(", r"SymmetricKey\(",
        r"(?<![\w.])(rand|random|srand|srandom|[dejlmn]rand48)\(", r"SecRandomCopyBytes"]),
    ("B22", "ログイン・生体認証・キーチェーン・課金", "trust-and-identity.md", False, [
        r"\bSecItem(Add|CopyMatching|Update|Delete)\b", r"kSecAttrAccessible", r"\bLAContext\b", r"evaluatePolicy",
        r"\bASAuthorization", r"ASWebAuthenticationSession", r"SecAccessControlCreateWithFlags",
        r"Product\.products\(", r"\.purchase\(", r"Transaction\.(currentEntitlements|updates|latest|all)\b",
        r"SKPaymentQueue", r"\b(SubscriptionStoreView|StoreView|ProductView)\(", r"\"Bearer\s", r"refresh_?[tT]oken"]),
]

PERSONAL_WORD = re.compile(r"(?i)(e-?mail|(?<![A-Za-z])phone|passw|passcode|(?<![A-Za-z])token|secret|birthday|postal)")
APP_INTENT = re.compile(r":\s*[^{\n]*\bAppIntent\b|\bOpenIntent\b|AppShortcutsProvider")
URL_HANDLER = re.compile(r"\.onOpenURL\b|openURLContexts|application\([^)]*open\s+url|handleOpen")
DEV_ENTRY = re.compile(
    r"ProcessInfo\.processInfo\.(arguments|environment)\b|CommandLine\.arguments|"
    r"AppCheckDebugProvider|\b(isUITest|isRunningTests|debugMenu|DebugMenu|MockServer)\b")
UPDATE_HINT = re.compile(r"itunes\.apple\.com/lookup|minimumVersion|[fF]orceUpdate|needsUpdate|AppStore\.sync")
LOW_LEVEL_NET = re.compile(r"\bNWConnection\b|\bnw_connection_create\b|CFStreamCreatePairWithSocket|"
                           r"\bCFSocketCreate|getStreamsToHost|\bStreamTask\b|streamTask\(with")
HTTP_LITERAL = re.compile(r"\"http://(?!localhost|127\.0\.0\.1|www\.apple\.com/DTDs|www\.w3\.org|schemas\.)[^\"\s]+\"")
SECRET_NAME = r"([A-Za-z_]*(?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|client[_-]?secret)[A-Za-z_]*)"
# name = "value": any service, as long as the name says what it is
SECRET_ASSIGN = re.compile(r"(?i)\b" + SECRET_NAME + r"\b[\"']?\]?\s*[:=]\s*[\"']([A-Za-z0-9_.\-+/=]{16,})[\"']")
# name: value without quotes, for configuration files only
SECRET_ASSIGN_LOOSE = re.compile(r"(?i)^\s*" + SECRET_NAME + r"\s*[:=]\s*([A-Za-z0-9_.\-+/=]{20,})\s*$")
# A quoted argument shaped like prefix_random ("xx_AbC123..."): any service. The shape is not confirmed against
# anyone's documentation, so it is reported as a candidate for a person to identify.
CALL_ARG_SECRET = re.compile(r"\(\s*[\"']([A-Za-z]{2,8}[_-])([A-Za-z0-9_\-]{20,})[\"']\s*[,)]")
CALL_ARG_LABEL = "関数の引数に直接書かれた、鍵らしい文字列（形は確かめていない。何の値かを見る）"
REGISTRY_CREDENTIAL = re.compile(r"(?i)(_authToken|_auth|_password)\s*=\s*\S{8,}")
# Shapes confirmed against each service's own documentation, plus the PEM header.
SECRET_SHAPES = [
    ("GitHub のトークン", re.compile(r"\b(gh[pousr]_[0-9A-Za-z_.\-]{30,}|github_pat_[0-9A-Za-z_]{30,})")),
    ("GitLab のトークン", re.compile(r"\bgl(pat|oas|dt|rt|ptt|cbt)-[0-9A-Za-z_\-]{16,}")),
    ("Slack のトークン", re.compile(r"\b(xox[bp]|xapp|xwfp)-[0-9A-Za-z-]{10,}")),
    ("AWS のアクセスキー ID（識別子。そばにシークレットアクセスキーが無いかを見る）",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Stripe の秘密の鍵か、制限つきの鍵", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}")),
    ("秘密鍵のブロック", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
# Google API keys share one shape whatever they are for. A Firebase key is meant to ship in the app; a Gemini key
# is a secret. The shape cannot tell them apart, so it is reported for a person to decide. The prefix is the one
# commonly seen; it was not found stated in Google's documentation.
GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")
GOOGLE_KEY_LABEL = "Google の API キー: どの種類かを確かめる（Firebase の鍵はアプリに入れる前提、Gemini の鍵は秘密。C2 を見る）"
# Keys that are meant to ship inside an app. Reported under C2, not as leaked secrets.
CLIENT_SHAPES = [
    ("Stripe の公開用の鍵", re.compile(r"\bpk_(live|test)_[0-9a-zA-Z]{16,}")),
]
CLIENT_KEY_CALL = re.compile(
    r"GMS(Services|PlacesClient)\.provideAPIKey|Purchases\.configure\(|StripeAPI\.defaultPublishableKey|"
    r"\.publishableKey\s*=|SentrySDK\.start|\.dsn\s*=|Mixpanel\.initialize\(|Bugsnag\.start\(|"
    r"MapboxOptions\.accessToken|SupabaseClient\(|appsFlyerDevKey|Intercom\.setApiKey|OneSignal\.initialize\(|"
    r"withAPIKey:|\bapiKey:\s*\"|\bclientToken:")
CLIENT_PLIST_KEY = re.compile(r"(?i)(api[_-]?key|access[_-]?token|client[_-]?(key|token)|publishable|dsn$|app[_-]?secret)")
# Build settings, as named in Apple's Build Settings Reference
PROTECTION_OFF = [
    (re.compile(r"CLANG_ENABLE_OBJC_ARC = NO"), "CLANG_ENABLE_OBJC_ARC = NO（自動の参照カウントが無効）"),
    (re.compile(r"GCC_DYNAMIC_NO_PIC = YES"), "GCC_DYNAMIC_NO_PIC = YES（位置に依存するコード）"),
    (re.compile(r"LD_NO_PIE = YES"), "LD_NO_PIE = YES（位置に依存する実行ファイル。Apple の文書では Mac 向けの設定）"),
    (re.compile(r"fno-stack-protector"), "-fno-stack-protector（スタックの保護が無効。C 系のコードで意味を持つ）"),
]
# INFOPLIST_KEY_UIFileSharingEnabled is not listed in Apple's Build Settings Reference (the other two are).
# It is searched for anyway: a miss costs nothing.
FILE_SHARING_SETTING = re.compile(
    r"INFOPLIST_KEY_(UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace|UISupportsDocumentBrowser) = YES")
FETCHING_SCRIPT = re.compile(r"\b(curl|wget)\b|git\s+clone|\bnpx\b|pip3?\s+install|brew\s+install|\|\s*(ba|z)?sh\b")
SECRETISH_NAME = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|private[_-]?key)")

SERVER_MARKERS = ["firebase.json", "wrangler.toml", "Dockerfile", "serverless.yml", "vercel.json", "netlify.toml",
                  "supabase", "functions", "server", "backend", "api", "worker", "workers"]
CI_MARKERS = ["ci_scripts", ".github/workflows", "fastlane", ".gitlab-ci.yml", "bitrise.yml", ".circleci"]


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.endswith((".xcassets", ".lproj", ".framework", ".xcframework"))]
        for name in filenames:
            yield os.path.join(dirpath, name)


def in_test_dir(relpath):
    """True for test targets and tooling folders: code there does not ship in the app."""
    return any(TEST_DIR.search(part) or part in TOOLING_DIRS for part in relpath.split(os.sep)[:-1])


def read(path, limit=MAX_BYTES):
    """Text of a file, or None when it is too large, unreadable or binary."""
    try:
        if limit and os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    if b"\0" in raw[:4096]:
        return None
    return raw.decode("utf-8", "replace")


def debug_lines(lines):
    """Line numbers that sit inside the true branch of `#if DEBUG`."""
    inside, stack = set(), []
    for number, line in enumerate(lines, 1):
        text = line.strip()
        if text.startswith("#if"):
            cond = text[3:].strip()
            stack.append("debug" if re.match(r"DEBUG\b", cond) else "release" if re.match(r"!\s*DEBUG\b", cond) else "other")
        elif text.startswith("#elseif") and stack:
            cond = text[7:].strip()
            stack[-1] = "debug" if re.match(r"DEBUG\b", cond) else "other"
        elif text.startswith("#else") and stack:
            stack[-1] = {"debug": "release", "release": "debug"}.get(stack[-1], "other")
        elif text.startswith("#endif") and stack:
            stack.pop()
        elif "debug" in stack:
            inside.add(number)
    return inside


def load_plist(path):
    try:
        with open(path, "rb") as handle:
            data = plistlib.load(handle)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def tracked_files(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, timeout=20)
        if out.returncode != 0:
            return None
        return set(out.stdout.decode("utf-8", "replace").split("\0"))
    except Exception:
        return None


def history_key_files(root, present):
    """Names of key-like files that were committed at some point and are gone now. Names only: content is not read."""
    try:
        out = subprocess.run(["git", "-C", root, "log", "--all", "--diff-filter=A", "--name-only", "--format="],
                             capture_output=True, timeout=30)
        if out.returncode != 0:
            return None
    except Exception:
        return None
    names = set(out.stdout.decode("utf-8", "replace").split("\n"))
    return sorted(n for n in names
                  if n and SECRET_FILE.search(n) and not n.endswith(".pub") and n not in present
                  and not any(part in SKIP_DIRS for part in n.split("/")))


def build_configurations(text):
    """(configuration name, text of its settings) for each XCBuildConfiguration in a project.pbxproj."""
    return [(m.group(2).strip().strip('"'), m.group(1))
            for m in re.finditer(r"isa = XCBuildConfiguration;(.*?)\n\s*name = ([^;]+);\n\s*\};", text, re.S)]


def debug_definitions(settings):
    """Which languages see DEBUG as defined in this configuration: "Swift", "C-family", both or neither.

    Swift's `#if DEBUG` follows Active Compilation Conditions and `-D DEBUG` in Other Swift Flags.
    C, C++ and Objective-C follow Preprocessor Macros and `-DDEBUG` in Other C Flags. `DEBUG=0` is not counted.
    """
    def value(name):
        found = re.search(name + r" = (\(.*?\)|[^;]*);", settings, re.S)
        return found.group(1) if found else ""
    kinds = []
    if re.search(r"\bDEBUG\b", value("SWIFT_ACTIVE_COMPILATION_CONDITIONS")) \
            or re.search(r"-D\W{0,6}DEBUG\b", value("OTHER_SWIFT_FLAGS")):
        kinds.append("Swift")
    if re.search(r"\bDEBUG\b(?!\s*=\s*0\b)", value("GCC_PREPROCESSOR_DEFINITIONS")) \
            or re.search(r"-D\W{0,6}DEBUG\b(?!\s*=\s*0\b)", value("OTHER_CFLAGS")):
        kinds.append("C 系")
    return kinds


def fmt(samples, limit):
    shown = ", ".join(f"{p}:{n}" for p, n in samples[:limit])
    more = len(samples) - limit
    return shown + (f"（ほか {more} ファイル）" if more > 0 else "")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--include-tests", action="store_true",
                        help="テスト用のターゲットと、道具のフォルダーでも機能を探す")
    parser.add_argument("--samples", type=int, default=4, help="観点ごとに表示する場所の数（既定は 4）")
    args = parser.parse_args()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit(f"フォルダーではありません: {root}")
    rel = lambda p: os.path.relpath(p, root)

    compiled = [(i, t, r, j, [re.compile(p) for p in pats]) for i, t, r, j, pats in FEATURES]
    hits = {i: [] for i, *_ in FEATURES}          # first hit per file
    counts = {i: 0 for i, *_ in FEATURES}
    sources = c_family = 0
    url_handler = False
    dev_out, dev_in = [], 0
    update_hint, http_literals, secrets, client_keys, client_calls, low_level_net = [], [], [], [], [], []
    intents, settings_first = [], []
    plists, entitlements, pbxprojs, resolved, secret_files, google_plists = [], [], [], [], [], []
    schemes_shared, xcconfigs = [], []

    for path in walk(root):
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1]
        relpath = rel(path)
        if SECRET_FILE.search(relpath) and not name.endswith(".pub"):
            secret_files.append(relpath)
            continue
        if ext in C_FAMILY_EXT:
            c_family += 1
        if name == "project.pbxproj":
            pbxprojs.append(path)
        elif ext == ".xcscheme" and "xcshareddata" in relpath:
            schemes_shared.append(path)
        elif ext == ".xcconfig":
            xcconfigs.append(path)
        elif name in ("Package.resolved", "Podfile.lock", "Cartfile.resolved"):
            resolved.append(path)
        elif ext == ".entitlements":
            entitlements.append(path)
        elif ext == ".plist":
            (google_plists if name.startswith("GoogleService-Info") else plists).append(path)
        if ext in BINARY_EXT or name in ("Package.resolved", "package-lock.json", "Podfile.lock", "yarn.lock"):
            continue
        text = read(path)
        if text is None:
            continue
        lines = text.split("\n")
        # Secrets: every text file, test targets included. Values are never kept, only where they are.
        named = ext in ASSIGN_EXT or name in ASSIGN_NAMES
        loose = ext in LOOSE_ASSIGN_EXT
        registry = name in (".npmrc", ".yarnrc", ".yarnrc.yml")
        is_google = name.startswith("GoogleService-Info")
        for number, line in enumerate(lines, 1):
            if len(line) > 4000:
                continue
            for label, shape in SECRET_SHAPES:
                if shape.search(line):
                    secrets.append((relpath, number, label))
            for label, shape in CLIENT_SHAPES:
                if shape.search(line):
                    client_keys.append((relpath, number, label))
            if GOOGLE_KEY.search(line) and not is_google:      # inside GoogleService-Info.plist it is expected
                secrets.append((relpath, number, GOOGLE_KEY_LABEL))
            match = (SECRET_ASSIGN.search(line) if named else None) or (SECRET_ASSIGN_LOOSE.search(line) if loose else None)
            if match and re.search(r"[0-9]", match.group(2)) and re.search(r"[A-Za-z]", match.group(2)) \
                    and not GOOGLE_KEY.search(line) \
                    and not any(shape.search(line) for _l, shape in SECRET_SHAPES + CLIENT_SHAPES):
                secrets.append((relpath, number, f"{match.group(1)} = <{len(match.group(2))} 文字>"))
            call = CALL_ARG_SECRET.search(line) if named else None
            if call and not match and re.search(r"[0-9]", call.group(2)) and re.search(r"[a-z]", call.group(2)) \
                    and re.search(r"[A-Z]", call.group(2)) and not GOOGLE_KEY.search(line) \
                    and not any(shape.search(line) for _l, shape in SECRET_SHAPES + CLIENT_SHAPES):
                secrets.append((relpath, number, CALL_ARG_LABEL))
            if registry and REGISTRY_CREDENTIAL.search(line):
                secrets.append((relpath, number, "パッケージの配布元の認証情報"))
        if ext not in SOURCE_EXT or (in_test_dir(relpath) and not args.include_tests):
            continue
        sources += 1
        if PERSONAL_WORD.search(text) and any(p.search(text) for p in compiled[6][4]):   # compiled[6] is B7
            settings_first.append(relpath)
        in_debug = debug_lines(lines)
        seen = set()
        for number, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            for fid, _t, _r, _j, patterns in compiled:
                if any(p.search(line) for p in patterns):
                    counts[fid] += 1
                    if fid not in seen:
                        seen.add(fid)
                        hits[fid].append((relpath, number))
            if URL_HANDLER.search(line):
                url_handler = True
            if APP_INTENT.search(line) and not any(p == relpath for p, _ in intents):
                intents.append((relpath, number))
            if CLIENT_KEY_CALL.search(line) and not any(p == relpath for p, _ in client_calls):
                client_calls.append((relpath, number))
            if DEV_ENTRY.search(line):
                if number in in_debug:
                    dev_in += 1
                else:
                    dev_out.append((relpath, number))
            if UPDATE_HINT.search(line) and not any(p == relpath for p, _ in update_hint):
                update_hint.append((relpath, number))
            if HTTP_LITERAL.search(line):
                http_literals.append((relpath, number))
            if LOW_LEVEL_NET.search(line) and not any(p == relpath for p, _ in low_level_net):
                low_level_net.append((relpath, number))

    tracked = tracked_files(root)
    out = print
    out(f"# 機能のスキャン: {root}")
    out(f"調べたソースファイル: {sources}{'' if args.include_tests else '（テスト用のターゲットと、道具のフォルダーは除く）'}")
    if c_family:
        out(f"C 系のファイル: {c_family}（references/not-checked.md の「メモリの破壊」の項を見る）")
    out("")
    out("## どのアプリでも確認する観点（A1〜A7）: 必ず確認する。references/every-app.md")
    project_texts = [(path, read(path, limit=0) or "") for path in pbxprojs]

    ats, schemes, file_sharing = [], [], []
    for path in plists:
        data = load_plist(path)
        if not data:
            continue
        if isinstance(data.get("NSAppTransportSecurity"), dict):
            ats.append(f"{rel(path)}: {sorted(data['NSAppTransportSecurity'].keys())}")
        for url_type in data.get("CFBundleURLTypes") or []:
            if isinstance(url_type, dict):
                schemes += [s for s in url_type.get("CFBundleURLSchemes") or [] if isinstance(s, str)]
        for key in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"):
            if data.get(key) is True:
                file_sharing.append(f"{rel(path)}: {key}")
    for path, text in project_texts:
        for key in sorted(set(FILE_SHARING_SETTING.findall(text))):
            file_sharing.append(f"{rel(path)}: INFOPLIST_KEY_{key}（ビルド設定）")
    out("A1 通信の保護の設定: " + ("; ".join(ats) if ats else "NSAppTransportSecurity のキーは無し"))
    if http_literals:
        out(f"   コードの中の http:// の文字列: {fmt(http_literals, args.samples)}")
    if low_level_net:
        out(f"   App Transport Security が適用されない、低い層の通信: {fmt(low_level_net, args.samples)}")
    out("A2 アプリに付けた権限:")
    if not entitlements:
        out("   .entitlements のファイルは無し")
    for path in entitlements:
        data = load_plist(path) or {}
        out(f"   {rel(path)}: {', '.join(sorted(data.keys())) or '（空）'}")
    grouped = {}
    for relpath, number, what in secrets:
        grouped.setdefault((relpath, what), []).append(number)
    if tracked is None:
        listed, local_only = secret_files, []
    else:
        listed = [f for f in secret_files if f in tracked]
        local_only = [f for f in secret_files if f not in tracked]
    out("A3 鍵やパスワードの直書き（テストを含む、すべてのテキストファイルを検索）: "
        + ("下に候補（値は表示しない）" if grouped or listed else "候補は無し"))
    for (relpath, what), numbers in list(grouped.items())[:30]:
        out(f"   {relpath}:{numbers[0]}  {what}" + (f"（このファイルに {len(numbers)} 件）" if len(numbers) > 1 else ""))
    if len(grouped) > 30:
        out(f"   ... ほか {len(grouped) - 30} 件")
    for relpath in listed[:30]:
        out(f"   鍵らしいファイル: {relpath}" + ("" if tracked is None else " [git で管理されている]"))
    if local_only:
        out(f"   git で管理されていない、鍵らしいファイル（あるべき状態）: {len(local_only)} 個"
            f"（例: {', '.join(local_only[:2])}）")
    gone = history_key_files(root, set(secret_files)) if tracked is not None else None
    if gone:
        out(f"   git の履歴に名前が残っていて、今は無い鍵らしいファイル: {', '.join(gone[:12])}"
            + (f"（ほか {len(gone) - 12} 個）" if len(gone) > 12 else ""))
    scanners = [tool for tool in ("gitleaks", "trufflehog") if shutil.which(tool)]
    out("   調べていないもの: git の履歴の中身と、このスクリプトが形を知らない鍵。"
        + (f"入っている検査ツール: {', '.join(scanners)}。" if scanners else "専用の検査ツールは入っていない。"))
    out(f"A4 開発用の機能: `#if DEBUG` の外に {len(dev_out)} 件、中に {dev_in} 件")
    if dev_out:
        out(f"   外にあるもの: {fmt(dev_out, args.samples)}")
    schemes = sorted(set(schemes))
    out("A5 URL スキーム: " + (f"登録 {schemes}; 受け取る処理: {'あり' if url_handler else '見つからない'}"
                             if schemes else "登録なし"))
    targets, mac, hardened, sandbox_setting = set(), False, set(), set()
    for path, text in project_texts:
        targets |= set(re.findall(r"((?:IPHONEOS|MACOSX|WATCHOS|TVOS|XROS)_DEPLOYMENT_TARGET) = ([0-9.]+)", text))
        mac = mac or bool(re.search(r"SDKROOT = macosx|MACOSX_DEPLOYMENT_TARGET|SUPPORTS_MACCATALYST = YES", text))
        hardened |= set(re.findall(r"ENABLE_HARDENED_RUNTIME = (YES|NO)", text))
        sandbox_setting |= set(re.findall(r"ENABLE_APP_SANDBOX = (YES|NO)", text))
    out("A6 古い版を使えなくする手段: 最低の OS: "
        + (", ".join(f"{k.split('_')[0].lower()} {v}" for k, v in sorted(targets)) or "見つからない")
        + "; 更新を求める処理: " + (fmt(update_hint, 2) if update_hint else "見つからない"))

    if not project_texts:
        out("A7 Xcode のビルド設定: project.pbxproj は無し（Swift パッケージだけなら、もともと無い）")
    else:
        debug_in_release, testable_release, off, script_phases, fetching = [], [], [], 0, []
        script_sandbox, enhanced = set(), set()
        for path, text in project_texts:
            for config, settings in build_configurations(text):
                if "debug" in config.lower():
                    continue
                kinds = debug_definitions(settings)
                if kinds:
                    debug_in_release.append(f"{config}（{' と '.join(kinds)}）")
                if re.search(r"ENABLE_TESTABILITY = YES", settings):
                    testable_release.append(config)
            for pattern, label in PROTECTION_OFF:
                if pattern.search(text):
                    off.append(label)
            for phase in re.finditer(r"isa = PBXShellScriptBuildPhase;(.*?)\n\t\t\};", text, re.S):
                script_phases += 1
                body = phase.group(1)
                if FETCHING_SCRIPT.search(body):
                    title = re.search(r'name = "?([^";]+)"?;', body)
                    fetching.append(title.group(1) if title else "（名前なし）")
            script_sandbox |= set(re.findall(r"ENABLE_USER_SCRIPT_SANDBOXING = (YES|NO)", text))
            enhanced |= set(re.findall(r"ENABLE_ENHANCED_SECURITY = (YES|NO)", text))
        out("A7 Xcode のビルド設定:")
        out("   Debug 以外の構成で、DEBUG を定義しているもの: " + (", ".join(sorted(set(debug_in_release))) or "無し"))
        out("   Debug 以外の構成で、ENABLE_TESTABILITY が有効なもの: " + (", ".join(sorted(set(testable_release))) or "無し"))
        out("   切ってある保護: " + ("; ".join(sorted(set(off))) or "無し"))
        out(f"   スクリプトを実行するビルドフェーズ: {script_phases}; ネットワークから取得するもの: " + (", ".join(fetching) or "無し")
            + f"; スクリプトのサンドボックス（ENABLE_USER_SCRIPT_SANDBOXING）: {', '.join(sorted(script_sandbox)) or '設定なし'}")
        for path in xcconfigs:
            text = read(path) or ""
            for number, line in enumerate(text.split("\n"), 1):
                if re.search(r"(SWIFT_ACTIVE_COMPILATION_CONDITIONS|GCC_PREPROCESSOR_DEFINITIONS).*\bDEBUG\b", line) \
                        and "debug" not in os.path.basename(path).lower():
                    out(f"   {rel(path)}:{number} が .xcconfig で DEBUG を定義している: どの構成が使うかを確かめる")
        env_names, arg_count, archive = [], 0, set()
        for path in schemes_shared:
            text = read(path) or ""
            env_names += re.findall(r'<EnvironmentVariable\s+key = "([^"]+)"', text)
            arg_count += len(re.findall(r"<CommandLineArgument\b", text))
            archive |= set(re.findall(r'<ArchiveAction\s+buildConfiguration = "([^"]+)"', text))
        secretish = sorted({n for n in env_names if SECRETISH_NAME.search(n)})
        out(f"   共有スキーム: {len(schemes_shared)}; 環境変数（名前だけ）: "
            + (", ".join(sorted(set(env_names))) or "無し") + f"; 起動時の引数: {arg_count}"
            + (f"; アーカイブの構成: {', '.join(sorted(archive))}" if archive else ""))
        if secretish:
            out(f"   スキームの変数のうち、秘密の値らしい名前のもの: {', '.join(secretish)}")
        out("   任意の強化（ENABLE_ENHANCED_SECURITY）: " + (", ".join(sorted(enhanced)) or "設定なし"))
    out("")

    used = [f for f in compiled if hits[f[0]]]
    unused = [f for f in compiled if not hits[f[0]]]
    out("## 使っている機能（B1〜B23）: 1つずつ確認する")
    for fid, title, ref, judgement, _p in used:
        tag = " [要判断: これは兆しにすぎない]" if judgement else ""
        out(f"{fid} {title}{tag}  -> references/{ref}")
        out(f"   {counts[fid]} 行、{len(hits[fid])} ファイル: {fmt(hits[fid], args.samples)}")
    if file_sharing:
        out(f"   B9 の注記: 「ファイル」アプリに見せているファイル: {'; '.join(file_sharing)}")
    if settings_first and hits["B7"]:
        out(f"   B7 の注記: 先にこれらを読む。設定の保存先を使っていて、個人情報らしい語がある: "
            f"{', '.join(settings_first[:6])}" + (f"（ほか {len(settings_first) - 6} 個）" if len(settings_first) > 6 else ""))
    if intents:
        out(f"   B1 の注記: App Intents が {len(intents)} ファイルにある。引数は、端末を使っている本人から来る。"
            "確認なしでデータを変える・消すものだけを読む。")
    groups = [rel(p) for p in entitlements if "com.apple.security.application-groups" in (load_plist(p) or {})]
    if groups and not hits["B10"]:
        out(f"B10 ウィジェットなどとのデータ共有  -> references/data-exposure.md")
        out(f"   App Group の権限がある: {', '.join(groups)}")
    if mac:
        sandbox = [rel(p) for p in entitlements if (load_plist(p) or {}).get("com.apple.security.app-sandbox") is True]
        out("B23 Mac 向けのアプリ  -> references/trust-and-identity.md")
        sandbox_state = ", ".join(sandbox) or (
            f"ビルド設定 ENABLE_APP_SANDBOX = {', '.join(sorted(sandbox_setting))}" if sandbox_setting else "見つからない")
        out(f"   App Sandbox: {sandbox_state}; "
            f"ENABLE_HARDENED_RUNTIME: {', '.join(sorted(hardened)) or '設定なし'}")
    out("")
    out("## 見つからなかった機能: これらは飛ばす")
    out("   " + ("; ".join(f"{fid} {title}" for fid, title, *_ in unused) or "（無し）")
        + ("" if mac else "; B23 Mac 向けのアプリ"))
    out("")

    out("## サーバーと外部のパッケージ（C1〜C3）: references/server-and-supply-chain.md")
    servers = [m for m in SERVER_MARKERS if os.path.exists(os.path.join(root, m))]
    for sub in sorted(os.listdir(root)):          # one level down, for monorepos
        subdir = os.path.join(root, sub)
        if os.path.isdir(subdir) and sub not in SKIP_DIRS and not sub.startswith("."):
            servers += [os.path.join(sub, m) for m in SERVER_MARKERS[:9] if os.path.exists(os.path.join(subdir, m))]
    out("C1 サーバー側のプログラム: " + (", ".join(servers) if servers
                                   else "上から2階層に、サーバーのフォルダーや設定は無し"))
    plist_keys = []
    for path in plists:
        data = load_plist(path) or {}
        names = sorted(k for k in data if isinstance(k, str) and CLIENT_PLIST_KEY.search(k))
        if names:
            plist_keys.append(f"{rel(path)}: {', '.join(names)}")
    if google_plists or client_calls or client_keys or plist_keys:
        out("C2 アプリに入れて配る鍵:")
        if google_plists:
            out(f"   Firebase の設定: {', '.join(rel(p) for p in google_plists)}")
        if client_calls:
            out(f"   SDK に渡している鍵: {fmt(client_calls, args.samples)}")
        if plist_keys:
            out(f"   Info.plist の鍵らしい項目（名前だけ）: {'; '.join(plist_keys)}")
        seen_client = {}
        for relpath, number, what in client_keys:
            seen_client.setdefault((relpath, what), number)
        for (relpath, what), number in list(seen_client.items())[:12]:
            out(f"   {relpath}:{number}  {what}")
    else:
        out("C2 アプリに入れて配る鍵: 無し")
    out("C3 外部のパッケージ:")
    if not resolved:
        out("   Package.resolved、Podfile.lock、Cartfile.resolved は無し")
    for path in resolved:
        relpath = rel(path)
        state = "" if tracked is None else (" [git で管理されている]" if relpath in tracked else " [git で管理されていない]")
        text = read(path) or ""
        pins = len(re.findall(r'"identity"\s*:', text))
        floating = len(re.findall(r'"branch"\s*:\s*"', text))
        detail = f"{pins} 個を固定、うち {floating} 個はブランチで指定" if pins else ""
        out(f"   {relpath}{state} {detail}".rstrip())
    ci = [m for m in CI_MARKERS if os.path.exists(os.path.join(root, m))]
    out("   ビルドの仕組み: " + (", ".join(ci) if ci else "リポジトリには無し"))
    out("")
    out("## 結果を使う前に")
    out("- パターンの照合だけです。見つかった箇所は「ここを見る」という意味で、問題かどうかはコードを読んで決めます。")
    out("- 見つからないことは、無いことの証明になりません。ラッパー、生成されたコード、Objective-C のカテゴリは、機能を隠すことがあります。")
    out("- CloudKit Console やサービスの管理画面など、リポジトリの外にある設定は、ここでは見えません。")
    out("- 鍵は、形を知っているものと、名前で分かるもので探します。どちらでもない鍵は見つからず、git の履歴の中身も調べません。")
    out("  そこまで調べるときは、専用の検査ツールを使います（references/every-app.md の A3）。")


if __name__ == "__main__":
    main()
