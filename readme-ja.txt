=== IP Login Restrictor ===
Contributors: gti-inc
Tags: セキュリティ, IP, ログイン, 管理画面, 制限
Requires at least: 5.0
Tested up to: 6.8.2
Stable tag: 1.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

IPアドレス（CIDR対応）による WordPress ログイン・管理画面アクセス制限プラグイン。wp-config.php による緊急許可IP設定も可能。

== 説明 ==

このプラグインは、WordPress のログインページ（`wp-login.php`）および管理画面（`wp-admin/`）へのアクセスを、特定の IP アドレスまたは CIDR 範囲で制限できます。

**主な機能：**

- `wp-login.php` や `wp-admin/` へのアクセスを許可された IP のみに制限
- CIDR表記（例：`192.168.1.0/24`）に対応
- 管理画面から有効／無効を切り替え可能（ラジオボタン）
- `wp-config.php` に以下を記述すると緊急IPを許可：  
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`
- 全てのIP制限を一時的に無効化：  
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`
- 管理画面から許可IPリストを編集可能
- アクセス拒否メッセージを **HTML** でカスタマイズ可能（テーマに依存せず、シンプルなHTMLとして出力）
- 本文中で `{ip}`, `{datetime}`, `{site_name}` のトークンが使用可能
- 現在のIPをワンクリックで追加可能
- 管理バーに有効／無効ステータスと現在IPを表示
- アップデート通知＆自動更新（GitHub連携）対応

※ `admin-ajax.php` と `admin-post.php` には影響しません。

== インストール方法 ==

1. プラグインファイルを `/wp-content/plugins/ip-login-restrictor` にアップロードするか、WordPress管理画面からインストールします。
2. 「プラグイン」画面から有効化します。
3. 「IP Login Restrictor」メニューから許可IPを設定します。

== よくある質問 ==

= 緊急IPを許可するには？ =  
`wp-config.php` に以下を追加してください：

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= 一時的にIP制限を解除するには？ =  
`wp-config.php` に以下を追加してください：

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

== スクリーンショット ==

1. 許可IP設定画面（緊急IP説明付き）
2. アクセス拒否メッセージのHTML編集画面

== 変更履歴 ==

= 1.4.1 =
*   **改善:** プロキシ経由のアクセス判定を改善（`HTTP_X_FORWARDED_FOR` を優先）
*   **改善:** IPv6の単一アドレス比較とサブネット判定（inet_pton使用）の精度を向上
*   **修正:** 最新の投稿に設定された臨時IP制限が、トップページ（アーカイブやホーム）全体に誤って適用されてしまう不具合を修正

= 1.4.0 =
*   **新機能:** IPv6サポートと自動検出機能を追加
*   **改善:** IPv4/IPv6デュアルスタック環境でのアクセス検証を強化

= 1.3.0 =
*   **新機能:** ページごとに臨時IPアドレスを設定できる機能を追加
*   **新機能:** ログイン不要の下書きプレビューアクセス許可を追加
*   **改善:** プレビューモード時に専用の通知バーを表示

= 1.2.0 =
*   **新機能:** レスキューURL機能を追加（アクセス時に自動で現在のIPを許可）
*   **新機能:** フロントエンド（公開ページ）のみのIP制限機能を追加
*   **新機能:** フロントエンド専用のIPリスト設定を追加

= 1.1.6 =
* 管理画面からON/OFF切り替え機能を追加
* アクセス拒否メッセージをHTMLカスタマイズ可能に（テーマ非依存）
* `{ip}`, `{datetime}`, `{site_name}` トークン対応
* デフォルトメッセージに翻訳を追加

= 1.1.1 =
* `REMOVE_WP_LOGIN_IP_ADDRESS` による制限解除機能追加
* LOLIPOP! 固定IPサービスへのリンク追加
* 現在のIP自動入力と緊急アクセス案内追加
* UI改善と細かい修正

= 1.0 =
* 初回リリース

== ライセンス ==
このプラグインは GNU General Public License v2 またはそれ以降のバージョンの下でライセンスされています。

== サードパーティライブラリ ==
* Plugin Update Checker（MITライセンス）  
  https://github.com/YahnisElsts/plugin-update-checker
