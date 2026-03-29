<?php

/**
 * Plugin Name: IP Login Restrictor
 * Plugin URI: https://github.com/taman777/ip-login-restrictor
 * Description: 指定された IP アドレス・CIDR だけが WordPress にログイン・管理画面にアクセスできます。wp-config.php に定義すれば緊急避難IPも許可されます。
 * Version: 1.4.1
 * Author: T.Satoh @ GTI Inc.
 * Text Domain: ip-login-restrictor
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) exit;

// Composer autoload（存在チェック）
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

require_once __DIR__ . '/includes/Class_IP_Utils.php';


use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

if (!class_exists('IP_Login_Restrictor')) {

class IP_Login_Restrictor
{

    const OPTION_IPS          = 'ip_login_restrictor_ips';
    const OPTION_FRONTEND_IPS = 'ip_login_restrictor_frontend_ips';
    const OPTION_ENABLED      = 'ip_login_restrictor_enabled'; // '1' or '0'
    const OPTION_FRONTEND_ENABLED = 'ip_login_restrictor_frontend_enabled'; // '1' or '0'
    const OPTION_RESCUE_KEY       = 'ip_login_restrictor_rescue_key';
    const OPTION_RESCUE_PARAM     = 'ip_login_restrictor_rescue_param'; // URLパラメータキー
    const OPTION_MSG_BODY     = 'ip_login_restrictor_message_body_html'; // 本文のみHTML
    const OPTION_PREVIEW_MSG  = 'ip_login_restrictor_preview_notice_msg'; // プレビュー中通知メッセージ
    const META_TEMPORARY_IPS  = '_iplr_temporary_ips'; // ページ固有の臨時IP
    const META_TEMPORARY_IPS_MESSAGE = '_iplr_temporary_ips_message'; // ページ固有の拒否メッセージ
    const META_TEMPORARY_IPS_EXPIRE  = '_iplr_temporary_ips_expire';  // ページ固有の制限有効期限

    /** @var string 管理メニューのフック名（load-フックでPOST処理用） */
    private $menu_hook = '';

    /** @var bool IP制限によりログインなしでプレビュー表示中か */
    private $is_preview_via_ip = false;

    public function __construct()
    {
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        // Rescue URL チェック (template_redirect なら安全)
        add_action('template_redirect', [$this, 'handle_rescue_request'], 1);

        // 下書きプレビューの許可（ログインなし・IP制限時のみ）
        add_filter('the_posts', [$this, 'allow_draft_preview'], 10, 2);

        // アクセス制限チェック
        // フロントエンド
        add_action('template_redirect', [$this, 'check_access']); // Existing hook with default priority 10
        // ログイン画面
        add_action('login_init',        [$this, 'check_access'], 1); // Changed priority to 1
        // 管理画面（admin-ajax等も含む）
        add_action('admin_init',        [$this, 'check_access'], 1); // Changed priority to 1
        // フロントエンドの通常アクセスもチェックするために template_redirect にもフックする (追加)
        add_action('template_redirect', [$this, 'check_access'], 1); // Added hook with priority 1

        add_action('wp_footer', [$this, 'debug_access_reason']); // Debug logic

        // プレビュー通知バー（画面下部）
        add_action('wp_footer',         [$this, 'show_preview_notice']);

        add_action('admin_menu',      [$this, 'add_admin_menu']);
        add_action('admin_bar_menu',  [$this, 'add_admin_bar_status'], 100);

        // 全体への警告通知
        add_action('admin_notices',   [$this, 'admin_page_restriction_notice']);

        // 管理バー色付け（有効=緑 / 無効=グレー）
        add_action('admin_head',      [$this, 'output_adminbar_css']);
        add_action('wp_head',         [$this, 'output_adminbar_css']);

        // ページ単位の臨時IP設定用メタボックス
        add_action('add_meta_boxes', [$this, 'add_temporary_ip_metabox']);
        add_action('save_post',      [$this, 'save_temporary_ip_metabox']);

        // 投稿一覧にカスタムカラム追加
        add_filter('manage_posts_columns',       [$this, 'add_temporary_ip_column']);
        add_filter('manage_pages_columns',       [$this, 'add_temporary_ip_column']);
        add_action('manage_posts_custom_column', [$this, 'display_temporary_ip_column'], 10, 2);
        add_action('manage_pages_custom_column', [$this, 'display_temporary_ip_column'], 10, 2);

        register_activation_hook(__FILE__, ['IP_Login_Restrictor', 'activate']);
        register_uninstall_hook(__FILE__,  ['IP_Login_Restrictor', 'uninstall']);

        $this->init_update_checker();
    }

    /** 言語ロード */
    public function load_textdomain()
    {
        load_plugin_textdomain('ip-login-restrictor', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

    /** PUC 初期化 */
    private function init_update_checker()
    {
        if (class_exists(PucFactory::class)) {
            $updateChecker = PucFactory::buildUpdateChecker(
                'https://github.com/taman777/ip-login-restrictor',
                __FILE__,
                'ip-login-restrictor'
            );
            $updateChecker->setBranch('main');
            // Private リポの場合のみ：
            // if (defined('GITHUB_TOKEN') && GITHUB_TOKEN) { $updateChecker->setAuthentication(GITHUB_TOKEN); }
        }
    }

    /** 翻訳対応のデフォルト本文（HTML）を返す */
    private static function get_default_body_html_translated()
    {
        // トークンはこのまま保持（後で置換）
        $tpl = __(
            '<h1>Access Denied</h1><p class="description">This IP address ({ip}) is not allowed to access the admin/login of {site_name}.<br><small>As of {datetime}</small></p>',
            'ip-login-restrictor'
        );
        return $tpl;
    }

    /** 有効化時: いきなりONにしない。本文HTMLのデフォルトも翻訳で用意 */
    public static function activate()
    {
        if (get_option(self::OPTION_ENABLED, null) === null) {
            add_option(self::OPTION_ENABLED, '0');
        }
        if (get_option(self::OPTION_FRONTEND_ENABLED, null) === null) {
            add_option(self::OPTION_FRONTEND_ENABLED, '0');
        }
        if (get_option(self::OPTION_IPS, null) === null) {
            add_option(self::OPTION_IPS, []);
        }
        if (get_option(self::OPTION_FRONTEND_IPS, null) === null) {
            add_option(self::OPTION_FRONTEND_IPS, []);
        }
        if (get_option(self::OPTION_MSG_BODY, null) === null) {
            // 静的メソッドで翻訳済みテンプレをセット
            add_option(self::OPTION_MSG_BODY, self::get_default_body_html_translated());
        }
        if (get_option(self::OPTION_PREVIEW_MSG, null) === null) {
            add_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        }
        if (get_option(self::OPTION_RESCUE_PARAM, null) === null) {
            add_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
        }
    }

    /** アンインストール時: 設定削除 */
    public static function uninstall()
    {
        delete_option(self::OPTION_IPS);
        delete_option(self::OPTION_FRONTEND_IPS);
        delete_option(self::OPTION_ENABLED);
        delete_option(self::OPTION_FRONTEND_ENABLED);
        delete_option(self::OPTION_RESCUE_KEY);
        delete_option(self::OPTION_RESCUE_PARAM);
        delete_option(self::OPTION_MSG_BODY);
    }

    /** 現在有効か */
    private function is_enabled()
    {
        return get_option(self::OPTION_ENABLED, '0') === '1';
    }

    /** フロントエンド制限が有効か */
    private function is_frontend_enabled()
    {
        return get_option(self::OPTION_FRONTEND_ENABLED, '0') === '1';
    }

    /** アクセスチェック本体（常にプレーンHTMLで安全に返す） */
    public function check_access()
    {
        // if (!$this->is_enabled()) return; // 削除: 個別ページ制限のみ有効な場合に対応するため
        if (defined('REMOVE_WP_LOGIN_IP_ADDRESS') && REMOVE_WP_LOGIN_IP_ADDRESS === true) return;

        // Ajax/post は除外
        if ($this->is_ajax_or_post()) return;

        // 対象エリア判定
        $is_admin_area = is_admin() || $this->is_login_page();
        $frontend_enabled = $this->is_frontend_enabled();
        $plugin_enabled = $this->is_enabled();

        // ページ個別の臨時IP設定を確認（フロントエンドの場合）
        $page_temp_ips_active = false;
        $post_id = 0;
        if (!$is_admin_area) {
            $post_id = get_queried_object_id();
            if (!$post_id) {
                 global $post;
                 // is_singular() の場合のみ $post->ID をフォールバックとして使用する
                 // これがないと、トップページ（最新の投稿）で最初の記事の制限がページ全体に誤爆する
                 if ($post && isset($post->ID) && is_singular()) {
                     $post_id = $post->ID;
                 }
            }
            
            if ($post_id) {
                $enabled_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
                if ($enabled_meta === '1') {
                    // 有効期限のチェック
                    $expire_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
                    if ($expire_meta) {
                        $expire_timestamp = strtotime($expire_meta);
                        if ($expire_timestamp && current_time('timestamp') > $expire_timestamp) {
                            $page_temp_ips_active = false;
                        } else {
                            $page_temp_ips_active = true;
                        }
                    } else {
                        // 期限なし
                        $page_temp_ips_active = true;
                    }
                }
            }
        }

        // 1. プラグイン全体が無効 かつ 個別ページ制限もない → 何もしない
        if (!$plugin_enabled && !$page_temp_ips_active) {
            return;
        }

        // 2. プラグイン全体が無効だが、個別ページ制限がある場合
        //    → 管理画面エリアなら何もしない（個別ページ制限はフロントエンドのみ）
        if (!$plugin_enabled && $is_admin_area) {
            return;
        }
        
        // 3. フロントエンドで、全体無効ではなく、フロント制限無効、かつ個別制限もない → 何もしない
        if (!$is_admin_area && $plugin_enabled && !$frontend_enabled && !$page_temp_ips_active) {
            return;
        }

        // ここからIPチェック処理
        $admin_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
             // 緊急避難IP対応（カンマ区切り/配列対応）
             $emergency_ips = WP_LOGIN_IP_ADDRESS;
             if (is_string($emergency_ips)) {
                 $emergency_ips = preg_split('/[\s,]+/', $emergency_ips, -1, PREG_SPLIT_NO_EMPTY);
             }
             if (is_array($emergency_ips)) {
                 $admin_ips = array_merge($admin_ips, $emergency_ips);
             } elseif (is_string($emergency_ips) && $emergency_ips !== '') {
                  $admin_ips[] = $emergency_ips;
             }
        }

        if ($is_admin_area) {
            // 管理画面エリア: 管理用IPリストのみ
            $allowed_ips = $admin_ips;
        } else {
            // フロントエンド
            
            // 管理者としてログイン済みの場合は、IPに関わらず許可する
            if (current_user_can('manage_options')) {
                return;
            }
            
            // $allowed_ips = $admin_ips; // 修正前: 無条件に管理者許可
            $allowed_ips = [];

            // プラグイン全体が「有効」な場合のみ、管理者リスト（Global）を許可対象に含める
            // 「無効」の場合は、管理者リストであっても許可しない（個別ページ設定のみを評価する）
            if ($plugin_enabled) {
                $allowed_ips = $admin_ips;
            }

            // フロントエンド制限が有効な場合のみ、フロントエンド共通リストを追加
            if ($plugin_enabled && $frontend_enabled) {
                $frontend_ips = get_option(self::OPTION_FRONTEND_IPS, []);
                $allowed_ips  = array_merge($allowed_ips, $frontend_ips);
            }

            // ページ固有の臨時IPを追加（有効な場合）
            if ($page_temp_ips_active && $post_id) {
                $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
                if ($temporary_ips) {
                    $temp_ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                    $temp_ips_array = array_filter(array_map('trim', $temp_ips_array));
                    $allowed_ips = array_merge($allowed_ips, $temp_ips_array);
                }
            }
        }



        $client_ips = IP_Login_Restrictor_Utils::get_client_ips();

        // 許可されているかチェック
        if (IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $allowed_ips)) {
             return;
        }

        // 許可されていない場合、かつまだJSチェックおよびPOST送信が行われていない場合
        // （ループ防止は Utils 側でも行っているが、ここでもチェック）
        if ( ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['iplr_denied_client_ip'])) && empty($_POST['iplr_denied_checked']) ) {
             IP_Login_Restrictor_Utils::render_js_collector_page();
        }

        // ここまで来たら完全に拒否（JSチェック後もNGだった、あるいはJSチェック済み）
        // 表示用のIPは、可能な限りメインのものを取得（IPv4優先などはお好みだが、allの先頭などを表示）
        // ユーザーが管理者へ連絡する際、複数の候補（IPv4/IPv6）を伝えられるように全て表示する
        $remote_ip = implode(', ', $client_ips['all'] ?? []);

        // if (!$this->ip_in_allowed_list($remote_ip, $allowed_ips)) { // 既にチェック済み
        {

            // 403 + HTML
            status_header(403);
            nocache_headers();
            header('Content-Type: text/html; charset=UTF-8');

            // 本文（未設定や空なら翻訳済みデフォルトで補填）
            $body_html = get_option(self::OPTION_MSG_BODY, '');
            if ($body_html === '') {
                $body_html = self::get_default_body_html_translated();
            }
            $body_html = wp_kses_post($body_html);

            // 置換トークン
            $page_message_html = '';
            if ($post_id) {
                $raw_msg = get_post_meta($post_id, self::META_TEMPORARY_IPS_MESSAGE, true);
                if ($raw_msg) {
                    $page_message_html = '<div class="page-message" style="margin: 15px 0; padding: 10px; background: #fff9c4; border-left: 4px solid #fbc02d; color: #333;">' . esc_html($raw_msg) . '</div>';
                }
            }

            // トークンが含まれていないがメッセージがある場合、末尾に強制展開用として追加
            if ($page_message_html !== '' && strpos($body_html, '{page_message}') === false) {
                // <small>等のタグがある可能性を考慮して単純に末尾に追加
                $body_html .= '{page_message}';
            }

            $replacements = [
                '{ip}'           => esc_html($remote_ip),
                '{datetime}'     => esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'))),
                '{site_name}'    => esc_html(get_bloginfo('name')),
                '{page_message}' => $page_message_html,
            ];
            $body_html = strtr($body_html, $replacements);

            // プレーンHTMLで返す（テーマ非依存）
            echo '<!doctype html><html lang="' . esc_attr(get_bloginfo('language')) . '"><head><meta charset="utf-8"><title>' . esc_html(__('Access Denied', 'ip-login-restrictor')) . '</title>';
            echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
            echo '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;line-height:1.6;background:#f8f9fa;color:#212529;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.box{max-width:720px;background:#fff;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.08);padding:28px}</style>';
            echo '</head><body><div class="box">' . $body_html . '</div></body></html>';

            exit;
        }
    }

    private function is_login_page()
    {
        return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php'], true);
    }

    private function is_ajax_or_post()
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? '';
        return (strpos($script, 'admin-ajax.php') !== false) || (strpos($script, 'admin-post.php') !== false);
    }

    private function get_client_ip()
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP']))       return $_SERVER['HTTP_CLIENT_IP'];
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    private function ip_in_allowed_list($ip, $allowed_list)
    {
        foreach ((array)$allowed_list as $allowed_ip) {
            $allowed_ip = trim((string)$allowed_ip);
            if ($allowed_ip === '') continue;
            if (strpos($allowed_ip, '/') !== false) {
                if ($this->cidr_match($ip, $allowed_ip)) return true;
            } else {
                if ($ip === $allowed_ip) return true;
            }
        }
        return false;
    }

    /**
     * 下書きプレビューの許可（ログインなし・IP制限時のみ）
     * 参照: https://developer.wordpress.org/reference/hooks/the_posts/
     */
    public function allow_draft_preview($posts, $query)
    {
        // 管理画面や、既に記事が見つかっている場合、メインクエリ以外は対象外
        if (is_admin() || !empty($posts) || !$query->is_main_query()) {
            return $posts;
        }

        // プレビューリクエストかチェック
        $post_id = 0;
        if (isset($_GET['preview']) && $_GET['preview'] === 'true') {
            if (isset($_GET['p'])) {
                $post_id = intval($_GET['p']);
            } elseif (isset($_GET['page_id'])) {
                $post_id = intval($_GET['page_id']);
            }
        }

        if ($post_id > 0) {
            if ($this->is_ip_allowed_for_post($post_id)) {
                $post = get_post($post_id);
                // 下書き、レビュー待ち、予約済みを許可
                if ($post && in_array($post->post_status, ['draft', 'pending', 'future'])) {
                    $this->is_preview_via_ip = true; // フラグを立てる
                    $posts = [$post];
                    // 404を回避
                    $query->is_404 = false;
                    // クエリフラグを適切に設定
                    if ($post->post_type === 'page') {
                        $query->is_page = true;
                    } else {
                        $query->is_single = true;
                    }
                }
            }
        }

        return $posts;
    }

    /**
     * 特定の投稿に対してIPが許可されているか判定
     */
    private function is_ip_allowed_for_post($post_id)
    {
        // プラグイン自体が無効でも、ページ個別設定があれば判定を行う
        // check_access() と同様のロジックで対応
        // if (!$this->is_enabled()) return false;

        $client_ips = IP_Login_Restrictor_Utils::get_client_ips();

        
        // 管理用IPリスト（緊急避難IP含む）
        $admin_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
             $emergency_ips = WP_LOGIN_IP_ADDRESS;
             if (is_string($emergency_ips)) {
                 $emergency_ips = preg_split('/[\s,]+/', $emergency_ips, -1, PREG_SPLIT_NO_EMPTY);
             }
             if (is_array($emergency_ips)) {
                 $admin_ips = array_merge($admin_ips, $emergency_ips);
             }
        }

        if (IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $admin_ips)) {
            return true;
        }

        // フロントエンドIPリスト
        // プラグイン全体が有効かつフロントエンド制限も有効な場合のみチェック
        if ($this->is_enabled() && $this->is_frontend_enabled()) {
            $frontend_ips = get_option(self::OPTION_FRONTEND_IPS, []);
            if (IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $frontend_ips)) {
                return true;
            }
        }

        // ページ個別の臨時IP
        $temp_enabled = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
        if ($temp_enabled === '1') {
            // 有効期限のチェック
            $expire_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
            if ($expire_meta) {
                $expire_timestamp = strtotime($expire_meta);
                if ($expire_timestamp && current_time('timestamp') > $expire_timestamp) {
                    return false;
                }
            }

            $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
            if ($temporary_ips) {
                $temp_ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                $temp_ips_array = array_filter(array_map('trim', $temp_ips_array));
                if (IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $temp_ips_array)) {
                    return true;
                }
            }

            // ここで許可されていない場合、かつJSチェックがまだならJS Collectorを表示して終了させる
            // （check_access と同様のロジック）
            if ( ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['iplr_denied_client_ip'])) && empty($_POST['iplr_denied_checked']) ) {
                IP_Login_Restrictor_Utils::render_js_collector_page();
            }
        }

        return false;
    }

    private function cidr_match($ip, $cidr)
    {
        list($subnet, $mask) = explode('/', $cidr);
        $ip_dec     = ip2long($ip);
        $subnet_dec = ip2long($subnet);
        if ($ip_dec === false || $subnet_dec === false) return false;
        $mask = (int)$mask;
        $mask_dec = ~((1 << (32 - $mask)) - 1);
        return ($ip_dec & $mask_dec) === ($subnet_dec & $mask_dec);
    }

    /** 管理メニュー追加（load-フックでPOST処理→リダイレクト） */
    public function add_admin_menu()
    {
        $this->menu_hook = add_menu_page(
            __('IP Login Restrictor', 'ip-login-restrictor'),
            __('IP Login Restrictor', 'ip-login-restrictor'),
            'manage_options',
            'ip-login-restrictor',
            [$this, 'settings_page'],
            'dashicons-shield',
            80
        );
        add_action("load-{$this->menu_hook}", [$this, 'handle_settings_post']);
    }

    /** POST保存＋リダイレクト（描画前に実行） */
    public function handle_settings_post()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        if (!current_user_can('manage_options')) return;

        check_admin_referer('ip_login_restrictor_save');

        // Rescue Key & Param
        if (isset($_POST['ip_login_restrictor_rescue_key'])) {
            $key = sanitize_text_field($_POST['ip_login_restrictor_rescue_key']);
            update_option(self::OPTION_RESCUE_KEY, $key);
        }
        if (isset($_POST['ip_login_restrictor_rescue_param'])) {
            $param = sanitize_text_field($_POST['ip_login_restrictor_rescue_param']);
            // 空の場合はデフォルトに戻す
            if ($param === '') {
                $param = 'iplr_rescue';
            }
            update_option(self::OPTION_RESCUE_PARAM, $param);
        }

        // 有効/無効
        if (isset($_POST['ip_login_restrictor_enabled'])) {
            $enabled = ($_POST['ip_login_restrictor_enabled'] === '1') ? '1' : '0';
            update_option(self::OPTION_ENABLED, $enabled);
        }

        // フロントエンド制限
        if (isset($_POST['ip_login_restrictor_frontend_enabled'])) {
            $frontend_enabled = ($_POST['ip_login_restrictor_frontend_enabled'] === '1') ? '1' : '0';
            update_option(self::OPTION_FRONTEND_ENABLED, $frontend_enabled);
        }

        // 許可IP (Admin)
        if (isset($_POST['ip_login_restrictor_ips'])) {
            $lines = preg_split("/\r\n|\r|\n/", (string) $_POST['ip_login_restrictor_ips']);
            $ips   = array_filter(array_map('trim', array_map('sanitize_text_field', $lines)));
            update_option(self::OPTION_IPS, $ips);
        }

        // 許可IP (Frontend)
        if (isset($_POST['ip_login_restrictor_frontend_ips'])) {
            $lines = preg_split("/\r\n|\r|\n/", (string) $_POST['ip_login_restrictor_frontend_ips']);
            $ips   = array_filter(array_map('trim', array_map('sanitize_text_field', $lines)));
            update_option(self::OPTION_FRONTEND_IPS, $ips);
        }

        // 本文HTML（安全なHTMLに限定）
        if (isset($_POST['ip_login_restrictor_message_body_html'])) {
            update_option(self::OPTION_MSG_BODY, wp_kses_post($_POST['ip_login_restrictor_message_body_html']));
        }

        // プレビュー通知メッセージ
        if (isset($_POST['ip_login_restrictor_preview_notice_msg'])) {
            update_option(self::OPTION_PREVIEW_MSG, sanitize_text_field($_POST['ip_login_restrictor_preview_notice_msg']));
        }

        // 「デフォルトに戻す」ボタン
        if (isset($_POST['iplr_restore_default_body']) && $_POST['iplr_restore_default_body'] === '1') {
            update_option(self::OPTION_MSG_BODY, self::get_default_body_html_translated());
        }

        // 空なら翻訳済みデフォルトで補填
        if (get_option(self::OPTION_MSG_BODY, '') === '') {
            update_option(self::OPTION_MSG_BODY, self::get_default_body_html_translated());
        }
        // 保存後に安全にリダイレクト（管理バーも最新状態で描画）
        wp_safe_redirect(
            add_query_arg(
                ['page' => 'ip-login-restrictor', 'settings-updated' => 'true'],
                admin_url('admin.php')
            )
        );
        exit;
    }

    /** 救済リクエスト処理 */
    public function handle_rescue_request()
    {
        $param_key = get_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
        if (!isset($_GET[$param_key])) return;

        $input_key = (string)$_GET[$param_key];
        $stored_key = get_option(self::OPTION_RESCUE_KEY, '');

        if ($stored_key !== '' && $input_key === $stored_key) {
            $client_ips = IP_Login_Restrictor_Utils::get_client_ips();
            $ips = get_option(self::OPTION_IPS, []);
            
            $added_ips = [];
            foreach ($client_ips['all'] as $ip) {
                if (!IP_Login_Restrictor_Utils::ip_matches($ip, $ips)) { // 配列ではなく単体v.s.リスト一括チェックはUtilsにはないが、ループで回す
                    // ※ ip_matches は (string, string) なので、既存リスト全体に対してチェックする必要がある
                    // ここではシンプルに「既存リストに含まれているか」を確認
                    $already_in = false;
                    foreach ($ips as $allowed_cidr) {
                        if (IP_Login_Restrictor_Utils::ip_matches($ip, $allowed_cidr)) {
                            $already_in = true;
                            break;
                        }
                    }
                    
                    if (!$already_in) {
                        $ips[] = $ip;
                        $added_ips[] = $ip;
                    }
                }
            }

            if (!empty($added_ips)) {
                update_option(self::OPTION_IPS, $ips);
                $msg = sprintf(__('Success! IPs [%s] have been added to the whitelist.', 'ip-login-restrictor'), implode(', ', $added_ips));
            } else {
                $msg = __('Your IP is already in the whitelist.', 'ip-login-restrictor');
            }

            // 完了メッセージを表示してログインへ
            wp_die(
                '<h1>' . esc_html__('Rescue Mode', 'ip-login-restrictor') . '</h1>' .
                '<p>' . esc_html($msg) . '</p>' .
                '<p><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('Proceed to Login', 'ip-login-restrictor') . '</a></p>',
                __('Rescue Mode', 'ip-login-restrictor'),
                ['response' => 200]
            );
        }
    }

    /** 設定ページ（描画のみ。本文はtextareaでHTML可） */
    public function settings_page()
    {
        if (!current_user_can('manage_options')) return;

        if (isset($_GET['settings-updated']) && $_GET['settings-updated'] === 'true') {
            echo '<div class="updated"><p>' . esc_html__('Settings saved.', 'ip-login-restrictor') . '</p></div>';
        }

        $rescue_key = get_option(self::OPTION_RESCUE_KEY, '');
        $rescue_param = get_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
        $rescue_url = $rescue_key ? home_url('/?' . $rescue_param . '=' . $rescue_key) : '';

        $enabled    = $this->is_enabled();
        $frontend_enabled = $this->is_frontend_enabled();
        $admin_ips        = implode("\n", get_option(self::OPTION_IPS, []));
        $frontend_ips     = implode("\n", get_option(self::OPTION_FRONTEND_IPS, []));
        $msg_body   = (string) get_option(self::OPTION_MSG_BODY, '');
        $preview_msg = (string) get_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        
        $c_ips = IP_Login_Restrictor_Utils::get_client_ips();
        $current_ip_v4 = implode(', ', $c_ips['ipv4']);
        $current_ip_v6 = implode(', ', $c_ips['ipv6']);
        // ボタンアクション用にメインのIPを決める（とりあえず先頭）
        $current_ip_primary = $c_ips['all'][0] ?? '';
        $primary_v6 = $c_ips['ipv6'][0] ?? '';

        // ページ単位の制限が有効なページを取得
        $temp_pages_query = new WP_Query([
            'post_type'      => ['post', 'page'],
            'posts_per_page' => -1,
            'meta_query'     => [
                [
                    'key'   => self::META_TEMPORARY_IPS . '_enabled',
                    'value' => '1',
                ]
            ],
        ]);
        $active_temp_pages = [];
        if ($temp_pages_query->have_posts()) {
            while ($temp_pages_query->have_posts()) {
                $temp_pages_query->the_post();
                $pid = get_the_ID();
                $expire_at = get_post_meta($pid, self::META_TEMPORARY_IPS_EXPIRE, true);
                
                $is_expired = false;
                $remaining_text = __('No expiration', 'ip-login-restrictor');
                
                if ($expire_at) {
                    $expire_ts = strtotime($expire_at);
                    $now = current_time('timestamp');
                    if ($now > $expire_ts) {
                        $is_expired = true;
                        $remaining_text = '<span style="color:#d63638;font-weight:bold;">' . __('Expired', 'ip-login-restrictor') . '</span>';
                    } else {
                        $diff = $expire_ts - $now;
                        $hours = floor($diff / 3600);
                        $mins  = floor(($diff % 3600) / 60);
                        $remaining_text = sprintf(__('%d hours %d mins left', 'ip-login-restrictor'), $hours, $mins);
                    }
                }

                // 期限切れでも「有効（Enable）」設定になっているものはリストに含める（ただし期限切れ表示付き）
                $active_temp_pages[] = [
                    'id'        => $pid,
                    'title'     => get_the_title(),
                    'slug'      => get_post_field('post_name', $pid),
                    'status'    => get_post_status($pid),
                    'edit_url'  => get_edit_post_link($pid),
                    'expire_at' => $expire_at,
                    'remaining' => $remaining_text,
                    'is_expired'=> $is_expired
                ];
            }
            wp_reset_postdata();
        }
?>
        <div class="wrap">
            <h1><?php _e('IP Login Restrictor Settings', 'ip-login-restrictor'); ?></h1>
            <form method="post">
                <?php wp_nonce_field('ip_login_restrictor_save'); ?>

                <h2><?php _e('Status', 'ip-login-restrictor'); ?></h2>
                <label style="display:inline-block;margin-right:16px;">
                    <input type="radio" name="ip_login_restrictor_enabled" value="1" <?php checked($enabled, true); ?>>
                    <span style="color:#1f8f3a;font-weight:700;"><?php _e('Enabled', 'ip-login-restrictor'); ?></span>
                </label>
                <label style="display:inline-block;">
                    <input type="radio" name="ip_login_restrictor_enabled" value="0" <?php checked($enabled, false); ?>>
                    <span style="color:#6c757d;font-weight:700;"><?php _e('Disabled', 'ip-login-restrictor'); ?></span>
                </label>
                <p class="description">
                    <?php _e('When enabled, admin/login access is restricted by the whitelist below.', 'ip-login-restrictor'); ?>
                </p>

                <h2><?php _e('Frontend Restriction', 'ip-login-restrictor'); ?></h2>
                <label style="display:inline-block;margin-right:16px;">
                    <input type="radio" name="ip_login_restrictor_frontend_enabled" value="1" <?php checked($frontend_enabled, true); ?>>
                    <span style="color:#1f8f3a;font-weight:700;"><?php _e('Restrict Frontend', 'ip-login-restrictor'); ?></span>
                </label>
                <label style="display:inline-block;">
                    <input type="radio" name="ip_login_restrictor_frontend_enabled" value="0" <?php checked($frontend_enabled, false); ?>>
                    <span style="color:#6c757d;font-weight:700;"><?php _e('Allow All (Default)', 'ip-login-restrictor'); ?></span>
                </label>
                <p class="description">
                    <?php _e('If enabled, normal pages (frontend) will also be restricted by the same IP whitelist. (Main plugin status must be Enabled)', 'ip-login-restrictor'); ?>
                </p>

                <?php if (!empty($active_temp_pages)): ?>
                    <div class="iplr-active-temp-pages" style="margin-top:20px; background:#fff; border:1px solid #ccd0d4; padding:15px; border-radius:4px;">
                        <h3><?php _e('Active Page Specific Restrictions', 'ip-login-restrictor'); ?></h3>
                        <p class="description"><?php _e('The following pages have page-specific IP restrictions enabled.', 'ip-login-restrictor'); ?></p>
                        <table class="wp-list-table widefat fixed striped" style="margin-top:10px;">
                            <thead>
                                <tr>
                                    <th style="width:60px;">ID</th>
                                    <th><?php _e('Title', 'ip-login-restrictor'); ?></th>
                                    <th style="width:100px;"><?php _e('Post Status', 'ip-login-restrictor'); ?></th>
                                    <th><?php _e('Slug', 'ip-login-restrictor'); ?></th>
                                    <th><?php _e('Remaining Time', 'ip-login-restrictor'); ?></th>
                                    <th style="width:80px;"><?php _e('Edit', 'ip-login-restrictor'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($active_temp_pages as $p): ?>
                                    <tr>
                                        <td><?php echo $p['id']; ?></td>
                                        <td><strong><a href="<?php echo esc_url($p['edit_url']); ?>"><?php echo esc_html($p['title']); ?></a></strong></td>
                                        <td><?php echo esc_html(get_post_status_object($p['status'])->label); ?></td>
                                        <td><code><?php echo esc_html($p['slug']); ?></code></td>
                                        <td><?php echo $p['remaining']; ?></td>
                                        <td><a href="<?php echo esc_url($p['edit_url']); ?>" class="button button-small"><?php _e('Edit', 'ip-login-restrictor'); ?></a></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
                <hr>

                <h2><?php _e('Rescue URL', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('This is your safety net if your IP address changes and you get locked out. Set a secret key below to generate your unique Rescue URL. Accessing that URL will automatically add your new IP to the Admin Whitelist. <b>Please bookmark the generated URL immediately.</b>', 'ip-login-restrictor'); ?>
                </p>
                <p>
                    <label>
                        <?php _e('Rescue Parameter Key:', 'ip-login-restrictor'); ?>
                        <input type="text" name="ip_login_restrictor_rescue_param" value="<?php echo esc_attr($rescue_param); ?>" class="regular-text" placeholder="iplr_rescue">
                    </label>
                </p>
                <p>
                    <label>
                        <?php _e('Rescue Key Value:', 'ip-login-restrictor'); ?>
                        <input type="text" name="ip_login_restrictor_rescue_key" value="<?php echo esc_attr($rescue_key); ?>" class="regular-text" placeholder="e.g. secret-key-123">
                    </label>
                </p>
                <?php if ($rescue_url): ?>
                    <p style="background:#fff;padding:10px;border:1px solid #ddd;display:inline-block;">
                        <strong><?php _e('Your Rescue URL:', 'ip-login-restrictor'); ?></strong><br>
                        <code><a href="<?php echo esc_url($rescue_url); ?>" target="_blank"><?php echo esc_html($rescue_url); ?></a></code>
                    </p>
                <?php endif; ?>
                
                <hr>

                <h3><?php _e('Admin & Login Allowed IPs', 'ip-login-restrictor'); ?></h3>
                <p class="description"><?php _e('These IPs can access EVERYTHING (Admin, Login, and Frontend).', 'ip-login-restrictor'); ?></p>
                <textarea name="ip_login_restrictor_ips" rows="8" cols="60"><?php echo esc_textarea($admin_ips); ?></textarea>
                <p>
                    <button type="button" class="button" onclick="addCurrentIP('ip_login_restrictor_ips', '<?php echo esc_js($current_ip_primary); ?>')"><?php _e('Add current IP to Admin List', 'ip-login-restrictor'); ?></button>
                    <?php if ($primary_v6 && $primary_v6 !== $current_ip_primary): ?>
                        <button type="button" class="button" style="margin-left:5px;" onclick="addCurrentIP('ip_login_restrictor_ips', '<?php echo esc_js($primary_v6); ?>')"><?php _e('Add IPv6 to Admin List', 'ip-login-restrictor'); ?></button>
                    <?php endif; ?>
                    <span style="margin-left:10px;">
                        <?php _e('Your IP:', 'ip-login-restrictor'); ?> 
                        <strong><?php echo $current_ip_v4 ?: ($current_ip_v6 ?: 'Unknown'); ?></strong>
                        <?php if ($current_ip_v6 && $current_ip_v4): ?>
                             (IPv6: <?php echo $current_ip_v6; ?>)
                        <?php endif; ?>
                    </span>
                </p>
                
                <!-- External IPv6 detection result will appear here -->
                <div id="iplr-detected-ipv6-box" style="display:none; margin-top:5px; margin-left:10px; padding:5px; background:#f0f0f1; border-left:4px solid #72aee6;">
                </div>

                <div id="iplr-frontend-ips-section" style="<?php echo $frontend_enabled ? '' : 'display:none;'; ?>">
                    <h3><?php _e('Frontend Only Allowed IPs', 'ip-login-restrictor'); ?></h3>
                    <p class="description"><?php _e('These IPs can ONLY access the Frontend (Normal pages). Ignored if Frontend Restriction is disabled.', 'ip-login-restrictor'); ?></p>
                    <textarea name="ip_login_restrictor_frontend_ips" rows="8" cols="60"><?php echo esc_textarea($frontend_ips); ?></textarea>
                    <p>
                        <button type="button" class="button" onclick="addCurrentIP('ip_login_restrictor_frontend_ips', '<?php echo esc_js($current_ip_primary); ?>')"><?php _e('Add current IP to Frontend List', 'ip-login-restrictor'); ?></button>
                    </p><br>
                </div>

                <h2><?php _e('Access Denied Body (HTML)', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('You can use basic HTML. Disallowed tags will be removed for security. Available tokens: {ip}, {datetime}, {site_name}.', 'ip-login-restrictor'); ?>
                </p>
                <textarea name="ip_login_restrictor_message_body_html" rows="10" cols="80"><?php echo esc_textarea($msg_body); ?></textarea>

                <p style="margin-top:8px;">
                    <button type="submit" name="iplr_restore_default_body" value="1" class="button">
                        <?php _e('Restore default message', 'ip-login-restrictor'); ?>
                    </button>
                </p>

                <hr>

                <h2><?php _e('Preview Notice Message', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('Message shown at the bottom/top of the screen when viewing a draft preview via IP restriction.', 'ip-login-restrictor'); ?>
                </p>
                <input type="text" name="ip_login_restrictor_preview_notice_msg" value="<?php echo esc_attr($preview_msg); ?>" class="regular-text" style="width:100%; max-width:600px;">

                <p class="submit" style="margin-top:18px;">
                    <input type="submit" class="button-primary" value="<?php esc_attr_e('Save Changes', 'ip-login-restrictor'); ?>">
                </p>
            </form>

            <p><strong><?php _e('Emergency IP (IPv4/IPv6):', 'ip-login-restrictor'); ?></strong>
                <?php _e('To manually whitelist an IPv4 or IPv6 address, add this to wp-config.php:', 'ip-login-restrictor'); ?>
                <code>define('WP_LOGIN_IP_ADDRESS', '192.0.2.1, 2001:db8::1');</code>
            </p>
            <p><strong><?php _e('Disable restriction:', 'ip-login-restrictor'); ?></strong>
                <?php _e('Add', 'ip-login-restrictor'); ?>
                <code>define('REMOVE_WP_LOGIN_IP_ADDRESS', true);</code>
                <?php _e('to disable all IP restrictions.', 'ip-login-restrictor'); ?>
            </p>

            <!-- 国際化なしの告知 -->
            <style>
                .iplr-promotion-box {
                    background: #f0f6fc;
                    border: 1px solid #cce5ff;
                    border-left: 4px solid #0073aa;
                    border-radius: 4px;
                    padding: 20px;
                    margin-top: 30px;
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                }
                .iplr-promotion-icon .dashicons {
                    font-size: 48px;
                    width: 48px;
                    height: 48px;
                    color: #0073aa;
                }
                .iplr-promotion-content h3 {
                    margin: 0 0 8px;
                    font-size: 1.2em;
                    color: #1d2327;
                }
                .iplr-promotion-content p {
                    margin: 0 0 12px;
                    color: #50575e;
                    font-size: 14px;
                }
                .iplr-promotion-btn {
                    display: inline-flex;
                    align-items: center;
                    background: #d63638; /* 目立つ色に */
                    color: #fff;
                    text-decoration: none;
                    padding: 8px 18px;
                    border-radius: 4px;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                }
                .iplr-promotion-btn:hover {
                    background: #b32d2e;
                    color: #fff;
                    transform: translateY(-1px);
                }
                .iplr-promotion-btn .dashicons {
                    margin-left: 6px;
                    font-size: 16px;
                    width: 16px;
                    height: 16px;
                    line-height: 1.4;
                }
            </style>
            <div class="iplr-promotion-box">
                <div class="iplr-promotion-icon">
                    <span class="dashicons dashicons-shield-alt"></span>
                </div>
                <div class="iplr-promotion-content">
                    <h3><?php _e('Do you need a static IP address to safely access the admin screen?', 'ip-login-restrictor'); ?></h3>
                    <p>
                        <?php _e('With a static IP, you can maximize IP restriction to enhance security.<br>Recommended for those who want safe and smooth access to the admin screen even from outside or in dynamic IP environments.', 'ip-login-restrictor'); ?>
                    </p>
                    <a href="https://vpn.lolipop.jp/signup?agency_code=f4702aa6f7ddvp" target="_blank" rel="noopener noreferrer" class="iplr-promotion-btn">
                        <?php _e('View LOLIPOP! Static IP Access Service', 'ip-login-restrictor'); ?> <span class="dashicons dashicons-external"></span>
                    </a>
                </div>
            </div>
        </div>
        <script>
            function addCurrentIP(targetName, ipValue) {
                const ip = ipValue || "<?php echo esc_js($this->get_client_ip()); ?>";
                const textarea = document.querySelector('textarea[name="' + targetName + '"]');
                const lines = textarea.value.split(/\r?\n/).map(l => l.trim());
                if (!lines.includes(ip)) {
                    lines.push(ip);
                    textarea.value = lines.filter(Boolean).join("\n");
                } else {
                    alert("<?php echo esc_js(__('This IP address is already added.', 'ip-login-restrictor')); ?>");
                }
            }

            // Toggle Frontend IPs section visibility
            document.querySelectorAll('input[name="ip_login_restrictor_frontend_enabled"]').forEach(function(radio) {
                radio.addEventListener('change', function() {
                    const section = document.getElementById('iplr-frontend-ips-section');
                    if (this.value === '1') {
                        section.style.display = '';
                    } else {
                        section.style.display = 'none';
                    }
                });
            });

            // Auto-detect IPv6 via JS (for cases where server connection is IPv4)
            (async function() {
                const detectBox = document.getElementById('iplr-detected-ipv6-box');
                if (!detectBox) return;

                const clientApis = [
                    // IPv6優先のAPIを先に配置
                    "https://api64.ipify.org?format=json", // v4/v6 dual stack
                    "https://ifconfig.co/json",
                    "https://ipinfo.io/json"
                ];

                let foundIp = "";
                for (const url of clientApis) {
                    try {
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), 4000);
                        const res = await fetch(url, { signal: controller.signal });
                        clearTimeout(timeoutId);
                        const json = await res.json();
                        if (json.ip && json.ip.indexOf(':') !== -1) { // IPv6 check
                            foundIp = json.ip;
                            break;
                        }
                    } catch (e) {
                        // ignore
                    }
                }

                if (foundIp) {
                    // サーバー側で既に同じIPv6が取れている場合は表示しない
                    const currentV4 = "<?php echo esc_js($current_ip_v4); ?>";
                    const currentV6 = "<?php echo esc_js($current_ip_v6); ?>";
                    
                    if (foundIp !== currentV4 && foundIp !== currentV6) {
                        detectBox.style.display = 'block';
                        detectBox.innerHTML = 
                            '<strong>IPv6: ' + foundIp + '</strong> ' + 
                            '<button type="button" class="button button-small" style="margin-left:5px;" onclick="addCurrentIP(\'ip_login_restrictor_ips\', \'' + foundIp + '\')"><?php echo esc_js(__('Add', 'ip-login-restrictor')); ?></button>';
                    }
                }
            })();
        </script>
    <?php
    }

    /** ページ単位の臨時IP設定用メタボックスを追加 */
    public function add_temporary_ip_metabox()
    {
        $post_types = ['post', 'page'];
        foreach ($post_types as $post_type) {
            add_meta_box(
                'iplr_temporary_ips',
                __('IP Login Restrictor - Temporary IPs', 'ip-login-restrictor'),
                [$this, 'render_temporary_ip_metabox'],
                $post_type,
                'side',
                'default'
            );
        }
    }

    /** メタボックスの表示 */
    public function render_temporary_ip_metabox($post)
    {
        wp_nonce_field('iplr_save_temporary_ips', 'iplr_temporary_ips_nonce');
        $temporary_ips = get_post_meta($post->ID, self::META_TEMPORARY_IPS, true);
        $temporary_ips_enabled = get_post_meta($post->ID, self::META_TEMPORARY_IPS . '_enabled', true);
        $expire_at = get_post_meta($post->ID, self::META_TEMPORARY_IPS_EXPIRE, true);

        // デフォルトは無効
        if ($temporary_ips_enabled === '') {
            $temporary_ips_enabled = '0';
        }

        // デフォルトの期限（新規作成時のみ）→「空」の場合は無期限とするので、自動設定はしない
        /*
        if ($expire_at === '' && empty($temporary_ips)) {
            $expire_at = date('Y-m-d\TH:i', current_time('timestamp') + 24 * 3600);
        }
        */

        $is_expired = false;
        if ($expire_at) {
            $is_expired = current_time('timestamp') > strtotime($expire_at);
        }

        $current_ip = esc_html($this->get_client_ip());
        ?>
        <div style="margin-bottom:12px;">
            <label style="display:inline-block;margin-right:12px;">
                <input type="radio" name="iplr_temporary_ips_enabled" value="1" <?php checked($temporary_ips_enabled, '1'); ?>>
                <span style="color:#1f8f3a;font-weight:600;"><?php _e('Enable', 'ip-login-restrictor'); ?></span>
            </label>
            <label style="display:inline-block;">
                <input type="radio" name="iplr_temporary_ips_enabled" value="0" <?php checked($temporary_ips_enabled, '0'); ?>>
                <span style="color:#6c757d;font-weight:600;"><?php _e('Disable', 'ip-login-restrictor'); ?></span>
            </label>
        </div>
        <p class="description">
            <?php _e('Add temporary IP addresses for this page only. One IP per line. CIDR notation is supported.', 'ip-login-restrictor'); ?>
        </p>
        <p class="description" style="margin-top:8px;">
            <?php _e('These IPs will be added to the default allowed IPs when accessing this page.', 'ip-login-restrictor'); ?>
        </p>
        <textarea name="iplr_temporary_ips" rows="6" style="width:100%;margin-top:10px;"><?php echo esc_textarea($temporary_ips); ?></textarea>
        
        <p style="margin-top:12px; font-weight:bold;"><?php _e('Expiration Date/Time:', 'ip-login-restrictor'); ?></p>
        <input type="datetime-local" name="iplr_temporary_ips_expire" value="<?php echo esc_attr($expire_at); ?>" style="width:100%;">
        <p class="description">
            <?php _e('Leave empty for no expiration. The page IP restriction will be automatically disabled after this time.', 'ip-login-restrictor'); ?>
            <?php if ($is_expired): ?>
                <br><span style="color:#d63638;font-weight:bold;"><?php _e('Status: Expired', 'ip-login-restrictor'); ?></span>
            <?php endif; ?>
        </p>

        <p style="margin-top:12px; font-weight:bold;"><?php _e('Custom Denied Message:', 'ip-login-restrictor'); ?></p>
        <input type="text" name="iplr_temporary_ips_message" value="<?php echo esc_attr(get_post_meta($post->ID, self::META_TEMPORARY_IPS_MESSAGE, true)); ?>" style="width:100%;" placeholder="<?php _e('e.g. Please contact the administrator.', 'ip-login-restrictor'); ?>">
        <p class="description"><?php _e('This message will replace the {page_message} token in the access denied body.', 'ip-login-restrictor'); ?></p>

        <p style="margin-top:8px;">
            <button type="button" class="button button-small" onclick="iplrAddCurrentIP('<?php echo esc_js($current_ip); ?>')">
                <?php _e('Add Current IP', 'ip-login-restrictor'); ?>
            </button>
            <span style="margin-left:8px;font-size:11px;color:#666;">
                <?php _e('Your IP:', 'ip-login-restrictor'); ?> <?php echo $current_ip; ?>
            </span>
        </p>
        
        <!-- IPv6 Button Row (Hidden by default) -->
        <p style="margin-top:4px; display:none;" id="iplr-ipv6-row">
            <button type="button" class="button button-small" id="iplr-add-ipv6-btn">
                <?php _e('Add Current IPv6', 'ip-login-restrictor'); ?>
            </button>
            <span style="margin-left:8px;font-size:11px;color:#666; font-weight:bold;" id="iplr-ipv6-text">
                <!-- IPv6 address -->
            </span>
        </p>
        
        <script>
            function iplrAddCurrentIP(val) {
                // val が空なら変数から...というロジックだが、ボタンからは常に渡すようにする
                const ip = val;
                if (!ip) return;

                const textarea = document.querySelector('textarea[name="iplr_temporary_ips"]');
                // 既存の内容を取得（空行除去）
                let currentVal = textarea.value.replace(/\r/g, '').split('\n').map(l => l.trim()).filter(l => l !== '');
                
                if (!currentVal.includes(ip)) {
                    currentVal.push(ip);
                    textarea.value = currentVal.join("\n") + "\n"; // 末尾改行
                    // alert("<?php echo esc_js(__('Added IP:', 'ip-login-restrictor')); ?> " + ip);
                } else {
                    alert("<?php echo esc_js(__('This IP address is already added.', 'ip-login-restrictor')); ?>");
                }
            }
 
            // Auto-detect IPv6
            window.iplrDetectIPv6 = async function() {
                const row = document.getElementById('iplr-ipv6-row');
                const text = document.getElementById('iplr-ipv6-text');
                const btn = document.getElementById('iplr-add-ipv6-btn');
                
                if (!row) return;
                
                // Show checking state if visible
                if (row.style.display !== 'none') {
                    // Start checking
                    text.innerHTML = '<span class="dashicons dashicons-update spin" style="font-size:14px;vertical-align:middle;"></span> <?php echo esc_js(__('Checking...', 'ip-login-restrictor')); ?>';
                }

                const clientApis = [
                    "https://api64.ipify.org?format=json&t=" + Date.now(),
                    "https://ifconfig.co/json?t=" + Date.now()
                ];

                let foundIp = "";
                for (const url of clientApis) {
                    try {
                        const controller = new AbortController();
                        const timeoutId = setTimeout(() => controller.abort(), 4000); // 4 sec timeout
                        const res = await fetch(url, { signal: controller.signal });
                        clearTimeout(timeoutId);
                        const json = await res.json();
                        if (json.ip && json.ip.indexOf(':') !== -1) { 
                            foundIp = json.ip;
                            break;
                        }
                    } catch (e) {}
                }
                
                const currentIp = "<?php echo esc_js($current_ip); ?>";
                
                if (foundIp && foundIp !== currentIp) {
                    row.style.display = 'block';
                    text.innerHTML = '<?php echo esc_js(__('IPv6 detected:', 'ip-login-restrictor')); ?> ' + foundIp + 
                        ' <a href="#" onclick="iplrDetectIPv6(); return false;" class="dashicons dashicons-update" style="text-decoration:none; margin-left:5px; vertical-align:middle; cursor:pointer;" title="<?php echo esc_js(__('Refresh', 'ip-login-restrictor')); ?>"></a>';
                    
                    btn.onclick = function() {
                        iplrAddCurrentIP(foundIp);
                    };
                } else {
                    // Not found or same as IPv4 (which means no separate IPv6 or only IPv4)
                    if (row.style.display !== 'none') {
                         if (!foundIp) {
                             text.innerHTML = '<?php echo esc_js(__('IPv6 detection failed.', 'ip-login-restrictor')); ?> <a href="#" onclick="iplrDetectIPv6(); return false;" class="dashicons dashicons-update" style="text-decoration:none; margin-left:5px; vertical-align:middle;"></a>';
                         } else {
                             // Same as v4, hide row? Or verify?
                             // Usually if same, we hide.
                             row.style.display = 'none';
                         }
                    }
                }
            };
            
            // Run on load
            iplrDetectIPv6();
        </script>
        <?php
    }

    /** メタボックスの保存 */
    public function save_temporary_ip_metabox($post_id)
    {
        // Nonce チェック
        if (!isset($_POST['iplr_temporary_ips_nonce']) || !wp_verify_nonce($_POST['iplr_temporary_ips_nonce'], 'iplr_save_temporary_ips')) {
            return;
        }

        // 自動保存の場合は何もしない
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }

        // 権限チェック
        if (!current_user_can('edit_post', $post_id)) {
            return;
        }


        // 臨時IP有効/無効の保存
        if (isset($_POST['iplr_temporary_ips_enabled'])) {
            $enabled = ($_POST['iplr_temporary_ips_enabled'] === '1') ? '1' : '0';
            update_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', $enabled);
        }

        // 臨時メッセージの保存
        if (isset($_POST['iplr_temporary_ips_message'])) {
            update_post_meta($post_id, self::META_TEMPORARY_IPS_MESSAGE, sanitize_text_field($_POST['iplr_temporary_ips_message']));
        }

        // 臨時IPの保存
        if (isset($_POST['iplr_temporary_ips'])) {
            $temporary_ips = sanitize_textarea_field($_POST['iplr_temporary_ips']);
            update_post_meta($post_id, self::META_TEMPORARY_IPS, $temporary_ips);
        } else {
            delete_post_meta($post_id, self::META_TEMPORARY_IPS);
        }

        // 有効期限の保存
        if (isset($_POST['iplr_temporary_ips_expire'])) {
            $expire_at = sanitize_text_field($_POST['iplr_temporary_ips_expire']);
            update_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, $expire_at);
        }
    }

    /** 投稿一覧にカスタムカラムを追加 */
    public function add_temporary_ip_column($columns)
    {
        $columns['iplr_temporary_ips'] = __('Temporary IPs', 'ip-login-restrictor');
        return $columns;
    }

    /** カスタムカラムの表示 */
    public function display_temporary_ip_column($column, $post_id)
    {
        if ($column === 'iplr_temporary_ips') {
            $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
            $temporary_ips_enabled = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
            
            if ($temporary_ips) {
                $ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                $ips_array = array_filter(array_map('trim', $ips_array));
                $count = count($ips_array);
                
                $expire_at = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
                $is_expired = $expire_at && (current_time('timestamp') > strtotime($expire_at));

                // スイッチの状態で色を変える
                if ($temporary_ips_enabled === '1' && !$is_expired) {
                    echo '<span style="color:#1f8f3a;font-weight:600;">✓ ' . sprintf(_n('%d IP', '%d IPs', $count, 'ip-login-restrictor'), $count) . '</span>';
                } elseif ($is_expired) {
                    echo '<span style="color:#d63638;font-weight:600;">! ' . __('Expired', 'ip-login-restrictor') . '</span>';
                } else {
                    echo '<span style="color:#999;font-weight:600;">✗ ' . sprintf(_n('%d IP', '%d IPs', $count, 'ip-login-restrictor'), $count) . '</span>';
                }
                
                echo '<div style="font-size:11px;color:#666;margin-top:2px;">' . esc_html(implode(', ', array_slice($ips_array, 0, 3)));
                if ($count > 3) {
                    echo '...';
                }
                if ($expire_at) {
                    echo '<br>' . esc_html($expire_at);
                }
                echo '</div>';
            } else {
                echo '<span style="color:#999;">—</span>';
            }
        }
    }

    /** 管理バー表示（有効/無効。有効時は現在IPも子項目に表示） */
    public function add_admin_bar_status($wp_admin_bar)
    {
        if (!is_admin_bar_showing()) return;
        if (!current_user_can('manage_options')) return;

        $enabled = $this->is_enabled();
        $frontend_enabled = $this->is_frontend_enabled();

        if ($enabled) {
            $status_text = __('Enabled', 'ip-login-restrictor');
            if ($frontend_enabled) {
                $status_text .= ' ' . __('(+Frontend)', 'ip-login-restrictor');
            }
        } else {
            $status_text = __('Disabled', 'ip-login-restrictor');
        }

        $parent_title = sprintf(__('IP Restrictor: %s', 'ip-login-restrictor'), $status_text);

        $wp_admin_bar->add_node([
            'id'    => 'ip-login-restrictor-status',
            'title' => esc_html($parent_title),
            'href'  => admin_url('admin.php?page=ip-login-restrictor'),
            'meta'  => ['class' => $enabled ? 'iplr-on' : 'iplr-off'],
        ]);

        if ($enabled) {
            $wp_admin_bar->add_node([
                'id'     => 'ip-login-restrictor-ip',
                'parent' => 'ip-login-restrictor-status',
                'title'  => esc_html(sprintf(__('Your IP: %s', 'ip-login-restrictor'), $this->get_client_ip())),
                'href'   => false,
            ]);
            
            // IPv6用のプレースホルダーメニュー
            $wp_admin_bar->add_node([
                'id'     => 'ip-login-restrictor-ipv6-detect',
                'parent' => 'ip-login-restrictor-status',
                'title'  => '<span id="iplr-adminbar-ipv6" style="font-size:11px; color:#aaa;">Check IPv6...</span>',
                'href'   => false,
                'meta'   => ['html' => '<script>
                    (async function(){
                        const el = document.getElementById("iplr-adminbar-ipv6");
                        if(!el) return;
                        const clientApis = ["https://api64.ipify.org?format=json", "https://ifconfig.co/json"];
                        let foundIp = "";
                        for (const url of clientApis) {
                            try {
                                const controller = new AbortController();
                                const timeoutId = setTimeout(() => controller.abort(), 4000);
                                const res = await fetch(url, { signal: controller.signal });
                                clearTimeout(timeoutId);
                                const json = await res.json();
                                if (json.ip && json.ip.indexOf(":") !== -1) { foundIp = json.ip; break; }
                            } catch(e){}
                        }
                        if(foundIp) {
                            const current = "' . esc_js($this->get_client_ip()) . '";
                            if(foundIp !== current) {
                                el.innerHTML = "IPv6: " + foundIp;
                                el.style.color = "#fff";
                                // 親要素のスタイル調整（任意）
                                const parent = el.closest(".ab-item");
                                if(parent) parent.style.height = "auto";
                            } else {
                                el.parentElement.parentElement.style.display = "none";
                            }
                        } else {
                            el.innerHTML = "IPv6: None";
                        }
                    })();
                </script>'],
            ]);
        }
    }

    /** 管理バーの色付け（Enabled=緑 / Disabled=グレー） */
    public function output_adminbar_css()
    {
        if (!is_admin_bar_showing()) return;
        if (!current_user_can('manage_options')) return;
    ?>
        <style>
            #wpadminbar .iplr-on>.ab-item {
                background-color: #28a745 !important;
                /* 緑 */
                color: #fff !important;
            }
            #wpadminbar .iplr-on>.ab-item:hover {
                background-color: #218838 !important;
                /* 濃い緑 */
            }
            #wpadminbar .iplr-off>.ab-item {
                background-color: #6c757d !important;
                /* グレー */
                color: #fff !important;
            }
            /* サブメニューのスタイル調整 */
            #wp-admin-bar-ip-login-restrictor-status-default li {
                height: auto !important;
            }
        </style>
<?php
    }

    /**
     * IP制限下でのプレビュー通知を表示
     */
    public function show_preview_notice()
    {
        if (!$this->is_preview_via_ip) return;

        $msg          = get_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        $toggle_label = __('Move', 'ip-login-restrictor');
        ?>
        <div id="iplr-preview-notice" onclick="this.classList.toggle('iplr-top')" title="<?php echo esc_attr($toggle_label); ?>">
            <div class="iplr-notice-content">
                <span class="dashicons dashicons-shield iplr-icon-shield"></span>
                <span class="iplr-text-msg"><?php echo esc_html($msg); ?></span>
                <span class="iplr-toggle-btn">
                    <span class="dashicons dashicons-sort"></span>
                    <span class="iplr-btn-text"><?php echo esc_html($toggle_label); ?></span>
                </span>
            </div>
        </div>
        <style>
            #iplr-preview-notice {
                position: fixed;
                bottom: 0;
                left: 0;
                width: 100%;
                background: rgba(30, 30, 30, 0.85);
                color: #fff;
                padding: 10px 0;
                text-align: center;
                font-size: 14px;
                z-index: 999999;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border-top: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 -4px 15px rgba(0, 0, 0, 0.3);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                user-select: none;
            }
            #iplr-preview-notice:hover {
                background: rgba(45, 45, 45, 0.95);
            }
            #iplr-preview-notice.iplr-top {
                bottom: auto;
                top: 0;
                border-top: none;
                border-bottom: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            }
            .iplr-notice-content {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
            }
            .iplr-icon-shield {
                color: #4caf50;
                font-size: 20px;
                width: 20px;
                height: 20px;
            }
            .iplr-toggle-btn {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                background: rgba(255, 255, 255, 0.15);
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 10px;
                transition: background 0.2s;
            }
            #iplr-preview-notice:hover .iplr-toggle-btn {
                background: rgba(255, 255, 255, 0.25);
            }
            .iplr-btn-text {
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            @media (max-width: 600px) {
                .iplr-btn-text { display: none; }
                .iplr-text-msg { font-size: 12px; }
            }
            /* 管理バーがある場合のボディパディング調整（簡易的） */
            body.iplr-preview-active { padding-bottom: 50px; }
            body.iplr-preview-active-top { padding-top: 50px; }
        </style>
        <script>
            (function() {
                const notice = document.getElementById('iplr-preview-notice');
                const body = document.body;
                body.classList.add('iplr-preview-active');
                
                notice.addEventListener('click', function() {
                    if (this.classList.contains('iplr-top')) {
                        body.classList.remove('iplr-preview-active');
                        body.classList.add('iplr-preview-active-top');
                    } else {
                        body.classList.add('iplr-preview-active');
                        body.classList.remove('iplr-preview-active-top');
                    }
                });
            })();
        </script>
        <?php
    }

    /**
     * 管理画面にページ単位のIP制御があることを通知
     */
    public function admin_page_restriction_notice()
    {
        if (!current_user_can('manage_options')) return;

        // ページ単位の制限が有効なページ（期限内）があるかチェック
        $args = [
            'post_type'      => ['post', 'page'],
            'posts_per_page' => 1,
            'fields'         => 'ids',
            'meta_query'     => [
                [
                    'key'   => self::META_TEMPORARY_IPS . '_enabled',
                    'value' => '1',
                ]
            ],
        ];
        
        $query = new WP_Query($args);
        $has_active = false;

        if ($query->have_posts()) {
            foreach ($query->posts as $pid) {
                $expire_at = get_post_meta($pid, self::META_TEMPORARY_IPS_EXPIRE, true);
                if (!$expire_at || strtotime($expire_at) > current_time('timestamp')) {
                    $has_active = true;
                    break;
                }
            }
        }

        if ($has_active) {
            echo '<div class="notice notice-error" style="background-color: #d63638; border-left-color: #9b2021; color: #fff; padding: 12px; margin-left: 0; margin-right: 0;">';
            echo '<p style="margin: 0; font-weight: bold; font-size: 15px; display: flex; align-items: center; gap: 8px;">';
            echo '<span class="dashicons dashicons-shield-alt"></span>';
            echo esc_html__('Page-specific IP Restriction Active', 'ip-login-restrictor');
            echo ' <a href="' . admin_url('admin.php?page=ip-login-restrictor') . '" style="color: #fff; text-decoration: underline; margin-left: 15px; font-weight: normal; font-size: 13px;">' . esc_html__('View Details', 'ip-login-restrictor') . '</a>';
            echo '</p></div>';
        }
    }
    /**
     * デバッグ用：管理者にはフッターに判定理由を表示
     */
    public function debug_access_reason()
    {
        if (!current_user_can('manage_options')) return;

        // Restriction Active Check
        $plugin_enabled = $this->is_enabled();
        $is_frontend_enabled = $this->is_frontend_enabled();
        $page_restriction_active = false;
        
        $pid = 0;
        if (is_singular()) {
             $pid = get_the_ID();
             if (!$pid) {
                 global $post;
                 if ($post && isset($post->ID)) $pid = $post->ID;
             }
             if ($pid) {
                 $temp_enabled = get_post_meta($pid, self::META_TEMPORARY_IPS . '_enabled', true);
                 if ($temp_enabled === '1') {
                     $page_restriction_active = true;
                 }
             }
        }
        
        $frontend_restriction_active = ($plugin_enabled && $is_frontend_enabled);
        
        if (!$frontend_restriction_active && !$page_restriction_active) {
            return; 
        }

        $client_ips = IP_Login_Restrictor_Utils::get_client_ips();
        
        $v4 = implode(', ', $client_ips['ipv4']);
        $v6 = implode(', ', $client_ips['ipv6']);
        $ip_display = $v4 ?: 'Unknown';
        if ($v6) {
            $ip_display .= ' <span style="color:#aaf;">[IPv6: ' . $v6 . ']</span>';
        }

        // Admin match?
        $admin_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
             $emergency = WP_LOGIN_IP_ADDRESS;
             if (is_string($emergency)) $emergency = preg_split('/[\s,]+/', $emergency, -1, PREG_SPLIT_NO_EMPTY);
             if (is_array($emergency)) $admin_ips = array_merge($admin_ips, $emergency);
        }
        
        // Debug: Show allowed IPs for page
        $page_status = '';
        if ($page_restriction_active && $pid) {
             $temp_ips = get_post_meta($pid, self::META_TEMPORARY_IPS, true);
             $page_status = ' <br><strong>Page Allowed IPs:</strong> ' . esc_html(str_replace(["\r", "\n"], ' ', trim($temp_ips)));
        }
        
        $is_admin_allowed = IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $admin_ips);
        
        if ($is_admin_allowed) {
            $reason = "Allowed by <strong>Admin/Global List</strong>";
            if (!$this->is_enabled()) {
                $reason .= " <small>(Safety Override - Plugin Disabled)</small>";
            }
            echo '<div style="background:#000;color:#0f0;padding:10px;position:fixed;bottom:0;left:0;z-index:999999;font-size:12px;opacity:0.9;line-height:1.5;">IPLR Debug: ' . $reason . ' (' . $ip_display . ')' . $page_status . '</div>';
            return;
        }

        // Frontend match?
        $frontend_ips = get_option(self::OPTION_FRONTEND_IPS, []);
        $plugin_enabled = $this->is_enabled();
        $is_frontend_enabled = $this->is_frontend_enabled();
        
        if ($plugin_enabled && $is_frontend_enabled && IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $frontend_ips)) {
            echo '<div style="background:#000;color:#0f0;padding:10px;position:fixed;bottom:0;left:0;z-index:999999;font-size:12px;opacity:0.9;line-height:1.5;">IPLR Debug: Allowed by <strong>Frontend List</strong> (' . $ip_display . ')' . $page_status . '</div>';
            return;
        }

        // Page match?
        if (is_singular()) {
            $pid = get_the_ID();
             if (!$pid) {
                 global $post;
                 if ($post && isset($post->ID)) $pid = $post->ID;
             }
            
            $temp_enabled = get_post_meta($pid, self::META_TEMPORARY_IPS . '_enabled', true);
            if ($temp_enabled === '1') {
                $temp_ips = get_post_meta($pid, self::META_TEMPORARY_IPS, true);
                $temp_ips_array = preg_split("/\r\n|\r|\n/", $temp_ips);
                if (IP_Login_Restrictor_Utils::client_is_allowed($client_ips, $temp_ips_array)) {
                     echo '<div style="background:#000;color:#0f0;padding:10px;position:fixed;bottom:0;left:0;z-index:999999;font-size:12px;opacity:0.9;line-height:1.5;">IPLR Debug: Allowed by <strong>Page Specific List</strong> (' . $ip_display . ')' . $page_status . '</div>';
                     return;
                }
                echo '<div style="background:#000;color:#f00;padding:10px;position:fixed;bottom:0;left:0;z-index:999999;font-size:12px;opacity:0.9;line-height:1.5;">IPLR Debug: <strong>Should be DENIED</strong> by Page List (' . $ip_display . ')' . $page_status . '</div>';
                return;
            }
        }
        
        echo '<div style="background:#000;color:#fff;padding:10px;position:fixed;bottom:0;left:0;z-index:999999;font-size:12px;opacity:0.9;line-height:1.5;">IPLR Debug: No specific restriction matched (' . $ip_display . ')' . $page_status . '</div>';
    }
}

} // End if class_exists

// 実行
new IP_Login_Restrictor();
