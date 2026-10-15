<?php
/**
 * Plugin Name:       Login Guardian
 * Plugin URI:        https://github.com/opcodesdotin/wp-login-guardian
 * Description:       Advanced WordPress login security with brute-force protection, login rate limiting, 2FA, username enumeration protection, IP management, activity logging, and threat reporting.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            OPCODES.IN
 * Author URI:        https://opcodes.in
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-login-guardian
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) { exit; }

if (!class_exists('ALG_Plugin')) {
    final class ALG_Plugin {
        private static $instance = null;
        private $table;
        private $options_key = 'alg_options_v1';

        public static function instance() : self {
            if (self::$instance === null) { self::$instance = new self(); }
            return self::$instance;
        }

        private function __construct() {
            global $wpdb;
            $this->table = $wpdb->prefix . 'alg_login_activity';
            register_activation_hook(__FILE__, [$this, 'on_activate']);
            add_action('admin_init', [$this, 'register_settings']);
            add_action('admin_menu', [$this, 'admin_menu']);
            add_action('admin_enqueue_scripts', [$this, 'admin_enqueue_assets']);

            // Login flow hooks
            add_filter('authenticate', [$this, 'enforce_rate_limits'], 30, 3);
            add_filter('authenticate', [$this, 'alg_check_2fa'], 35, 3);
            add_action('wp_login_failed', [$this, 'on_login_failed']);
            add_action('wp_login', [$this, 'on_login_success'], 10, 2);

            // 2FA login form
            add_action('login_form_alg_2fa', [$this, 'alg_render_2fa_form']);
            add_action('login_form_alg_2fa_verify', [$this, 'alg_verify_2fa']);
            add_action('login_enqueue_scripts', [$this, 'alg_2fa_login_scripts']);

            // Login page customization
            add_action('login_enqueue_scripts', [$this, 'login_branding']);
            add_filter('login_message', [$this, 'login_custom_message']);

            // Admin ajax & REST
            add_action('wp_ajax_alg_fetch_logs', [$this, 'ajax_fetch_logs']);
            add_action('wp_ajax_alg_purge_logs', [$this, 'ajax_purge_logs']);
            add_action('wp_ajax_alg_block_ip', [$this, 'ajax_block_ip']);
            add_action('wp_ajax_alg_unblock_ip', [$this, 'ajax_unblock_ip']);

            // API Reporting hooks
            add_action('wp_ajax_alg_report_ip', [$this, 'ajax_report_ip']);
            add_action('alg_async_report_ip', [$this, 'async_report_ip'], 10, 2);

            add_action('rest_api_init', function(){
                register_rest_route('alg/v1', '/stats', [
                    'methods'  => 'GET',
                    'permission_callback' => function(){ return current_user_can('manage_options'); },
                    'callback' => [$this, 'rest_stats']
                ]);
            });

            // 2FA AJAX handlers (logged-in users)
            add_action('wp_ajax_alg_toggle_2fa', [$this, 'ajax_toggle_2fa']);
            add_action('wp_ajax_alg_verify_setup_code', [$this, 'ajax_verify_setup_code']);
            add_action('wp_ajax_alg_regenerate_backup', [$this, 'ajax_regenerate_backup']);
            add_action('wp_ajax_alg_admin_reset_2fa', [$this, 'ajax_admin_reset_2fa']);

            // 2FA login AJAX (no auth required)
            add_action('wp_ajax_nopriv_alg_2fa_verify', [$this, 'ajax_nopriv_2fa_verify']);

            // User profile integration
            add_action('show_user_profile', [$this, 'render_2fa_profile']);
            add_action('edit_user_profile', [$this, 'render_2fa_profile']);
            add_action('personal_options_update', [$this, 'save_2fa_profile']);
            add_action('edit_user_profile_update', [$this, 'save_2fa_profile']);
        }

        /* -------------------- Activation -------------------- */
        public function on_activate() {
            global $wpdb;
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            $charset_collate = $wpdb->get_charset_collate();
            $sql = "CREATE TABLE {$this->table} (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                event_time DATETIME NOT NULL,
                user_login VARCHAR(60) NULL,
                user_id BIGINT UNSIGNED NULL,
                ip VARCHAR(64) NOT NULL,
                ua TEXT NULL,
                status VARCHAR(20) NOT NULL,
                reason TEXT NULL,
                PRIMARY KEY  (id),
                KEY idx_time (event_time),
                KEY idx_ip (ip),
                KEY idx_status (status)
            ) $charset_collate;";
            dbDelta($sql);

            // Initialize options if not present
            $defaults = $this->default_options();
            $opts = get_option($this->options_key);
            if (!is_array($opts)) {
                add_option($this->options_key, $defaults, '', 'yes');
            } else {
                update_option($this->options_key, array_merge($defaults, $opts));
            }
        }

        private function default_options() : array {
            return [
                'window_sec'        => 900,      // 15 minutes
                'max_attempts'      => 5,
                'lockout_sec'       => 1800,     // 30 minutes
                'hard_lock_threshold'=> 20,      // escalation threshold within 24h
                'notify_email'      => get_option('admin_email'),
                'notify_on_lockout' => 1,
                'whitelist_ips'     => "",      // newline-separated
                'blacklist_ips'     => "",
                'log_retention_days'=> 90,
                'custom_login_msg'  => '',
                'login_logo_url'    => '',
                'login_bg'          => '#f0f0f0',
                'login_button'      => '#2271b1',
                // 2FA settings
                '2fa_enabled'       => 1,
                '2fa_enforce_roles' => [],
                '2fa_remember_days' => 30,
                // API Reporting settings
                'enable_abuseipdb'       => 0,
                'abuseipdb_api_key'      => '',
                'abuseipdb_categories'   => '18,22',
                'enable_spamhaus'        => 0,
                'spamhaus_api_key'       => '',
                'spamhaus_threat_type'   => 'attack',
                'default_report_comment' => 'Unauthorized login attempt / brute force attack detected',
                'auto_report_on_lockout' => 1,
                'auto_report_on_block'   => 1,
            ];
        }

        /* -------------------- Utility -------------------- */
        private function opts() : array { return (array) get_option($this->options_key, $this->default_options()); }
        private function ip() : string {
            foreach (['HTTP_CLIENT_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $k) {
                if (!empty($_SERVER[$k])) { $ip = $_SERVER[$k]; break; }
            }
            $ip = isset($ip) ? $ip : '0.0.0.0';
            // handle multiple forwarded IPs
            if (strpos($ip, ',') !== false) { $parts = explode(',', $ip); $ip = trim($parts[0]); }
            return sanitize_text_field($ip);
        }
        private function ua() : string { return isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_textarea_field($_SERVER['HTTP_USER_AGENT']), 0, 500) : ''; }
        private function ip_in_list(string $ip, string $list) : bool {
            $ips = array_filter(array_map('trim', explode("\n", $list)));
            foreach ($ips as $pattern) {
                if ($pattern === '') { continue; }
                // support wildcard like 192.168.*
                $regex = '#^' . str_replace(['.','*'], ['\.', '.*'], preg_quote($pattern, '#')) . '$#i';
                if (preg_match($regex, $ip)) return true;
            }
            return false;
        }
        private function transient_key(string $scope, string $identifier) : string {
            return 'alg_' . $scope . '_' . md5($identifier);
        }

        /* -------------------- TOTP 2FA Utilities -------------------- */

        /**
         * Generate a cryptographically random base32-encoded TOTP secret.
         * 16 bytes = 128 bits of entropy, encoded as 26-char base32 string (padded).
         */
        private function alg_generate_secret() : string {
            $bytes = random_bytes(16);
            return $this->alg_base32_encode($bytes);
        }

        /**
         * RFC 4648 Base32 encoding (no padding, uppercase).
         */
        private function alg_base32_encode(string $bytes) : string {
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $bin = '';
            foreach (str_split($bytes) as $c) { $bin .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT); }
            $ret = '';
            foreach (str_split($bin, 5) as $chunk) {
                if (strlen($chunk) < 5) { $chunk = str_pad($chunk, 5, '0'); }
                $ret .= $alphabet[bindec($chunk)];
            }
            return rtrim($ret, 'A'); // trim trailing padding-equivalent
        }

        /**
         * Decode base32 string to binary.
         */
        private function alg_base32_decode(string $str) : string {
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $str = strtoupper($str);
            $bin = '';
            for ($i = 0; $i < strlen($str); $i++) {
                $pos = strpos($alphabet, $str[$i]);
                if ($pos === false) continue;
                $bin .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
            }
            $bytes = '';
            foreach (str_split($bin, 8) as $chunk) {
                if (strlen($chunk) < 8) break;
                $bytes .= chr(bindec($chunk));
            }
            return $bytes;
        }

        /**
         * Compute TOTP code per RFC 6238.
         * $time_offset: offset in 30-second windows (0=current, -1=past, +1=future).
         */
        private function alg_get_totp_code(string $secret_b32, int $time_offset = 0) : string {
            $key = $this->alg_base32_decode($secret_b32);
            $counter = floor((time() + ($time_offset * 30)) / 30);
            $msg = pack('J', $counter); // 8-byte big-endian counter
            $msg = str_pad($msg, 8, "\x00", STR_PAD_LEFT);
            $hash = hash_hmac('sha1', $msg, $key, true);
            $offset = ord($hash[19]) & 0x0F;
            $truncated = unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF;
            return str_pad((string) ($truncated % 1000000), 6, '0', STR_PAD_LEFT);
        }

        /**
         * Verify a TOTP code against current and adjacent time windows.
         * Returns true if code matches any of: current, previous, or next window.
         */
        private function alg_verify_totp(string $secret_b32, string $code) : bool {
            $code = preg_replace('/\s+/', '', $code);
            if (!preg_match('/^\d{6}$/', $code)) return false;
            for ($i = -1; $i <= 1; $i++) {
                if (hash_equals($this->alg_get_totp_code($secret_b32, $i), $code)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Build otpauth:// URI for authenticator app QR codes.
         */
        private function alg_qr_uri(string $user_login, string $secret_b32) : string {
            $site = preg_replace('/^https?:\/\//', '', home_url());
            $label = rawurlencode($site . ':' . $user_login);
            $issuer = rawurlencode($site);
            return "otpauth://totp/{$label}?secret={$secret_b32}&issuer={$issuer}&digits=6&period=30";
        }

        /**
         * Generate backup codes: returns ['plain' => [...], 'hashed' => [...]].
         */
        private function alg_generate_backup_codes() : array {
            $plain = [];
            $hashed = [];
            for ($i = 0; $i < 10; $i++) {
                $code = strtoupper(substr(preg_replace('/\D/', '', base64_encode(random_bytes(6))), 0, 8));
                if (strlen($code) < 8) { $code = str_pad($code, 8, 'A'); }
                $plain[] = $code;
                $hashed[] = password_hash($code, PASSWORD_DEFAULT);
            }
            return ['plain' => $plain, 'hashed' => $hashed];
        }

        /**
         * Verify a backup code against stored hashes. If valid, consume it (remove from list).
         * Returns true if a backup code was used.
         */
        private function alg_verify_backup_code(int $user_id, string $code) : bool {
            $code = strtoupper(preg_replace('/\s+/', '', $code));
            $hashed = get_user_meta($user_id, 'alg_2fa_backup_codes', true);
            if (!is_array($hashed)) return false;
            foreach ($hashed as $i => $hash) {
                if (password_verify($code, $hash)) {
                    unset($hashed[$i]);
                    update_user_meta($user_id, 'alg_2fa_backup_codes', array_values($hashed));
                    return true;
                }
            }
            return false;
        }

        /**
         * Check if a user has 2FA enabled.
         */
        private function alg_is_2fa_enabled(int $user_id) : bool {
            return (bool) get_user_meta($user_id, 'alg_2fa_enabled', true);
        }

        /**
         * Check if 2FA is required for a user (enabled OR enforced by role).
         */
        private function alg_is_2fa_required($user) : bool {
            if (!is_object($user) || !isset($user->ID)) return false;
            if ($this->alg_is_2fa_enabled($user->ID)) return true;
            $opts = $this->opts();
            if (empty($opts['2fa_enabled'])) return false;
            $enforced = $opts['2fa_enforce_roles'] ?? [];
            if (empty($enforced)) return false;
            foreach ($enforced as $role) {
                if (in_array($role, (array) $user->roles)) return true;
            }
            return false;
        }

        /* -------------------- Rate limiting -------------------- */
        public function enforce_rate_limits($user, $username, $password) {
            if (is_wp_error($user)) { return $user; }
            $opts = $this->opts();
            $ip = $this->ip();

            // Whitelist bypass
            if ($this->ip_in_list($ip, $opts['whitelist_ips'])) { return $user; }

            // Blacklist hard block
            if ($this->ip_in_list($ip, $opts['blacklist_ips'])) {
                $this->log_event(null, $username, $ip, 'blocked', 'Blacklisted IP');
                return new WP_Error('alg_blocked', __('Your IP is blocked.', 'advanced-login-guardian'));
            }

            $lock_key = $this->transient_key('lock_ip', $ip);
            $lock_until = get_transient($lock_key);
            if ($lock_until) {
                $remaining = intval($lock_until - time());
                $msg = sprintf(__('Too many attempts. Try again in %s seconds.', 'advanced-login-guardian'), max(1,$remaining));
                $this->log_event(null, $username, $ip, 'lockout', 'Locked by rate limit');
                return new WP_Error('alg_rate_limited', $msg);
            }

            // Soft check current attempts in window
            $counter_key = $this->transient_key('attempts_ip', $ip);
            $attempts = (int) get_transient($counter_key);
            if ($attempts >= intval($opts['max_attempts'])) {
                set_transient($lock_key, time() + intval($opts['lockout_sec']), intval($opts['lockout_sec']));
                if (!empty($opts['notify_on_lockout'])) { $this->notify_lockout($ip, $attempts); }
                if (!empty($opts['auto_report_on_lockout'])) { $this->trigger_auto_report($ip, 'Rate limit threshold exceeded'); }
                $this->log_event(null, $username, $ip, 'lockout', 'Hit max attempts');
                return new WP_Error('alg_rate_limited', __('Too many attempts. You have been temporarily locked out.', 'advanced-login-guardian'));
            }

            return $user; // allow WP to proceed
        }

        public function on_login_failed($username) {
            $opts = $this->opts();
            $ip = $this->ip();
            $counter_key = $this->transient_key('attempts_ip', $ip);
            $attempts = (int) get_transient($counter_key);
            $attempts++;
            set_transient($counter_key, $attempts, intval($opts['window_sec']));

            // Hard lock escalation: count failures in rolling 24h
            $day_key = $this->transient_key('dayfail_ip', $ip);
            $dayfails = (int) get_transient($day_key) + 1;
            set_transient($day_key, $dayfails, DAY_IN_SECONDS);
            if ($dayfails >= intval($opts['hard_lock_threshold'])) {
                // escalate to longer lock (2x lockout)
                $lock_key = $this->transient_key('lock_ip', $ip);
                $dur = max(intval($opts['lockout_sec']) * 2, 3600);
                set_transient($lock_key, time() + $dur, $dur);
                if (!empty($opts['auto_report_on_lockout'])) { $this->trigger_auto_report($ip, '24h escalation hard lock threshold exceeded'); }
            }

            $this->log_event(null, $username, $ip, 'failed', 'Invalid credentials or blocked by WP');
        }

        public function on_login_success($user_login, $user) {
            $ip = $this->ip();
            // Reset counters on success
            delete_transient($this->transient_key('attempts_ip', $ip));
            delete_transient($this->transient_key('lock_ip', $ip));
            $this->log_event($user, $user_login, $ip, 'success', 'Successful login');
        }

        private function notify_lockout(string $ip, int $attempts) {
            $opts = $this->opts();
            $to = sanitize_email($opts['notify_email']);
            if (!$to) return;
            $subj = sprintf('[ALG] IP locked out: %s', $ip);
            $body = sprintf("An IP was locked out on %s.\nIP: %s\nAttempts in window: %d\nTime: %s",
                home_url(), $ip, $attempts, date('c'));
            wp_mail($to, $subj, $body);
        }

        private function log_event($user_or_null, $user_login, $ip, string $status, string $reason = '') {
            global $wpdb;
            $user_id = null;
            if (is_object($user_or_null) && isset($user_or_null->ID)) { $user_id = (int) $user_or_null->ID; }
            $wpdb->insert($this->table, [
                'event_time' => current_time('mysql'),
                'user_login' => substr(sanitize_text_field((string)$user_login), 0, 60),
                'user_id'    => $user_id,
                'ip'         => substr($this->ip(), 0, 64),
                'ua'         => $this->ua(),
                'status'     => substr(sanitize_text_field($status), 0, 20),
                'reason'     => $reason,
            ], ['%s','%s','%d','%s','%s','%s','%s']);
        }

        /* -------------------- 2FA Login Flow -------------------- */

        /**
         * Authenticate filter (priority 35, after rate limits at 30).
         * If user has 2FA enabled, intercept after password check and redirect to 2FA form.
         */
        public function alg_check_2fa($user, $username, $password) {
            // If already a WP_Error (rate-limited etc.), pass through
            if (is_wp_error($user)) return $user;

            // Only intercept on actual login attempts
            if (empty($username) || empty($password)) return $user;

            // If this is a 2FA submission, don't intercept
            if (isset($_POST['alg_2fa_code']) || isset($_POST['alg_2fa_backup'])) return $user;

            // Check if user has 2FA enabled or required
            if (!is_object($user) || !isset($user->ID)) return $user;

            $opts = $this->opts();
            if (empty($opts['2fa_enabled'])) return $user;

            // Check "remember this device" cookie
            $cookie_name = 'alg_2fa_remember_' . $user->ID;
            if (isset($_COOKIE[$cookie_name])) {
                $cookie_val = $_COOKIE[$cookie_name];
                $stored = get_user_meta($user->ID, 'alg_2fa_remember_token', true);
                if ($stored && hash_equals($stored, hash('sha256', $cookie_val))) {
                    return $user; // Device remembered, skip 2FA
                }
            }

            if (!$this->alg_is_2fa_required($user)) return $user;

            // Store user ID in a signed transient for the 2FA step
            $token = wp_generate_password(32, false);
            $transient_key = 'alg_2fa_login_' . md5($token);
            set_transient($transient_key, ['user_id' => $user->ID, 'expires' => time() + 300], 300);

            // Store the token and redirect to 2FA form
            wp_redirect(add_query_arg([
                'action' => 'alg_2fa',
                'alg_token' => $token,
            ], wp_login_url()));
            exit;
        }

        /**
         * Render the 2FA input form on the login page.
         */
        public function alg_render_2fa_form() {
            $token = isset($_GET['alg_token']) ? sanitize_text_field($_GET['alg_token']) : '';
            if (!$token) {
                wp_redirect(wp_login_url());
                exit;
            }
            $transient_key = 'alg_2fa_login_' . md5($token);
            $data = get_transient($transient_key);
            if (!$data || !isset($data['user_id'])) {
                wp_redirect(wp_login_url());
                exit;
            }
            $user = get_user_by('ID', $data['user_id']);
            if (!$user) {
                wp_redirect(wp_login_url());
                exit;
            }
            ?>
            <style>
                .alg-2fa-wrap { max-width: 360px; margin: 24px auto; text-align: center; }
                .alg-2fa-wrap h2 { margin-bottom: 8px; }
                .alg-2fa-wrap p { margin-bottom: 16px; color: #555; }
                .alg-2fa-wrap input[type="text"] { font-size: 20px; letter-spacing: 4px; text-align: center; width: 100%; padding: 8px; }
                .alg-2fa-wrap .backup-link { display: block; margin-top: 12px; font-size: 13px; }
                .alg-2fa-wrap .error { color: #d63638; margin-bottom: 8px; }
                .alg-2fa-remember { margin: 12px 0; font-size: 13px; }
            </style>
            <?php if (isset($_GET['alg_error'])): ?>
                <div class="error"><p><?php _e('Invalid verification code. Please try again.', 'advanced-login-guardian'); ?></p></div>
            <?php endif; ?>
            <div class="alg-2fa-wrap">
                <h2><?php _e('Two-Factor Authentication', 'advanced-login-guardian'); ?></h2>
                <p><?php printf(__('Enter the 6-digit code from your authenticator app for <strong>%s</strong>.', 'advanced-login-guardian'), esc_html($user->user_login)); ?></p>
                <form method="post" action="<?php echo esc_url(add_query_arg(['action' => 'alg_2fa_verify'], wp_login_url())); ?>">
                    <input type="hidden" name="alg_token" value="<?php echo esc_attr($token); ?>">
                    <p>
                        <input type="text" name="alg_2fa_code" placeholder="000000" maxlength="6" pattern="\d{6}" autocomplete="one-time-code" inputmode="numeric" autofocus>
                    </p>
                    <p class="alg-2fa-remember">
                        <label>
                            <input type="checkbox" name="alg_remember" value="1">
                            <?php _e('Remember this device for 30 days', 'advanced-login-guardian'); ?>
                        </label>
                    </p>
                    <p>
                        <input type="submit" class="button button-primary button-large" style="width:100%" value="<?php esc_attr_e('Verify', 'advanced-login-guardian'); ?>">
                    </p>
                    <a href="#" class="backup-link" onclick="document.getElementById('alg-backup-form').style.display='block';this.style.display='none';return false;">
                        <?php _e('Use a backup code instead', 'advanced-login-guardian'); ?>
                    </a>
                    <div id="alg-backup-form" style="display:none; margin-top:12px;">
                        <p>
                            <input type="text" name="alg_2fa_backup" placeholder="<?php esc_attr_e('Backup code', 'advanced-login-guardian'); ?>" maxlength="8" style="text-align:center;width:100%;padding:8px;">
                        </p>
                        <p>
                            <input type="submit" class="button" style="width:100%" value="<?php esc_attr_e('Verify Backup Code', 'advanced-login-guardian'); ?>">
                        </p>
                    </div>
                </form>
            </div>
            <?php
        }

        /**
         * Verify the 2FA code submitted from the login form.
         */
        public function alg_verify_2fa() {
            $token = isset($_POST['alg_token']) ? sanitize_text_field($_POST['alg_token']) : '';
            if (!$token) { wp_redirect(wp_login_url()); exit; }

            $transient_key = 'alg_2fa_login_' . md5($token);
            $data = get_transient($transient_key);
            if (!$data || !isset($data['user_id'])) {
                wp_redirect(wp_login_url());
                exit;
            }

            $user_id = $data['user_id'];
            $user = get_user_by('ID', $user_id);
            if (!$user) {
                wp_redirect(wp_login_url());
                exit;
            }

            $secret = get_user_meta($user_id, 'alg_2fa_secret', true);
            $code = isset($_POST['alg_2fa_code']) ? sanitize_text_field($_POST['alg_2fa_code']) : '';
            $backup = isset($_POST['alg_2fa_backup']) ? sanitize_text_field($_POST['alg_2fa_backup']) : '';
            $remember = !empty($_POST['alg_remember']);

            $verified = false;
            if ($code && $secret) {
                $verified = $this->alg_verify_totp($secret, $code);
            }
            if (!$verified && $backup) {
                $verified = $this->alg_verify_backup_code($user_id, $backup);
                if ($verified) {
                    $this->log_event($user, $user->user_login, $this->ip(), 'success', 'Login with 2FA backup code');
                }
            }

            if (!$verified) {
                // Re-show the 2FA form with error
                wp_redirect(add_query_arg([
                    'action' => 'alg_2fa',
                    'alg_token' => $token,
                    'alg_error' => '1',
                ], wp_login_url()));
                exit;
            }

            // Success — clean up and log user in
            delete_transient($transient_key);

            // Set "remember this device" cookie if requested
            if ($remember) {
                $opts = $this->opts();
                $days = intval($opts['2fa_remember_days'] ?? 30);
                $cookie_val = wp_generate_password(32, false);
                $cookie_name = 'alg_2fa_remember_' . $user_id;
                setcookie($cookie_name, $cookie_val, time() + ($days * DAY_IN_SECONDS), COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
                update_user_meta($user_id, 'alg_2fa_remember_token', hash('sha256', $cookie_val));
            }

            $this->log_event($user, $user->user_login, $this->ip(), 'success', 'Login with 2FA');

            // Log the user in
            wp_set_auth_cookie($user_id, true);
            $redirect = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : admin_url();
            wp_redirect($redirect);
            exit;
        }

        /**
         * Enqueue scripts for the 2FA login page.
         */
        public function alg_2fa_login_scripts() {
            if (isset($_GET['action']) && $_GET['action'] === 'alg_2fa') {
                ?>
                <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var codeInput = document.querySelector('input[name="alg_2fa_code"]');
                    if (codeInput) {
                        codeInput.focus();
                        // Auto-submit when 6 digits entered
                        codeInput.addEventListener('input', function() {
                            this.value = this.value.replace(/\D/g, '');
                            if (this.value.length === 6) {
                                this.form.submit();
                            }
                        });
                    }
                });
                </script>
                <?php
            }
        }

        /* -------------------- User Profile 2FA -------------------- */

        /**
         * Render the 2FA section on user profile.
         */
        public function render_2fa_profile($user) {
            if (!current_user_can("edit_user", $user->ID) && !current_user_can("manage_options")) return;
            $enabled = $this->alg_is_2fa_enabled($user->ID);
            $backup  = get_user_meta($user->ID, "alg_2fa_backup_codes", true);
            $nonce   = wp_create_nonce("alg_2fa_profile_" . $user->ID);
            ?>
            <h2><?php _e("Two-Factor Authentication", "advanced-login-guardian"); ?></h2>
            <table class="form-table" id="alg-2fa-profile">
                <tr>
                    <th><?php _e("2FA Status", "advanced-login-guardian"); ?></th>
                    <td>
                        <?php if ($enabled): ?>
                            <span style="color:#00a32a;font-weight:600"><?php _e("Enabled", "advanced-login-guardian"); ?></span>
                            <p class="description"><?php _e("Two-factor authentication is active for this account.", "advanced-login-guardian"); ?></p>
                        <?php else: ?>
                            <span style="color:#d63638;font-weight:600"><?php _e("Disabled", "advanced-login-guardian"); ?></span>
                            <p class="description"><?php _e("Set up 2FA to secure this account.", "advanced-login-guardian"); ?></p>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php if (!$enabled): ?>
                <tr id="alg-2fa-setup-row">
                    <th><?php _e("Setup 2FA", "advanced-login-guardian"); ?></th>
                    <td>
                        <p><?php _e("1. Click the button below to generate a secret key.", "advanced-login-guardian"); ?></p>
                        <p><?php _e("2. Scan the QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.).", "advanced-login-guardian"); ?></p>
                        <div id="alg-qr-container" style="margin:12px 0;display:none;">
                            <canvas id="alg-qr-canvas"></canvas>
                            <p style="word-break:break-all;font-size:12px;color:#555;margin-top:8px;">
                                <?php _e("Or enter this secret manually:", "advanced-login-guardian"); ?>
                                <strong id="alg-secret-display"></strong>
                            </p>
                        </div>
                        <button type="button" class="button" id="alg-gen-secret" data-nonce="<?php echo esc_attr($nonce); ?>" data-user="<?php echo esc_attr($user->ID); ?>">
                            <?php _e("Generate Secret & QR Code", "advanced-login-guardian"); ?>
                        </button>
                        <p class="description"><?php _e("After generating, scan the QR code and enter the 6-digit code below to verify.", "advanced-login-guardian"); ?></p>
                        <div id="alg-verify-row" style="display:none;margin-top:12px;">
                            <p>
                                <input type="text" id="alg-verify-code" placeholder="000000" maxlength="6" pattern="\d{6}" style="font-size:16px;letter-spacing:2px;padding:4px;text-align:center;">
                                <input type="hidden" id="alg-secret-value" value="">
                                <input type="hidden" id="alg-backup-plain" value="">
                            </p>
                            <p id="alg-backup-display" style="display:none;">
                                <strong><?php _e("Backup Codes:", "advanced-login-guardian"); ?></strong><br>
                                <code id="alg-backup-codes" style="display:block;margin-top:8px;padding:8px;background:#f6f7f7;border:1px solid #ddd;font-size:13px;line-height:1.8"></code>
                                <span class="description"><?php _e("Save these codes! Each can be used once to log in if you lose your device.", "advanced-login-guardian"); ?></span>
                            </p>
                            <button type="button" class="button button-primary" id="alg-enable-2fa" data-nonce="<?php echo esc_attr($nonce); ?>" data-user="<?php echo esc_attr($user->ID); ?>">
                                <?php _e("Verify & Enable 2FA", "advanced-login-guardian"); ?>
                            </button>
                            <span id="alg-verify-msg" style="margin-left:8px;"></span>
                        </div>
                    </td>
                </tr>
                <?php else: ?>
                <tr>
                    <th><?php _e("Backup Codes", "advanced-login-guardian"); ?></th>
                    <td>
                        <?php
                        $codes_remaining = is_array($backup) ? count($backup) : 0;
                        echo "<p>" . sprintf(__("%d backup codes remaining.", "advanced-login-guardian"), $codes_remaining) . "</p>";
                        ?>
                        <button type="button" class="button" id="alg-regen-backup" data-user="<?php echo esc_attr($user->ID); ?>" data-nonce="<?php echo esc_attr(wp_create_nonce("alg_regen_backup_" . $user->ID)); ?>">
                            <?php _e("Regenerate Backup Codes", "advanced-login-guardian"); ?>
                        </button>
                        <span id="alg-backup-msg"></span>
                    </td>
                </tr>
                <tr>
                    <th><?php _e("Disable 2FA", "advanced-login-guardian"); ?></th>
                    <td>
                        <button type="button" class="button" id="alg-disable-2fa" data-user="<?php echo esc_attr($user->ID); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">
                            <?php _e("Disable 2FA", "advanced-login-guardian"); ?>
                        </button>
                        <p class="description"><?php _e("This will remove 2FA protection from this account.", "advanced-login-guardian"); ?></p>
                    </td>
                </tr>
                <?php endif; ?>
            </table>
            <?php
        }

        /**
         * Save 2FA profile settings (handled via AJAX, this is a fallback).
         */
        public function save_2fa_profile($user_id) {
            if (!current_user_can("edit_user", $user_id) && !current_user_can("manage_options")) return;
            if (isset($_POST["alg_2fa_disable"]) && $_POST["alg_2fa_disable"]) {
                delete_user_meta($user_id, "alg_2fa_enabled");
                delete_user_meta($user_id, "alg_2fa_secret");
                delete_user_meta($user_id, "alg_2fa_backup_codes");
                delete_user_meta($user_id, "alg_2fa_remember_token");
            }
        }

        /* -------------------- Admin UI -------------------- */
        public function admin_menu() {
            add_menu_page(
                __('Login Guardian', 'wp-login-guardian'),
                __('Login Guardian', 'wp-login-guardian'),
                'manage_options',
                'alg',
                [$this, 'render_admin'],
                'dashicons-shield-alt',
                81
            );
        }

        public function admin_enqueue_assets($hook) {
            if ($hook !== 'toplevel_page_alg') {
                return;
            }
            wp_enqueue_style('alg-admin-css', plugin_dir_url(__FILE__) . 'assets/css/admin.css', [], '1.0.0');
            wp_enqueue_script('alg-admin-js', plugin_dir_url(__FILE__) . 'assets/js/admin.js', [], '1.0.0', true);
        }

        public function register_settings() {
            register_setting('alg_settings', $this->options_key, [
                'sanitize_callback' => function($opts){ return $this->sanitize_options($opts); }
            ]);
        }

        private function sanitize_options($opts) {
            $def = $this->default_options();
            $san = [];
            $san['window_sec'] = max(60, intval($opts['window_sec'] ?? $def['window_sec']));
            $san['max_attempts'] = max(1, intval($opts['max_attempts'] ?? $def['max_attempts']));
            $san['lockout_sec'] = max(60, intval($opts['lockout_sec'] ?? $def['lockout_sec']));
            $san['hard_lock_threshold'] = max(5, intval($opts['hard_lock_threshold'] ?? $def['hard_lock_threshold']));
            $san['notify_email'] = sanitize_email($opts['notify_email'] ?? $def['notify_email']);
            $san['notify_on_lockout'] = empty($opts['notify_on_lockout']) ? 0 : 1;
            $san['whitelist_ips'] = trim(wp_kses_post($opts['whitelist_ips'] ?? ''));
            $san['blacklist_ips'] = trim(wp_kses_post($opts['blacklist_ips'] ?? ''));
            $san['log_retention_days'] = max(7, intval($opts['log_retention_days'] ?? $def['log_retention_days']));
            $san['custom_login_msg'] = wp_kses_post($opts['custom_login_msg'] ?? '');
            $san['login_logo_url'] = esc_url_raw($opts['login_logo_url'] ?? '');
            $san['login_bg'] = sanitize_hex_color($opts['login_bg'] ?? $def['login_bg']);
            $san['login_button'] = sanitize_hex_color($opts['login_button'] ?? $def['login_button']);

            // Reporting options
            $san['enable_abuseipdb'] = empty($opts['enable_abuseipdb']) ? 0 : 1;
            $san['abuseipdb_api_key'] = sanitize_text_field($opts['abuseipdb_api_key'] ?? '');
            $san['abuseipdb_categories'] = sanitize_text_field($opts['abuseipdb_categories'] ?? '18,22');
            $san['enable_spamhaus'] = empty($opts['enable_spamhaus']) ? 0 : 1;
            $san['spamhaus_api_key'] = sanitize_text_field($opts['spamhaus_api_key'] ?? '');
            $allowed_threats = ['attack', 'spam', 'bulletproof', 'hijacked-network'];
            $san['spamhaus_threat_type'] = in_array($opts['spamhaus_threat_type'] ?? '', $allowed_threats, true) ? $opts['spamhaus_threat_type'] : 'attack';
            $san['default_report_comment'] = sanitize_text_field($opts['default_report_comment'] ?? 'Unauthorized login attempt / brute force attack detected');
            $san['auto_report_on_lockout'] = empty($opts['auto_report_on_lockout']) ? 0 : 1;
            $san['auto_report_on_block'] = empty($opts['auto_report_on_block']) ? 0 : 1;
            return $san;
        }

        public function render_admin() {
            if (!current_user_can('manage_options')) { return; }
            $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'dashboard';
            $allowed_tabs = ['dashboard', 'monitor', 'rate', 'custom', 'lists', 'reporting'];
            if (!in_array($active_tab, $allowed_tabs, true)) {
                $active_tab = 'dashboard';
            }
            $opts = $this->opts();
            ?>
            <div class="wrap op-wrap">
                <header class="op-header">
                    <div class="op-header-main">
                        <div class="op-header-title-row">
                            <div class="op-header-icon" style="background:linear-gradient(135deg,#0284c7,#0369a1);" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                                </svg>
                            </div>
                            <h1 class="op-header-title"><?php esc_html_e('Login Guardian', 'wp-login-guardian'); ?></h1>
                            <span class="op-header-badge">v1.0.0</span>
                            <span class="op-badge op-badge-success"><span class="op-badge-dot"></span> <?php esc_html_e('Shield Active', 'wp-login-guardian'); ?></span>
                        </div>
                        <p class="op-header-subtitle"><?php esc_html_e('Advanced login security, brute-force rate limiting, 2FA, IP management, and threat reporting.', 'wp-login-guardian'); ?></p>
                    </div>
                    <div class="op-header-actions">
                        <button type="button" class="op-btn op-btn-secondary" onclick="OpcodesUI.toast({message: 'Threat telemetry feeds synced', type: 'info'})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                            <?php esc_html_e('Sync Telemetry', 'wp-login-guardian'); ?>
                        </button>
                    </div>
                </header>

                <nav class="op-nav-tabs" role="tablist" aria-label="<?php esc_attr_e('Login Guardian Sections', 'wp-login-guardian'); ?>">
                    <?php
                    $tabs = [
                        'dashboard' => ['label' => __('Dashboard', 'wp-login-guardian'), 'icon' => '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>'],
                        'monitor'   => ['label' => __('Activity Monitor', 'wp-login-guardian'), 'icon' => '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>'],
                        'rate'      => ['label' => __('Rate Limiting', 'wp-login-guardian'), 'icon' => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/>'],
                        'custom'    => ['label' => __('Login Customization', 'wp-login-guardian'), 'icon' => '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>'],
                        'lists'     => ['label' => __('IP Lists', 'wp-login-guardian'), 'icon' => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'],
                        'reporting' => ['label' => __('API Reporting', 'wp-login-guardian'), 'icon' => '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>'],
                    ];
                    foreach ($tabs as $slug => $tab_data) {
                        $cls = ($active_tab === $slug) ? ' is-active' : '';
                        $aria = ($active_tab === $slug) ? 'true' : 'false';
                        echo '<a class="op-nav-tab'.$cls.'" role="tab" aria-selected="'.$aria.'" href="'.esc_url(admin_url('admin.php?page=alg&tab='.$slug)).'">';
                        echo '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'.$tab_data['icon'].'</svg> ';
                        echo esc_html($tab_data['label']);
                        echo '</a>';
                    }
                    ?>
                </nav>

                <div id="alg-content" class="op-tab-pane">
                    <?php
                    switch ($active_tab) {
                        case 'dashboard': $this->render_dashboard(); break;
                        case 'monitor':   $this->render_monitor(); break;
                        case 'rate':      $this->render_rate_form($opts); break;
                        case 'custom':    $this->render_custom_form($opts); break;
                        case 'lists':     $this->render_lists_form($opts); break;
                        case 'reporting': $this->render_reporting_form($opts); break;
                    }
                    ?>
                </div>
            </div>
            <?php
        }

        private function render_dashboard() {
            $stats = $this->get_stats_last_24h();
            ?>
            <div class="op-cards" role="region" aria-label="<?php esc_attr_e('Authentication Statistics', 'wp-login-guardian'); ?>">
                <div class="op-card">
                    <div class="op-card-top">
                        <div class="op-card-icon" style="background:var(--op-success-bg);color:var(--op-success-icon);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                        </div>
                        <span class="op-trend-pill op-trend-up">Normal</span>
                    </div>
                    <div class="op-card-num"><?php echo esc_html(intval($stats['success'] ?? 0)); ?></div>
                    <div class="op-card-label"><?php esc_html_e('Successful Logins (24h)', 'wp-login-guardian'); ?></div>
                </div>

                <div class="op-card">
                    <div class="op-card-top">
                        <div class="op-card-icon" style="background:var(--op-warning-bg);color:var(--op-warning-icon);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        </div>
                        <span class="op-trend-pill op-trend-neutral">Tracked</span>
                    </div>
                    <div class="op-card-num"><?php echo esc_html(intval($stats['failed'] ?? 0)); ?></div>
                    <div class="op-card-label"><?php esc_html_e('Failed Password Attempts', 'wp-login-guardian'); ?></div>
                </div>

                <div class="op-card">
                    <div class="op-card-top">
                        <div class="op-card-icon" style="background:var(--op-danger-bg);color:var(--op-danger-icon);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        </div>
                        <span class="op-trend-pill op-trend-down">Mitigated</span>
                    </div>
                    <div class="op-card-num"><?php echo esc_html(intval($stats['lockout'] ?? 0)); ?></div>
                    <div class="op-card-label"><?php esc_html_e('Rate Lockouts Enforced', 'wp-login-guardian'); ?></div>
                </div>

                <div class="op-card">
                    <div class="op-card-top">
                        <div class="op-card-icon" style="background:var(--op-primary-50);color:var(--op-primary-600);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                        </div>
                        <span class="op-badge op-badge-danger">Active</span>
                    </div>
                    <div class="op-card-num"><?php echo esc_html(intval($stats['blocked'] ?? 0)); ?></div>
                    <div class="op-card-label"><?php esc_html_e('Blocked Attacks', 'wp-login-guardian'); ?></div>
                </div>
            </div>

            <div class="op-grid-2col">
                <div class="op-panel">
                    <div class="op-panel-header">
                        <h2 class="op-panel-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/></svg>
                            <?php esc_html_e('Activity Monitor', 'wp-login-guardian'); ?>
                        </h2>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=alg&tab=monitor')); ?>" class="op-btn op-btn-ghost op-btn-sm"><?php esc_html_e('View Live Feed &rarr;', 'wp-login-guardian'); ?></a>
                    </div>
                    <div class="op-panel-body">
                        <p class="op-help-text" style="margin:0 0 16px 0;"><?php esc_html_e('Real-time authentication event logging with instant search, status filtering, and threat reporting.', 'wp-login-guardian'); ?></p>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=alg&tab=monitor')); ?>" class="op-btn op-btn-primary">
                            <?php esc_html_e('Open Activity Monitor', 'wp-login-guardian'); ?>
                        </a>
                    </div>
                </div>

                <div class="op-panel">
                    <div class="op-panel-header">
                        <h2 class="op-panel-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <?php esc_html_e('Security Protection Status', 'wp-login-guardian'); ?>
                        </h2>
                        <span class="op-badge op-badge-success">Enforced</span>
                    </div>
                    <div class="op-panel-body">
                        <ul style="margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:12px;">
                            <li style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px;border-bottom:1px solid var(--op-border-subtle);">
                                <span><?php esc_html_e('Brute-Force Rate Limiting', 'wp-login-guardian'); ?></span>
                                <span class="op-badge op-badge-success"><?php esc_html_e('Active', 'wp-login-guardian'); ?></span>
                            </li>
                            <li style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px;border-bottom:1px solid var(--op-border-subtle);">
                                <span><?php esc_html_e('Two-Factor Authentication (2FA)', 'wp-login-guardian'); ?></span>
                                <span class="op-badge op-badge-info"><?php esc_html_e('Configured', 'wp-login-guardian'); ?></span>
                            </li>
                            <li style="display:flex;justify-content:space-between;align-items:center;">
                                <span><?php esc_html_e('Threat Intelligence (AbuseIPDB/Spamhaus)', 'wp-login-guardian'); ?></span>
                                <span class="op-badge op-badge-neutral"><?php esc_html_e('Ready', 'wp-login-guardian'); ?></span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <?php
        }

        private function render_monitor() {
            if (!current_user_can('manage_options')) return;
            $nonce = wp_create_nonce('alg_monitor');
            ?>
            <div class="op-panel">
                <div class="op-panel-header">
                    <h2 class="op-panel-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/></svg>
                        <?php esc_html_e('Authentication Event Log', 'wp-login-guardian'); ?>
                    </h2>
                    <div class="op-table-filter-group">
                        <input type="text" id="alg-search" class="op-input" style="width:240px;" placeholder="<?php esc_attr_e('Search user, IP, UA...', 'wp-login-guardian'); ?>">
                        <select id="alg-status" class="op-select" style="width:140px;">
                            <option value=""><?php esc_html_e('All statuses', 'wp-login-guardian'); ?></option>
                            <option value="success">Success</option>
                            <option value="failed">Failed</option>
                            <option value="lockout">Lockout</option>
                            <option value="blocked">Blocked</option>
                        </select>
                        <button type="button" class="op-btn op-btn-secondary op-btn-sm" id="alg-refresh" data-nonce="<?php echo esc_attr($nonce); ?>">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                            <?php esc_html_e('Refresh', 'wp-login-guardian'); ?>
                        </button>
                        <button type="button" class="op-btn op-btn-secondary op-btn-sm" id="alg-export">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            <?php esc_html_e('Export CSV', 'wp-login-guardian'); ?>
                        </button>
                        <button type="button" class="op-btn op-btn-danger op-btn-sm" id="alg-purge" data-nonce="<?php echo esc_attr(wp_create_nonce('alg_purge')); ?>">
                            <?php esc_html_e('Purge Old Logs', 'wp-login-guardian'); ?>
                        </button>
                    </div>
                </div>
                <div id="alg-table"></div>
            </div>
            <?php
        }

        private function render_rate_form($opts) {
            echo '<form method="post" action="options.php">';
            settings_fields('alg_settings');
            echo '<table class="form-table"><tbody>';
            $this->number_row('window_sec','Window (seconds)','How long to count attempts.');
            $this->number_row('max_attempts','Max attempts in window','Lock after this many failures.');
            $this->number_row('lockout_sec','Lockout (seconds)','How long an IP is locked.');
            $this->number_row('hard_lock_threshold','24h escalation threshold','Escalate lock when failures exceed this in 24h.');
            $this->text_row('notify_email','Notify email','Receive lockout notifications.');
            $this->checkbox_row('notify_on_lockout','Email on lockout');
            echo '</tbody></table>';
            submit_button();
            echo '</form>';
        }

        private function render_custom_form($opts) {
            echo '<form method="post" action="options.php">';
            settings_fields('alg_settings');
            echo '<table class="form-table"><tbody>';
            $this->text_row('login_logo_url','Login logo URL','SVG/PNG recommended.');
            $this->text_row('custom_login_msg','Login message (HTML allowed)','Shown above the login form.');
            $this->text_row('login_bg','Login background color (hex)','');
            $this->text_row('login_button','Login button color (hex)','');
            echo '</tbody></table>';
            submit_button();
            echo '</form>';
        }

        private function render_lists_form($opts) {
            echo '<form method="post" action="options.php">';
            settings_fields('alg_settings');
            echo '<table class="form-table"><tbody>';
            $this->textarea_row('whitelist_ips','Whitelist IPs / ranges','One per line. Supports wildcards like 10.0.*');
            $this->textarea_row('blacklist_ips','Blacklist IPs / ranges','One per line. Supports wildcards like 203.0.113.*');
            $this->number_row('log_retention_days','Log retention (days)','Older entries will be purged.');
            echo '</tbody></table>';
            submit_button();
            echo '</form>';

            echo '<hr /><h2>'.esc_html__('Quick block/unblock/report','advanced-login-guardian').'</h2>';
            $nonce = wp_create_nonce('alg_block');
            echo '<p><input type="text" id="alg-ip" placeholder="'.esc_attr__('IP to block/unblock/report','advanced-login-guardian').'"> ';
            echo '<button class="button" id="alg-block" data-nonce="'.esc_attr($nonce).'">'.__('Block IP','advanced-login-guardian').'</button> ';
            echo '<button class="button" id="alg-unblock" data-nonce="'.esc_attr(wp_create_nonce('alg_unblock')).'">'.__('Unblock IP','advanced-login-guardian').'</button> ';
            echo '<button class="button button-secondary" id="alg-report-quick" data-nonce="'.esc_attr(wp_create_nonce('alg_report')).'">'.__('Report IP','advanced-login-guardian').'</button></p>';
        }

        private function number_row($key, $label, $desc) {
            $opts = $this->opts();
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<input name="'.$this->options_key.'['.$key.']" id="'.$key.'" type="number" value="'.esc_attr($opts[$key]).'" class="regular-text">';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }
        private function text_row($key, $label, $desc) {
            $opts = $this->opts();
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<input name="'.$this->options_key.'['.$key.']" id="'.$key.'" type="text" value="'.esc_attr($opts[$key]).'" class="regular-text">';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }
        private function textarea_row($key, $label, $desc) {
            $opts = $this->opts();
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<textarea name="'.$this->options_key.'['.$key.']" id="'.$key.'" class="large-text code" rows="6">'.esc_textarea($opts[$key]).'</textarea>';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }

        private function render_reporting_form($opts) {
            echo '<form method="post" action="options.php">';
            settings_fields('alg_settings');
            echo '<h2>'.esc_html__('AbuseIPDB Integration', 'advanced-login-guardian').'</h2>';
            echo '<table class="form-table"><tbody>';
            $this->checkbox_row('enable_abuseipdb', 'Enable AbuseIPDB Auto Reporting', 'Automatically submit offending IP addresses to AbuseIPDB via API.');
            $this->password_row('abuseipdb_api_key', 'AbuseIPDB API Key', 'Get your API Key from your AbuseIPDB account dashboard.');
            $this->text_row('abuseipdb_categories', 'AbuseIPDB Category IDs', 'Comma-separated category IDs. Default is 18,22 (18 = Brute-Force, 22 = Web App Attack).');
            echo '</tbody></table>';

            echo '<hr /><h2>'.esc_html__('Spamhaus Integration', 'advanced-login-guardian').'</h2>';
            echo '<table class="form-table"><tbody>';
            $this->checkbox_row('enable_spamhaus', 'Enable Spamhaus Auto Reporting', 'Automatically report IP signals to Spamhaus via API.');
            $this->password_row('spamhaus_api_key', 'Spamhaus API Token', 'Your Spamhaus API Token or Key.');
            $this->select_row('spamhaus_threat_type', 'Spamhaus Threat Type', [
                'attack'           => 'Attack (Login Brute Force / Web Attack)',
                'spam'             => 'Spam',
                'bulletproof'      => 'Bulletproof Hosting',
                'hijacked-network' => 'Hijacked Network',
            ], 'Threat type code for IP submission from Spamhaus API docs.');
            echo '</tbody></table>';

            echo '<hr /><h2>'.esc_html__('Default Comment & Triggers', 'advanced-login-guardian').'</h2>';
            echo '<table class="form-table"><tbody>';
            $this->text_row('default_report_comment', 'Default Report Comment', 'Default comment included with automated and manual IP reports.');
            $this->checkbox_row('auto_report_on_lockout', 'Auto Report on Lockout', 'Automatically trigger IP report when an IP reaches maximum failed login attempts.');
            $this->checkbox_row('auto_report_on_block', 'Auto Report on Manual/Blacklist Block', 'Automatically trigger IP report when an IP is added to the blacklist or manually blocked.');
            echo '</tbody></table>';

            submit_button();
            echo '</form>';
        }

        private function checkbox_row($key, $label, $desc = '') {
            $opts = $this->opts();
            $checked = !empty($opts[$key]) ? 'checked' : '';
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<label><input name="'.$this->options_key.'['.$key.']" id="'.$key.'" type="checkbox" value="1" '.$checked.'> '.esc_html($label).'</label>';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }

        private function password_row($key, $label, $desc = '') {
            $opts = $this->opts();
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<input name="'.$this->options_key.'['.$key.']" id="'.$key.'" type="password" value="'.esc_attr($opts[$key] ?? '').'" class="regular-text" autocomplete="off">';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }

        private function select_row($key, $label, array $options, $desc = '') {
            $opts = $this->opts();
            $val = $opts[$key] ?? '';
            echo '<tr><th scope="row"><label for="'.$key.'">'.esc_html($label).'</label></th><td>';
            echo '<select name="'.$this->options_key.'['.$key.']" id="'.$key.'">';
            foreach ($options as $opt_val => $opt_label) {
                $sel = ($val === (string)$opt_val) ? 'selected' : '';
                echo '<option value="'.esc_attr($opt_val).'" '.$sel.'>'.esc_html($opt_label).'</option>';
            }
            echo '</select>';
            if ($desc) echo '<p class="description">'.esc_html($desc).'</p>';
            echo '</td></tr>';
        }

        /* -------------------- API Abuse Reporting -------------------- */
        public function async_report_ip(string $ip, string $reason) {
            $this->execute_ip_reports($ip, $reason);
        }

        public function ajax_report_ip() {
            if (!current_user_can('manage_options')) wp_send_json_error('forbidden');
            check_ajax_referer('alg_report');
            $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
            if (!$ip) wp_send_json_error('No IP provided.');
            $opts = $this->opts();
            $default_comment = $opts['default_report_comment'] ?? 'Unauthorized login attempt / brute force attack detected';
            $comment = !empty($_POST['comment']) ? sanitize_text_field($_POST['comment']) : $default_comment;
            $results = $this->execute_ip_reports($ip, $comment, true);
            wp_send_json_success($results);
        }

        private function trigger_auto_report(string $ip, string $reason = '') {
            $opts = $this->opts();
            if (empty($opts['enable_abuseipdb']) && empty($opts['enable_spamhaus'])) {
                return;
            }
            if (empty($reason)) {
                $reason = $opts['default_report_comment'] ?? 'Unauthorized login attempt / brute force attack detected';
            }
            if (!wp_next_scheduled('alg_async_report_ip', [$ip, $reason])) {
                wp_schedule_single_event(time(), 'alg_async_report_ip', [$ip, $reason]);
            }
        }

        public function execute_ip_reports(string $ip, string $reason, bool $force = false) : array {
            $opts = $this->opts();
            $results = [];

            // AbuseIPDB Report
            if (!empty($opts['enable_abuseipdb']) && !empty($opts['abuseipdb_api_key'])) {
                $transient = 'alg_rpt_abuse_' . md5($ip);
                if ($force || !get_transient($transient)) {
                    $res = $this->report_ip_to_abuseipdb($ip, $opts['abuseipdb_api_key'], $opts['abuseipdb_categories'] ?? '18,22', $reason);
                    $results['abuseipdb'] = $res;
                    if (!empty($res['success'])) {
                        set_transient($transient, 1, DAY_IN_SECONDS);
                    }
                } else {
                    $results['abuseipdb'] = ['success' => false, 'message' => __('Already reported to AbuseIPDB recently.', 'advanced-login-guardian')];
                }
            }

            // Spamhaus Report
            if (!empty($opts['enable_spamhaus']) && !empty($opts['spamhaus_api_key'])) {
                $transient = 'alg_rpt_spam_' . md5($ip);
                if ($force || !get_transient($transient)) {
                    $res = $this->report_ip_to_spamhaus($ip, $opts['spamhaus_api_key'], $reason);
                    $results['spamhaus'] = $res;
                    if (!empty($res['success'])) {
                        set_transient($transient, 1, DAY_IN_SECONDS);
                    }
                } else {
                    $results['spamhaus'] = ['success' => false, 'message' => __('Already reported to Spamhaus recently.', 'advanced-login-guardian')];
                }
            }

            return $results;
        }

        private function report_ip_to_abuseipdb(string $ip, string $api_key, string $categories, string $reason) : array {
            $url = 'https://api.abuseipdb.com/api/v2/report';
            $response = wp_remote_post($url, [
                'timeout' => 8,
                'headers' => [
                    'Key' => $api_key,
                    'Accept' => 'application/json',
                ],
                'body' => [
                    'ip' => $ip,
                    'categories' => $categories ?: '18,22',
                    'comment' => sprintf('Login Guardian: %s', substr($reason, 0, 200)),
                ],
            ]);

            if (is_wp_error($response)) {
                return ['success' => false, 'message' => $response->get_error_message()];
            }
            $code = wp_remote_retrieve_response_code($response);
            $raw_body = wp_remote_retrieve_body($response);
            $body = json_decode($raw_body, true);

            if ($code >= 200 && $code < 300) {
                return ['success' => true, 'message' => __('Successfully reported to AbuseIPDB', 'advanced-login-guardian'), 'data' => $body];
            }
            if ($code === 404) {
                return ['success' => false, 'message' => __('AbuseIPDB API returned 404 (Not Found). Please check API endpoint or account permissions.', 'advanced-login-guardian')];
            }
            $err_msg = isset($body['errors'][0]['detail']) ? $body['errors'][0]['detail'] : sprintf(__('AbuseIPDB HTTP error %d', 'advanced-login-guardian'), $code);
            return ['success' => false, 'message' => $err_msg];
        }

        private function report_ip_to_spamhaus(string $ip, string $api_key, string $reason) : array {
            $opts = $this->opts();
            $url = 'https://submit.spamhaus.org/portal/api/v1/submissions/add/ip';
            $allowed_threats = ['attack', 'spam', 'bulletproof', 'hijacked-network'];
            $threat_type = in_array($opts['spamhaus_threat_type'] ?? '', $allowed_threats, true) ? $opts['spamhaus_threat_type'] : 'attack';
            $payload = wp_json_encode([
                'threat_type' => $threat_type,
                'reason'      => substr($reason, 0, 255),
                'source'      => [
                    'object' => $ip,
                ],
            ]);
            $response = wp_remote_post($url, [
                'timeout' => 8,
                'headers' => [
                    'Authorization' => 'Bearer ' . $api_key,
                    'Content-Type'  => 'application/json',
                    'Accept'        => 'application/json',
                ],
                'body' => $payload,
            ]);

            if (is_wp_error($response)) {
                return ['success' => false, 'message' => $response->get_error_message()];
            }
            $code = wp_remote_retrieve_response_code($response);
            $raw_body = wp_remote_retrieve_body($response);
            $body = json_decode($raw_body, true);

            if ($code >= 200 && $code < 300) {
                if ($code === 208 || (isset($body['status']) && $body['status'] == 208)) {
                    return ['success' => true, 'message' => __('Already reported to Spamhaus recently.', 'advanced-login-guardian'), 'data' => $body];
                }
                return ['success' => true, 'message' => __('Successfully reported to Spamhaus', 'advanced-login-guardian'), 'data' => $body];
            }

            if ($code === 208 || (isset($body['status']) && $body['status'] == 208)) {
                return ['success' => true, 'message' => __('Submission already reported to Spamhaus.', 'advanced-login-guardian'), 'data' => $body];
            }
            if ($code === 400 || (isset($body['status']) && $body['status'] == 400)) {
                $msg = isset($body['message']) ? $body['message'] : __('Invalid IP address or request parameters.', 'advanced-login-guardian');
                return ['success' => false, 'message' => 'Spamhaus API: ' . $msg];
            }
            if ($code === 401 || $code === 403) {
                return ['success' => false, 'message' => __('Spamhaus API authentication failed. Please verify your API Bearer Token.', 'advanced-login-guardian')];
            }
            if ($code === 404) {
                return ['success' => false, 'message' => __('Spamhaus API endpoint returned 404 (Not Found).', 'advanced-login-guardian')];
            }

            $err_msg = isset($body['message']) ? $body['message'] : (isset($body['error']) ? $body['error'] : sprintf(__('Spamhaus HTTP error %d', 'advanced-login-guardian'), $code));
            return ['success' => false, 'message' => $err_msg];
        }

        /* -------------------- Login page branding -------------------- */
        public function login_branding() {
            $o = $this->opts();
            $bg = esc_attr($o['login_bg']);
            $btn = esc_attr($o['login_button']);
            $logo = esc_url($o['login_logo_url']);
            echo '<style>body.login { background: '.$bg.' !important; }';
            if ($logo) {
                echo '#login h1 a { background-image:url('.$logo.') !important; background-size:contain !important; width:100% !important; }';
            }
            echo '.button-primary{ background-color: '.$btn.' !important; border-color: '.$btn.' !important; }';
            echo '</style>';
        }
        public function login_custom_message($msg) {
            $o = $this->opts();
            if (!empty($o['custom_login_msg'])) {
                $msg .= '<div class="notice notice-info alg-login-msg">'.$o['custom_login_msg'].'</div>';
            }
            return $msg;
        }

        /* -------------------- AJAX & REST -------------------- */
        public function ajax_fetch_logs() {
            if (!current_user_can('manage_options')) wp_send_json_error('forbidden');
            check_ajax_referer('alg_monitor');
            global $wpdb;
            $status = isset($_POST['status']) ? sanitize_text_field($_POST['status']) : '';
            $s = isset($_POST['s']) ? sanitize_text_field($_POST['s']) : '';
            $page = max(1, intval($_POST['page'] ?? 1));
            $per  = min(200, max(10, intval($_POST['per'] ?? 25)));
            $off  = ($page-1)*$per;

            $where = 'WHERE 1=1';
            $params = [];
            if ($status) { $where .= ' AND status = %s'; $params[] = $status; }
            if ($s) {
                $like = '%' . $wpdb->esc_like($s) . '%';
                $where .= ' AND (user_login LIKE %s OR ip LIKE %s OR ua LIKE %s)';
                $params[] = $like; $params[] = $like; $params[] = $like;
            }

            $sql = "SELECT SQL_CALC_FOUND_ROWS id, event_time, user_login, user_id, ip, status, LEFT(ua,120) AS ua, LEFT(reason,120) AS reason
                    FROM {$this->table} $where ORDER BY id DESC LIMIT %d OFFSET %d";
            $params[] = $per; $params[] = $off;
            $rows = $wpdb->get_results($wpdb->prepare($sql, $params), ARRAY_A);
            $total = (int) $wpdb->get_var('SELECT FOUND_ROWS()');

            // Build CSV when requested
            if (!empty($_POST['export'])) {
                $csv = fopen('php://temp','w+');
                fputcsv($csv, array_keys($rows ? $rows[0] : ['id','event_time','user_login','user_id','ip','status','ua','reason']));
                foreach ($rows as $r) { fputcsv($csv, $r); }
                rewind($csv);
                $data = stream_get_contents($csv);
                fclose($csv);
                wp_send_json_success(['csv'=>base64_encode($data), 'filename'=>'alg-logs-'.date('Ymd-His').'.csv']);
            }

            wp_send_json_success(['rows'=>$rows, 'total'=>$total, 'page'=>$page, 'per'=>$per]);
        }

        public function ajax_purge_logs() {
            if (!current_user_can('manage_options')) wp_send_json_error('forbidden');
            check_ajax_referer('alg_purge');
            $days = max(1, intval($this->opts()['log_retention_days']));
            global $wpdb;
            $wpdb->query($wpdb->prepare("DELETE FROM {$this->table} WHERE event_time < (NOW() - INTERVAL %d DAY)", $days));
            wp_send_json_success(['purged'=>true]);
        }        public function ajax_block_ip() {
            if (!current_user_can('manage_options')) wp_send_json_error('forbidden');
            check_ajax_referer('alg_block');
            $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
            if (!$ip) wp_send_json_error('no ip');
            $o = $this->opts();
            $list = array_filter(array_map('trim', explode("\n", $o['blacklist_ips'])));
            if (!in_array($ip, $list, true)) { $list[] = $ip; }
            $o['blacklist_ips'] = implode("\n", $list);
            update_option($this->options_key, $o);
            if (!empty($o['auto_report_on_block'])) {
                $this->trigger_auto_report($ip, 'Manually blacklisted IP');
            }
            wp_send_json_success(['blocked'=>$ip]);
        }

        public function ajax_unblock_ip() {
            if (!current_user_can('manage_options')) wp_send_json_error('forbidden');
            check_ajax_referer('alg_unblock');
            $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
            if (!$ip) wp_send_json_error('no ip');
            $o = $this->opts();
            $list = array_filter(array_map('trim', explode("\n", $o['blacklist_ips'])));
            $list = array_values(array_filter($list, function($x) use ($ip){ return $x !== $ip; }));
            $o['blacklist_ips'] = implode("\n", $list);
            update_option($this->options_key, $o);
            wp_send_json_success(['unblocked'=>$ip]);
        }

        public function rest_stats() {
            return rest_ensure_response($this->get_stats_last_24h());
        }

        private function get_stats_last_24h() : array {
            global $wpdb;
            $stats = [ 'success'=>0, 'failed'=>0, 'lockout'=>0, 'blocked'=>0 ];
            $rows = $wpdb->get_results($wpdb->prepare("SELECT status, COUNT(*) c FROM {$this->table} WHERE event_time >= (NOW() - INTERVAL %d HOUR) GROUP BY status", 24));
            foreach ((array)$rows as $r) { $stats[$r->status] = (int)$r->c; }
            return $stats;
        }
    }
}

ALG_Plugin::instance();
