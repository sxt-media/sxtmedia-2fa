<?php
/**
 * Plugin Name: sxtmedia 2FA Schutz
 * Plugin URI: https://www.sxt-media.at
 * Description: Erweiterter Zwei-Faktor-Schutz mit Authenticator-App, E-Mail-Verifizierung, Backup-Codes und abgesichertem Login-Flow von sxtmedia.
 * Author: sxtmedia
 * Author URI: https://www.sxt-media.at
 * Version: @@VERSION@@
 */

if (!defined('ABSPATH'))
    exit;

class SXT_Simple_2FA
{
    const META_SECRET = '_sxt_2fa_secret';
    const META_TOTP_ENABLED = '_sxt_2fa_totp_enabled';
    const META_EMAIL_ENABLED = '_sxt_2fa_email_enabled';
    const META_RECOVERY_CODES = '_sxt_2fa_recovery_codes';
    const META_EMAIL_CODE_HASH = '_sxt_2fa_email_code_hash';
    const META_EMAIL_CODE_EXPIRES = '_sxt_2fa_email_code_expires';

    public function __construct()
    {
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_filter('plugins_api', [$this, 'plugin_info'], 20, 3);

        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_bar_menu', [$this, 'adminbar_2fa_status'], 999);
        add_action('admin_init', [$this, 'force_setup']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        add_action('wp_ajax_sxt_send_setup_email', [$this, 'ajax_send_setup_email']);

        add_filter('manage_users_columns', [$this, 'users_column_2fa']);
        add_filter('manage_users_custom_column', [$this, 'users_column_2fa_content'], 10, 3);

        add_filter('wp_authenticate_user', [$this, 'check_rate_limit'], 1, 2);
        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('rest_authentication_errors', [$this, 'secure_rest_api']);

        add_filter('authenticate', [$this, 'authenticate_password_step'], 999, 3);
        add_action('wp_login_failed', [$this, 'force_2fa_redirect_on_failure'], 10, 2);

        add_action('login_form_sxt_2fa', [$this, 'render_2fa_login_step']);
        add_action('login_init', [$this, 'handle_2fa_login_step']);
        add_filter('login_errors', [$this, 'filter_login_errors']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($actions) {
            unset($actions['deactivate']);
            return $actions;
        });
    }

    public function check_update($transient)
    {
        if (empty($transient->checked))
            return $transient;

        // sxt-media-comment: JSON vom eigenen Server abfragen
        $response = wp_remote_get('https://www.sxt-media.at/updates/2fa.json');
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200)
            return $transient;

        $data = json_decode(wp_remote_retrieve_body($response));
        if ($data && version_compare('3.2', $data->new_version, '<')) {
            $plugin_slug = plugin_basename(__FILE__);
            $transient->response[$plugin_slug] = (object) [
                'slug' => 'sxtmedia-2fa',
                'new_version' => $data->new_version,
                'package' => $data->package,
                'url' => 'https://github.com/sxt-media/sxtmedia-2fa'
            ];
        }
        return $transient;
    }

    public function plugin_info($res, $action, $args)
    {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'sxtmedia-2fa')
            return $res;

        $response = wp_remote_get('https://www.sxt-media.at/updates/2fa.json');
        if (is_wp_error($response))
            return $res;

        $data = json_decode(wp_remote_retrieve_body($response));
        if (!$data)
            return $res;

        return (object) [
            'name' => 'sxtmedia 2FA Schutz',
            'slug' => 'sxtmedia-2fa',
            'version' => $data->new_version,
            'package' => $data->package,
            'last_updated' => date('Y-m-d H:i:s'),
            'sections' => ['description' => 'Erweiterter Zwei-Faktor-Schutz.'],
            'download_link' => $data->package
        ];
    }

    private static function get_encryption_key()
    {
        return hash_hmac('sha256', wp_salt('secure_auth'), LOGGED_IN_SALT);
    }


    private static function encrypt($value)
    {
        $key = self::get_encryption_key();
        $iv = random_bytes(12);
        $cipher = openssl_encrypt($value, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

        return bin2hex($iv) . '::' . base64_encode($cipher) . '::' . bin2hex($tag);
    }

    private static function decrypt($raw)
    {
        if (substr_count($raw, '::') !== 2)
            return '';

        $key = self::get_encryption_key();
        [$iv_hex, $cipher_base64, $tag_hex] = explode('::', $raw, 3);

        $iv = hex2bin($iv_hex);
        $tag = hex2bin($tag_hex);

        if (false === $iv || false === $tag || strlen($iv) !== 12 || strlen($tag) !== 16) {
            return '';
        }

        $cipher = base64_decode($cipher_base64, true);
        if (false === $cipher)
            return '';

        return openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    }

    private static function get_client_ip()
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '127.0.0.1';
    }

    private static function set_2fa_cookie($token, $expire = 0)
    {
        $value = hash_hmac('sha256', $token, LOGGED_IN_SALT);
        setcookie('sxt_2fa_auth', $value, [
            'expires' => $expire,
            'path' => COOKIEPATH,
            'domain' => COOKIE_DOMAIN,
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }

    public function adminbar_2fa_status($admin_bar)
    {
        if (!is_user_logged_in())
            return;

        $user_id = get_current_user_id();
        $totp = get_user_meta($user_id, self::META_TOTP_ENABLED, true);
        $email = get_user_meta($user_id, self::META_EMAIL_ENABLED, true);
        $enabled = ($totp || $email);
        $color = $enabled ? '#00a32a' : '#d63638';
        $text = $enabled ? '2FA aktiv' : '2FA nicht eingerichtet';

        $admin_bar->add_node([
            'id' => 'sxt-2fa-status',
            'parent' => 'user-actions',
            'title' => '<span style="color:' . esc_attr($color) . ';font-size:16px;">●</span> ' . esc_html($text),
            'meta' => ['class' => 'sxt-2fa-adminbar']
        ]);
    }

    public function enqueue_admin_assets($hook)
    {
        if ($hook === 'profile_page_sxt-2fa' || $hook === 'users_page_sxt-2fa') {
            wp_enqueue_script(
                'sxt-qrcode-lib',
                plugin_dir_url(__FILE__) . 'js/qrcode.min.js',
                [],
                '1.0.0',
                true
            );
        }
    }

    public function menu()
    {
        add_users_page('2FA Setup', '2FA Setup', 'read', 'sxt-2fa', [$this, 'setup_page']);
    }

    public function force_setup()
    {
        if (!is_user_logged_in() || wp_doing_ajax() || (defined('DOING_CRON') && DOING_CRON) || (defined('WP_CLI') && WP_CLI) || (defined('REST_REQUEST') && REST_REQUEST)) {
            return;
        }

        $user_id = get_current_user_id();
        if (get_user_meta($user_id, self::META_TOTP_ENABLED, true) || get_user_meta($user_id, self::META_EMAIL_ENABLED, true)) {
            return;
        }

        if (($_GET['page'] ?? '') !== 'sxt-2fa') {
            wp_safe_redirect(admin_url('users.php?page=sxt-2fa'));
            exit;
        }
    }

    public function users_column_2fa($columns)
    {
        $columns['sxt_2fa'] = '2FA';
        return $columns;
    }

    public function users_column_2fa_content($value, $column_name, $user_id)
    {
        if ($column_name !== 'sxt_2fa')
            return $value;

        $totp = get_user_meta($user_id, self::META_TOTP_ENABLED, true);
        $email = get_user_meta($user_id, self::META_EMAIL_ENABLED, true);

        return ($totp || $email)
            ? '<span style="color:#00a32a;font-weight:600;">● Aktiv</span>'
            : '<span style="color:#d63638;font-weight:600;">● Inaktiv</span>';
    }

    public function ajax_send_setup_email()
    {
        check_ajax_referer('sxt_send_email_code', 'nonce');

        if (!is_user_logged_in() || !current_user_can('read')) {
            wp_send_json_error();
        }

        // sxt-media-comment: Explizit die ID des aktuell eingeloggten Ajax-Aufrufers nutzen
        self::send_email_code(get_current_user_id());
        wp_send_json_success(['message' => 'Code versendet.']);
    }

    public function setup_page()
    {
        if (!current_user_can('read')) {
            wp_die('Berechtigung fehlt.');
        }

        $user_id = get_current_user_id();
        $user = wp_get_current_user();
        $current_tab = sanitize_text_field($_GET['tab'] ?? 'setup');

        if (!empty($_POST)) {
            check_admin_referer('sxt_save_2fa');

            // sxt-media-comment: Verhindert, dass POST-Daten die $user_id manipulieren
            if (!is_user_logged_in() || (int) $user_id !== (int) get_current_user_id()) {
                wp_die('Unzulässige Aktion.');
            }
        }

        $encrypted_secret = get_user_meta($user_id, self::META_SECRET, true);
        $secret = $encrypted_secret ? self::decrypt($encrypted_secret) : '';

        if (!$secret) {
            $secret = self::create_secret(32);
            update_user_meta($user_id, self::META_SECRET, self::encrypt($secret));
        }

        $totp_enabled = get_user_meta($user_id, self::META_TOTP_ENABLED, true);
        $email_enabled = get_user_meta($user_id, self::META_EMAIL_ENABLED, true);

        if (!empty($_POST['reset_totp']) || !empty($_POST['regenerate_recovery_codes'])) {
            $reauth_code = sanitize_text_field($_POST['reauth_code'] ?? '');
            $reauth_valid = self::verify_totp($secret, $reauth_code, $user_id) || self::verify_setup_email_code($user_id, $reauth_code);

            if (!$reauth_valid) {
                echo '<div class="notice notice-error"><p>Bestätigungscode für diese Aktion ungültig. Bitte einen neuen Code anfordern.</p></div>';
            } elseif (!empty($_POST['reset_totp'])) {
                delete_user_meta($user_id, self::META_SECRET);
                update_user_meta($user_id, self::META_TOTP_ENABLED, 0);
                $secret = self::create_secret(32);
                update_user_meta($user_id, self::META_SECRET, self::encrypt($secret));
                $totp_enabled = false;
                echo '<div class="notice notice-success"><p>Authenticator zurückgesetzt.</p></div>';
            } else {
                $codes = [];
                $hashed_codes = [];
                for ($i = 0; $i < 10; $i++) {
                    $plain = wp_generate_password(12, false, false);
                    $codes[] = $plain;
                    $hashed_codes[] = wp_hash_password($plain);
                }
                update_user_meta($user_id, self::META_RECOVERY_CODES, $hashed_codes);

                echo '<div class="notice notice-warning"><h3>Neue Backup-Codes sichern!</h3><ul style="margin-top:10px;">';
                foreach ($codes as $code) {
                    echo '<li style="margin-bottom:8px;"><code style="font-size:14px;">' . esc_html($code) . '</code></li>';
                }
                echo '</ul><p style="font-weight:600;">ACHTUNG: Codes sofort sichern! Diese Codes werden nur einmal angezeigt.</p></div>';
            }
        }

        if (empty($_POST['reset_totp']) && !empty($_POST['save_2fa'])) {
            $enable_totp = !empty($_POST['enable_totp']);
            $enable_email = !empty($_POST['enable_email']);

            if (!$enable_totp && !$enable_email) {
                echo '<div class="notice notice-error"><p>Mindestens eine 2FA-Methode muss aktiviert werden.</p></div>';
                return;
            }

            if ($enable_totp && !$totp_enabled) {
                $code = sanitize_text_field($_POST['totp_code'] ?? '');
                if (!self::verify_totp($secret, $code, $user_id)) {
                    echo '<div class="notice notice-error"><p>Authenticator Code falsch oder bereits verwendet.</p></div>';
                    return;
                }
            }

            if ($enable_email && !$email_enabled) {
                $email_code = sanitize_text_field($_POST['email_code'] ?? '');
                if (!self::verify_setup_email_code($user_id, $email_code)) {
                    echo '<div class="notice notice-error"><p>E-Mail Bestätigungscode falsch oder abgelaufen.</p></div>';
                    return;
                }
            }

            update_user_meta($user_id, self::META_TOTP_ENABLED, $enable_totp ? 1 : 0);
            update_user_meta($user_id, self::META_EMAIL_ENABLED, $enable_email ? 1 : 0);

            if (($enable_totp || $enable_email) && !get_user_meta($user_id, self::META_RECOVERY_CODES, true)) {
                $codes = [];
                $hashed_codes = [];
                for ($i = 0; $i < 8; $i++) {
                    $plain = wp_generate_password(12, false, false);
                    $codes[] = $plain;
                    $hashed_codes[] = wp_hash_password($plain);
                }
                update_user_meta($user_id, self::META_RECOVERY_CODES, $hashed_codes);

                echo '<div class="notice notice-warning is-dismissible" style="padding: 15px;">';
                echo '    <h3 style="margin-top: 0;">WICHTIG: Recovery-Codes sichern!</h3>';
                echo '    <p>Diese Backup-Codes sind Ihre letzte Rettung. Sie können verwendet werden, wenn:</p>';
                echo '    <ul style="list-style-type: disc; margin-left: 20px;">';
                echo '        <li>Sie keinen Zugriff mehr auf Ihre Authenticator-App haben.</li>';
                echo '        <li>Sie Ihre E-Mails vorübergehend nicht empfangen können.</li>';
                echo '    </ul>';
                echo '    <ul style="margin-top: 15px;">';

                foreach ($codes as $code) {
                    echo '<li><code>' . esc_html($code) . '</code></li>';
                }

                echo '    </ul><p style="font-weight:600;">ACHTUNG: Codes sofort sichern! Diese Codes werden nur einmal angezeigt.</p>';
                echo '</div>';
            }

            echo '<div class="notice notice-success"><p>2FA erfolgreich gespeichert.</p></div>';
            $totp_enabled = get_user_meta($user_id, self::META_TOTP_ENABLED, true);
            $email_enabled = get_user_meta($user_id, self::META_EMAIL_ENABLED, true);
        }

        $issuer = get_bloginfo('name');
        $otpauth = 'otpauth://totp/' . rawurlencode($issuer . ':' . $user->user_email) . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
        ?>
        <div class="wrap">
            <h1>2FA Schutz by sxtmedia</h1>

            <nav class="nav-tab-wrapper" style="margin-bottom: 20px;">
                <a href="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=setup')); ?>"
                    class="nav-tab <?php echo $current_tab === 'setup' ? 'nav-tab-active' : ''; ?>">Einrichtung</a>
                <a href="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=backup')); ?>"
                    class="nav-tab <?php echo $current_tab === 'backup' ? 'nav-tab-active' : ''; ?>">Backup-Codes</a>
                <a href="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=reset')); ?>"
                    class="nav-tab <?php echo $current_tab === 'reset' ? 'nav-tab-active' : ''; ?>">Zurücksetzen</a>
            </nav>

            <?php if (!$totp_enabled && !$email_enabled): ?>
                <div id="sxt-2fa-modal"
                    style="position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99999;display:flex;align-items:center;justify-content:center;">
                    <div
                        style="background:#fff;max-width:520px;padding:24px;border-radius:4px;box-shadow:0 10px 40px rgba(0,0,0,.25);">
                        <h2 style="margin-top:0;">2FA ab sofort verpflichtend</h2>
                        <p>Zum Schutz dieser Website ist die Zwei-Faktor-Authentifizierung (2FA) ab sofort verpflichtend. Bitte
                            richten Sie entweder eine <strong>Authenticator App</strong> (z. B. Google Authenticator, Bitwarden)
                            oder die <strong>E-Mail-Verifizierung</strong> ein und sichern Sie anschließend Ihre Backup-Codes, um
                            den Ausschluss aus Ihrem Konto zu verhindern.</p>
                        <p><button type="button" class="button button-primary"
                                onclick="document.getElementById('sxt-2fa-modal').style.display='none';">2FA jetzt
                                einrichten</button></p>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($current_tab === 'setup'): ?>
                <form method="post" action="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=setup')); ?>">
                    <?php wp_nonce_field('sxt_save_2fa'); ?>
                    <h2>Authenticator App</h2>
                    <p><label><input type="checkbox" name="enable_totp" value="1" <?php checked($totp_enabled); ?>> Authenticator
                            App aktivieren</label></p>

                    <?php if (!$totp_enabled): ?>
                        <div id="sxt-qrcode" style="margin: 15px 0;" data-otpauth="<?php echo esc_attr($otpauth); ?>"></div>
                        <p>Secret / Einrichtungsschlüssel:<br><code><?php echo esc_html($secret); ?></code></p>
                        <p>Code verifizieren:<br>
                            <input type="text" name="totp_code" placeholder="123456" autocomplete="one-time-code">
                        </p>
                    <?php else: ?>
                        <p style="color:#00a32a;font-weight:600;">Erfolgreich eingerichtet</p>
                    <?php endif; ?>

                    <hr>
                    <h2>E-Mail Code</h2>
                    <p><label><input type="checkbox" name="enable_email" value="1" <?php checked($email_enabled); ?>> E-Mail 2FA
                            aktivieren (Code wird an <strong><?php echo esc_html($user->user_email); ?></strong> gesendet)</label>
                    </p>
                    <?php if ($email_enabled): ?>
                        <p style="color:#00a32a;font-weight:600;">Erfolgreich eingerichtet</p>
                    <?php else: ?>
                        <p>
                            <button type="button" id="sxt-send-email-code" class="button button-secondary">Bestätigungscode
                                anfordern</button>
                            <span id="sxt-email-status" style="margin-left:10px;"></span>
                        </p>
                        <p>E-Mail Code bestätigen:<br><input type="text" name="email_code" placeholder="123456"
                                autocomplete="one-time-code"></p>
                    <?php endif; ?>

                    <hr>
                    <p><button class="button button-primary" name="save_2fa" value="1">Speichern</button></p>
                </form>
            <?php endif; ?>

            <?php if ($current_tab === 'backup'): ?>
                <form method="post" action="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=backup')); ?>">
                    <?php wp_nonce_field('sxt_save_2fa'); ?>
                    <h2>Kritische Aktionen (Backup-Codes)</h2>

                    <p>Geben Sie zur Bestätigung Ihren aktuellen App- oder E-Mail-Code ein:</p>
                    <p><input type="text" name="reauth_code" placeholder="Aktueller 2FA-Code" autocomplete="off"></p>
                    <p>
                        <button type="button" class="button button-secondary sxt-send-reauth-email">2FA Code per E-Mail
                            senden</button>
                        <span class="sxt-reauth-email-status" style="margin-left:10px;"></span>
                    </p>
                    <p>
                        <button type="submit" name="regenerate_recovery_codes" value="1" class="button button-primary">Neue
                            Backup-Codes generieren</button>
                    </p>
                </form>
            <?php endif; ?>

            <?php if ($current_tab === 'reset'): ?>
                <form method="post" action="<?php echo esc_url(admin_url('users.php?page=sxt-2fa&tab=reset')); ?>">
                    <?php wp_nonce_field('sxt_save_2fa'); ?>
                    <h2>Kritische Aktionen (Zurücksetzen)</h2>

                    <p>Geben Sie zur Bestätigung Ihren aktuellen App- oder E-Mail-Code ein:</p>
                    <p><input type="text" name="reauth_code" placeholder="Aktueller 2FA-Code" autocomplete="off"></p>
                    <p>
                        <button type="button" class="button button-secondary sxt-send-reauth-email">2FA Code per E-Mail
                            senden</button>
                        <span class="sxt-reauth-email-status" style="margin-left:10px;"></span>
                    </p>
                    <p>
                        <button type="submit" name="reset_totp" value="1" class="button button-primary">Authenticator
                            zurücksetzen</button>
                    </p>
                </form>
            <?php endif; ?>
        </div>
        <script>
            document.addEventListener("DOMContentLoaded", function () {
                var qrContainer = document.getElementById("sxt-qrcode");
                // sxt-media-comment: Wert sicher aus dem DOM-Attribut lesen statt Inline-PHP
                if (typeof QRCode !== 'undefined' && qrContainer) {
                    var otpauth = qrContainer.getAttribute('data-otpauth');
                    if (otpauth) {
                        new QRCode(qrContainer, { text: otpauth, width: 220, height: 220 });
                    }
                }
                const button = document.getElementById('sxt-send-email-code');
                if (button) {
                    button.addEventListener('click', function () {
                        const status = document.getElementById('sxt-email-status');
                        status.innerHTML = 'Sende...';
                        fetch(ajaxurl, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: new URLSearchParams({ action: 'sxt_send_setup_email', nonce: '<?php echo wp_create_nonce('sxt_send_email_code'); ?>' })
                        })
                            .then(r => r.json())
                            .then(data => { status.innerHTML = data.success ? '<span style="color:green;">Code versendet</span>' : '<span style="color:red;">Fehler</span>'; });
                    });
                }
                // sxt-media-comment: Event-Listener fuer Re-Auth Mail-Buttons in den kritischen Tabs
                document.querySelectorAll('.sxt-send-reauth-email').forEach(btn => {
                    btn.addEventListener('click', function () {
                        const status = this.nextElementSibling;
                        status.innerHTML = 'Sende...';
                        fetch(ajaxurl, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: new URLSearchParams({ action: 'sxt_send_setup_email', nonce: '<?php echo wp_create_nonce('sxt_send_email_code'); ?>' })
                        })
                            .then(r => r.json())
                            .then(data => { status.innerHTML = data.success ? '<span style="color:green;">Code versendet</span>' : '<span style="color:red;">Fehler</span>'; });
                    });
                });
            });
        </script>
        <?php
    }

    public function check_rate_limit($user, $username)
    {
        if (empty($username))
            return $user;

        $key = 'sxt_bf_' . md5($username . self::get_client_ip());
        if ((int) get_transient($key) >= 5) {
            return new WP_Error('sxt_rate_limited', 'Zu viele Fehlversuche. IP temporär gesperrt.');
        }

        if ($user instanceof WP_User) {
            $user_key = 'sxt_bf_uid_' . $user->ID;
            if ((int) get_transient($user_key) >= 5) {
                return new WP_Error('sxt_rate_limited', 'Konto temporär gesperrt wegen zu vieler Versuche.');
            }
        }

        return $user;
    }

    private function increment_rate_limit($username, $user_id = 0)
    {
        if (empty($username) && !$user_id)
            return;

        $ip_key = 'sxt_bf_' . md5($username . self::get_client_ip());
        set_transient($ip_key, ((int) get_transient($ip_key)) + 1, 15 * MINUTE_IN_SECONDS);

        if ($user_id) {
            $user_key = 'sxt_bf_uid_' . (int) $user_id;
            set_transient($user_key, ((int) get_transient($user_key)) + 1, 15 * MINUTE_IN_SECONDS);
        }
    }

    public function secure_rest_api($errors)
    {
        if (!empty($errors))
            return $errors;

        if (!defined('REST_REQUEST') || !REST_REQUEST) {
            return $errors;
        }

        if (function_exists('wp_is_application_passwords_available') && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
            return $errors;
        }

        // sxt-media-comment: Erlaubt internen WordPress-Core REST-Requests den Zugriff
        if (is_user_logged_in() && (is_admin() || (defined('REST_REQUEST') && REST_REQUEST && current_user_can('read')))) {
            return $errors;
        }

        $user_id = get_current_user_id();

        if (
            $user_id && (
                get_user_meta($user_id, self::META_TOTP_ENABLED, true) ||
                get_user_meta($user_id, self::META_EMAIL_ENABLED, true)
            )
        ) {
            return new WP_Error(
                'rest_2fa_required',
                'REST-Zugriff verweigert. Nutzen Sie Application Passwords.',
                ['status' => 401]
            );
        }

        return $errors;
    }

    public function authenticate_password_step($user, $username, $password)
    {
        if (is_wp_error($user) || !$user instanceof WP_User) {
            if (is_wp_error($user))
                $this->increment_rate_limit($username);
            return $user;
        }

        $user_id = $user->ID;
        $totp_enabled = get_user_meta($user_id, self::META_TOTP_ENABLED, true);
        $email_enabled = get_user_meta($user_id, self::META_EMAIL_ENABLED, true);

        if (!$totp_enabled && !$email_enabled)
            return $user;

        $token = wp_generate_password(32, false);

        self::set_2fa_cookie($token, time() + 300);

        set_transient('sxt_2fa_' . $token, [
            'user_id' => $user_id,
            'user' => $username,
            'attempts' => 0,
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ], 5 * MINUTE_IN_SECONDS);

        set_transient('sxt_2fa_remember_' . $token, !empty($_POST['rememberme']) ? 1 : 0, 5 * MINUTE_IN_SECONDS);

        wp_clear_auth_cookie();

        return new WP_Error('sxt_2fa_required', '2FA', ['redirect_to' => wp_login_url() . '?action=sxt_2fa&token=' . urlencode($token)]);
    }

    public function force_2fa_redirect_on_failure($username, $error)
    {
        if (is_wp_error($error) && $error->get_error_code() === 'sxt_2fa_required') {
            $data = $error->get_error_data();
            if (!empty($data['redirect_to'])) {
                wp_safe_redirect($data['redirect_to']);
                exit;
            }
        }
    }

    public function filter_login_errors($error)
    {
        if (isset($_GET['reason']) && $_GET['reason'] === '2fa_limit') {
            return '<strong>Fehler:</strong> Zu viele falsche 2FA-Codes. Bitte erneut einloggen.';
        }
        if (strpos($error, '2FA') !== false) {
            return '<strong>2FA erforderlich:</strong> Bitte verifizieren Sie Ihre Identität.';
        }
        return $error;
    }

    public function render_2fa_login_step()
    {
        $token = sanitize_text_field($_GET['token'] ?? '');
        $session = get_transient('sxt_2fa_' . $token);
        $cookie_expected = hash_hmac('sha256', $token, LOGGED_IN_SALT);

        if (!$session || !isset($_COOKIE['sxt_2fa_auth']) || !hash_equals($cookie_expected, $_COOKIE['sxt_2fa_auth']) || ($session['ua'] ?? '') !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
            wp_die('Sitzung ungültig.', 'Fehler', ['response' => 403]);
        }

        $user_id = (int) $session['user_id'];

        if (get_user_meta($user_id, self::META_EMAIL_ENABLED, true) && !get_transient('sxt_email_sent_' . $token)) {
            self::send_email_code($user_id);
            set_transient('sxt_email_sent_' . $token, '1', 5 * MINUTE_IN_SECONDS);
        }

        $error = new WP_Error();
        if (isset($_GET['err']))
            $error->add('sxt_2fa_invalid', 'Code ungültig oder abgelaufen.');

        login_header('2FA Login', '', $error);
        ?>
        <form name="sxt2faloginform" id="loginform" action="<?php echo esc_url(wp_login_url() . '?action=sxt_2fa'); ?>"
            method="post">
            <p>
                <label for="sxt_otp">2FA Code / Recovery-Code</label>
                <input type="text" name="sxt_otp" id="sxt_otp" class="input" size="20" autocomplete="one-time-code" required
                    autofocus>
            </p>
            <input type="hidden" name="token" value="<?php echo esc_attr($token); ?>">
            <?php wp_nonce_field('sxt_verify_2fa', 'sxt_2fa_nonce'); ?>
            <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
                    value="Verifizieren"></p>
        </form>
        <?php
        login_footer('sxt_otp');
        exit;
    }

    public function handle_2fa_login_step()
    {
        if (($_GET['action'] ?? '') !== 'sxt_2fa')
            return;
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            if (isset($_GET['token']))
                $this->render_2fa_login_step();
            return;
        }

        $token = sanitize_text_field($_POST['token'] ?? '');
        $session = get_transient('sxt_2fa_' . $token);
        $cookie_expected = hash_hmac('sha256', $token, LOGGED_IN_SALT);

        if (!$session || !isset($_COOKIE['sxt_2fa_auth']) || !hash_equals($cookie_expected, $_COOKIE['sxt_2fa_auth']) || ($session['ua'] ?? '') !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
            wp_die('Sitzung ungültig.', 'Fehler', ['response' => 403]);
        }

        if (!isset($_POST['sxt_2fa_nonce']) || !wp_verify_nonce($_POST['sxt_2fa_nonce'], 'sxt_verify_2fa')) {
            wp_die('CSRF-Token ungültig.', 'Fehler', ['response' => 403]);
        }

        $user_id = (int) $session['user_id'];

        if (($session['attempts'] ?? 0) >= 5) {
            delete_transient('sxt_2fa_' . $token);
            self::set_2fa_cookie($token, time() - 3600);
            $this->increment_rate_limit($session['user'] ?? '', $user_id);
            wp_safe_redirect(wp_login_url() . '?login=failed&reason=2fa_limit');
            exit;
        }

        $code = sanitize_text_field($_POST['sxt_otp'] ?? '');
        $valid = false;

        $recovery_codes = get_user_meta($user_id, self::META_RECOVERY_CODES, true);
        if (is_array($recovery_codes) && strlen($code) > 6) {
            foreach ($recovery_codes as $index => $hashed) {
                if (wp_check_password($code, $hashed)) {
                    unset($recovery_codes[$index]);
                    update_user_meta($user_id, self::META_RECOVERY_CODES, array_values($recovery_codes));
                    $valid = true;
                    break;
                }
            }
        }

        if (!$valid && get_user_meta($user_id, self::META_TOTP_ENABLED, true)) {
            $secret = self::decrypt(get_user_meta($user_id, self::META_SECRET, true));
            if (self::verify_totp($secret, $code, $user_id))
                $valid = true;
        }

        if (!$valid && get_user_meta($user_id, self::META_EMAIL_ENABLED, true)) {
            if (self::verify_email_code($user_id, $code))
                $valid = true;
        }

        if (!$valid) {
            $session['attempts'] = ($session['attempts'] ?? 0) + 1;
            set_transient('sxt_2fa_' . $token, $session, 5 * MINUTE_IN_SECONDS);
            $this->increment_rate_limit($session['user'] ?? '', $user_id);
            wp_safe_redirect(wp_login_url() . '?action=sxt_2fa&token=' . urlencode($token) . '&err=1');
            exit;
        }

        $remember = (bool) get_transient('sxt_2fa_remember_' . $token);
        delete_transient('sxt_2fa_' . $token);
        delete_transient('sxt_email_sent_' . $token);
        self::set_2fa_cookie($token, time() - 3600);

        wp_clear_auth_cookie();
        wp_set_auth_cookie($user_id, $remember);
        wp_set_current_user($user_id);

        $user_data = get_userdata($user_id);
        if ($user_data)
            do_action('wp_login', $user_data->user_login, $user_data);

        wp_safe_redirect(admin_url());
        exit;
    }

    private static function send_email_code($user_id)
    {
        $user = get_user_by('id', $user_id);
        if (!$user)
            return;

        $code = (string) random_int(100000, 999999);
        update_user_meta($user_id, self::META_EMAIL_CODE_HASH, wp_hash_password($code));
        update_user_meta($user_id, self::META_EMAIL_CODE_EXPIRES, time() + (10 * MINUTE_IN_SECONDS));

        $subject = '2FA-Code für ' . wp_specialchars_decode(get_bloginfo('name'));
        // sxt-media-comment: Erweitertes E-Mail-Template mit Gültigkeitshinweis
        $message = '<p>Guten Tag,</p>';
        $message .= '<p>hier ist Ihr angeforderter Bestätigungscode:</p>';
        $message .= '<p style="font-size:28px;font-weight:bold;letter-spacing:3px;margin:20px 0;">' . esc_html($code) . '</p>';
        $message .= '<p style="color:#666;font-size:12px;">Dieser Code ist aus Sicherheitsgründen nur <strong>10 Minuten</strong> gültig. Falls Sie diesen Code nicht angefordert haben, können Sie diese E-Mail ignorieren.</p>';
        wp_mail($user->user_email, $subject, $message, ['Content-Type: text/html; charset=UTF-8']);
    }

    private static function verify_setup_email_code($user_id, $code)
    {
        return self::verify_email_code($user_id, $code);
    }

    private static function verify_email_code($user_id, $code)
    {
        $hash = get_user_meta($user_id, self::META_EMAIL_CODE_HASH, true);
        $expires = (int) get_user_meta($user_id, self::META_EMAIL_CODE_EXPIRES, true);

        if (!$hash || !$expires || time() > $expires || !wp_check_password($code, $hash))
            return false;

        delete_user_meta($user_id, self::META_EMAIL_CODE_HASH);
        delete_user_meta($user_id, self::META_EMAIL_CODE_EXPIRES);
        return true;
    }

    private static function create_secret($length = 16)
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < $length; $i++)
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        return $secret;
    }

    private static function verify_totp($secret, $code, $user_id, $window = 1)
    {
        $code = preg_replace('/\D/', '', $code);
        if (!$secret || strlen($code) !== 6)
            return false;

        $time_slice = floor(time() / 30);
        for ($i = -$window; $i <= $window; $i++) {
            $target_slice = $time_slice + $i;
            if (hash_equals(self::totp($secret, $target_slice), $code)) {
                $replay_key = 'sxt_2fa_rpl_' . md5($user_id . '_' . $target_slice);
                if (get_transient($replay_key))
                    return false;
                set_transient($replay_key, '1', 60);
                return true;
            }
        }
        return false;
    }

    private static function totp($secret, $time_slice)
    {
        $key = self::base32_decode($secret);
        $time = pack('N*', 0) . pack('N*', $time_slice);
        $hash = hash_hmac('sha1', $time, $key, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $value = ((ord($hash[$offset]) & 0x7F) << 24) | ((ord($hash[$offset + 1]) & 0xFF) << 16) | ((ord($hash[$offset + 2]) & 0xFF) << 8) | (ord($hash[$offset + 3]) & 0xFF);
        return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
    }

    private static function base32_decode($secret)
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = strtoupper(preg_replace('/[^A-Z2-7]/', '', $secret));
        $bits = '';
        foreach (str_split($secret) as $char) {
            $val = strpos($alphabet, $char);
            if ($val === false)
                continue;
            $bits .= str_pad(decbin($val), 5, '0', STR_PAD_LEFT);
        }
        $data = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8)
                $data .= chr(bindec($byte));
        }
        return $data;
    }
}
new SXT_Simple_2FA();
