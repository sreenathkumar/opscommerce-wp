<?php

/*
* Plugin Name: OpsCommerce
* Plugin URI: https://opscommerce.app
* Description: Unified dashboard to manage orders from multiple WooCommerce stores.
* Version: 0.0.1
* Requires at least: 5.2
* Requires PHP: 7.2
* Author: Pixelated Code
* Author URI: https://pixelatedcode.com
* License: GPL v2 or later
* Text Domain: opscommerce
* Requires Plugins: woocommerce
*/

if (!defined('ABSPATH')) exit;

define('OPSWP_OPTION_KEY', 'opscommerceWP_connection');
define('OPSWP_AUTHORIZE_URL', 'http://localhost:3000/authorize');
define('OPSWP_TOKEN_URL', 'http://localhost:3000/api/connect/woocommerce');
define('OPSWP_STATUS_URL', 'http://localhost:3000/api/connect/status');

class OPSCOMMERCEWP
{

    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_notices', [$this, 'maybe_show_missing_woo_notice']);
        add_action('admin_notices', [$this, 'maybe_show_error_notice']);

        add_action('admin_post_opswp_start_auth', [$this, 'start_auth']);
        add_action('admin_post_opswp_complete_auth', [$this, 'complete_auth']);
        add_action('admin_post_opswp_disconnect', [$this, 'disconnect']);
    }

    public function maybe_show_missing_woo_notice()
    {
        if (!class_exists('WooCommerce')) {
            echo '<div class="notice notice-error"><p>OpsCommerce requires WooCommerce to be installed and active.</p></div>';
        }
    }

    public function maybe_show_error_notice()
    {
        if (!empty($_GET['opswp_error']) && current_user_can('manage_woocommerce')) {
            echo '<div class="notice notice-error"><p>Connection failed: ' . esc_html(sanitize_text_field($_GET['opswp_error'])) . '</p></div>';
        }
    }

    public function add_settings_page()
    {
        add_menu_page(
            'OpsCommerce',
            'OpsCommerce',
            'manage_woocommerce',
            'opscommerce',
            [$this, 'render_settings_page'],
            'dashicons-admin-links'
        );
    }

    public function render_settings_page()
    {
        $connection = get_option(OPSWP_OPTION_KEY);
        $live_status = $this->check_connection_status($connection);


        if ($live_status === false) {
            delete_option(OPSWP_OPTION_KEY);
            $connection = false;
        }

?>
        <div class="wrap">
            <h1>OpsCommerce</h1>

            <?php if (!class_exists('WooCommerce')): ?>
                <p>WooCommerce must be active before you can connect.</p>
                <?php return; ?>
            <?php endif; ?>

            <?php if (!empty($connection['connected'])): ?>
                <p>&#9989; Connected as app user <code><?php echo esc_html($connection['org_id']); ?></code></p>
                <p>Webhooks registered: <code><?php echo esc_html(implode(', ', $connection['webhook_ids'] ?? [])); ?></code></p>
                <a class="button" href="<?php echo esc_url(admin_url('admin-post.php?action=opswp_disconnect')); ?>">Disconnect</a>
            <?php else: ?>
                <p>Connect this store to your app. You'll be taken to your app to approve the connection, then brought straight back here.</p>
                <a class="button button-primary" href="<?php echo esc_url(admin_url('admin-post.php?action=opswp_start_auth')); ?>">Connect to Your App</a>
            <?php endif; ?>
        </div>
<?php
    }

    private function check_connection_status($connection)
    {
        $cache_key = 'opswp_status_cache';
        $cached = get_transient($cache_key);

        if ($cached !== false) {
            return $cached === 'unknown' ? null : (bool) $cached;
        }


        $timestamp = time();
        $store_url = get_home_url();
        $signed_str = $timestamp . '.' . $store_url;
        $signature  = hash_hmac('sha256', $signed_str, $connection['secret'] ?? '');

        $response = wp_remote_post(OPSWP_STATUS_URL, [
            'timeout'   => 8,
            'headers'   => ['ContentType' => 'application/json'],
            'body'      => wp_json_encode([
                'timeout'     => 8,
                'store_url'   => $store_url,
                'ts'          => $timestamp,
                'sig'         => $signature,
                'platform'    => 'woocommerce'
            ])
        ]);


        if (is_wp_error($response)) {
            set_transient($cache_key, 'unknown', 60);
            return null;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($body['ok'])) {
            set_transient($cache_key, 'unknown', 60);
            return null;
        }

        $status = !empty($body['connected']);

        set_transient($cache_key, $status, 60); // cache 60s
        return $status;
    }

    /** generate PKCE pair + state, stash verifier locally, redirect to the app. */
    public function start_auth()
    {
        if (!current_user_can('manage_woocommerce')) wp_die('Unauthorized', 403);
        if (!class_exists('WooCommerce')) wp_die('WooCommerce is required.', 400);

        $verifier  = $this->generate_code_verifier();
        $challenge = $this->generate_code_challenge($verifier);
        $state     = bin2hex(random_bytes(16));

        set_transient('opswp_pkce_' . $state, [
            'verifier' => $verifier,
            'user_id'  => get_current_user_id(),
        ], 10 * MINUTE_IN_SECONDS);

        $authorize_url = add_query_arg([
            'site_url'              => home_url(),
            'callback_url'          => admin_url('admin-post.php?action=opswp_complete_auth'),
            'state'                 => $state,
            'code_challenge'        => $challenge,
            'code_challenge_method' => 'S256',
            'platform'              => 'woocommerce'
        ], OPSWP_AUTHORIZE_URL);

        wp_redirect($authorize_url);
        exit;
    }

    /** exchange the returned auth code + our stored verifier for a webhook secret, then register webhooks. */
    public function complete_auth()
    {
        if (!current_user_can('manage_woocommerce')) wp_die('Unauthorized', 403);

        $state = isset($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $code  = isset($_GET['code']) ? sanitize_text_field($_GET['code']) : '';
        $error = isset($_GET['error']) ? sanitize_text_field($_GET['error']) : '';

        if ($error) {
            wp_safe_redirect(admin_url('admin.php?page=opscommerce&opswp_error=' . urlencode($error)));
            exit;
        }

        $pkce = get_transient('opswp_pkce_' . $state);
        if (!$pkce || !$code) {
            wp_safe_redirect(admin_url('admin.php?page=opscommerce&opswp_error=' . urlencode('Session expired, please try connecting again.')));
            exit;
        }
        delete_transient('opswp_pkce_' . $state); // one-time use

        $response = wp_remote_post(OPSWP_TOKEN_URL, [
            'timeout' => 20,
            'headers' => ['Content-Type' => 'application/json'],
            'body'    => wp_json_encode([
                'code'          => $code,
                'code_verifier' => $pkce['verifier'],
            ]),
        ]);

        if (is_wp_error($response)) {
            wp_safe_redirect(admin_url('admin.php?page=opscommerce&opswp_error=' . urlencode($response->get_error_message())));
            exit;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (empty($body['ok'])) {
            wp_safe_redirect(admin_url('admin.php?page=opscommerce&opswp_error=' . urlencode($body['message'] ?? 'Token exchange failed')));
            exit;
        }

        $webhook_ids = $this->register_webhooks($body['webhook_secret'], $body['delivery_url']);

        update_option(OPSWP_OPTION_KEY, [
            'connected'   => true,
            'org_id'     => $body['org_id'],
            'webhook_ids' => $webhook_ids,
            'secret'      => $body['webhook_secret']
        ]);

        wp_safe_redirect(admin_url('admin.php?page=opscommerce'));
        exit;
    }

    public function disconnect()
    {
        if (!current_user_can('manage_woocommerce')) wp_die('Unauthorized', 403);

        $connection = get_option(OPSWP_OPTION_KEY);
        if (!empty($connection['webhook_ids'])) {
            foreach ($connection['webhook_ids'] as $id) {
                $webhook = wc_get_webhook($id);
                if ($webhook) $webhook->delete(true);
            }
        }
        delete_option(OPSWP_OPTION_KEY);

        wp_safe_redirect(admin_url('admin.php?page=opscommerce'));
        exit;
    }

    private function register_webhooks($secret, $delivery_url)
    {
        $webhook_user_id = get_current_user_id();
        $topics = ['order.created', 'order.updated', 'order.deleted'];
        $ids = [];
        foreach ($topics as $topic) {
            $webhook = new WC_Webhook();
            $webhook->set_name('OpsCommerce - ' . $topic);
            $webhook->set_user_id($webhook_user_id);
            $webhook->set_topic($topic);
            $webhook->set_delivery_url($delivery_url);
            $webhook->set_secret($secret);
            $webhook->set_status('active');
            $webhook->save();
            $ids[] = $webhook->get_id();
        }
        return $ids;
    }

    private function generate_code_verifier()
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function generate_code_challenge($verifier)
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}

new OPSCOMMERCEWP();
