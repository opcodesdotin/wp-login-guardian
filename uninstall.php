<?php
/**
 * Uninstall WP-Login Guardian
 *
 * Cleans up options and custom tables when the plugin is deleted.
 *
 * @package WP_Login_Guardian
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Delete options
delete_option('alg_options_v1');
delete_site_option('alg_options_v1');

// Drop custom activity database table
$table_name = $wpdb->prefix . 'alg_login_activity';
$wpdb->query("DROP TABLE IF EXISTS {$table_name}");
