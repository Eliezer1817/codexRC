<?php

/**
 * Plugin Name: Custom PHP settings
 * Plugin URI: https://wordpress.org/plugins/custom-php-settings/
 * Description: Customize PHP settings.
 * Version: 2.4.1
 * Requires at least: 4.1.0
 * Requires PHP: 5.6
 * Author: Cyclonecode
 * Author URI: https://stackoverflow.com/users/1047662/cyclonecode?tab=profile
 * Copyright: Cyclonecode
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: custom-php-settings
 * Domain Path: /languages
 *
 * @package custom-php-settings
 */
namespace CustomPhpSettings;

require_once __DIR__ . '/vendor/autoload.php';
use CustomPhpSettings\Backend\Backend;
use CustomPhpSettings\Plugin\Settings\Settings;
if ( function_exists( 'cps_fs' ) ) {
    cps_fs()->set_basename( false, __FILE__ );
} else {
    if ( !function_exists( 'cps_fs' ) ) {
        // Create a helper function for easy SDK access.
        function cps_fs() {
            if ( !isset( $cps_fs ) ) {
                $cps_fs = fs_dynamic_init( [
                    'id'             => '13735',
                    'slug'           => 'custom-php-settings',
                    'premium_slug'   => 'custom-php-settings-pro',
                    'type'           => 'plugin',
                    'public_key'     => 'pk_f39e0a5328f4297b51802fe17e93f',
                    'is_premium'     => false,
                    'has_addons'     => FALSE,
                    'has_paid_plans' => TRUE,
                    'menu'           => [
                        'slug' => 'custom-php-settings',
                    ],
                    'is_live'        => true,
                ] );
            }
            return $cps_fs;
        }

        // Init Freemius.
        cps_fs();
        // Signal that SDK was initiated.
        do_action( 'cps_fs_loaded' );
    }
    add_action( 'after_setup_theme', function () {
        if ( is_admin() ) {
            new Backend(new Settings(Backend::SETTINGS_NAME));
        }
    } );
    register_activation_hook( __FILE__, ['CustomPhpSettings\\Backend\\Backend', 'activate'] );
    register_deactivation_hook( __FILE__, ['CustomPhpSettings\\Backend\\Backend', 'deActivate'] );
    register_uninstall_hook( __FILE__, ['CustomPhpSettings\\Backend\\Backend', 'delete'] );
}