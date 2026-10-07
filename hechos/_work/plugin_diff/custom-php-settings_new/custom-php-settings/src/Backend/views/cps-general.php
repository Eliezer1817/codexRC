<?php

use function CustomPhpSettings\cps_fs;
$settings = '';
$environmentVariables = array();
$php_settings = $this->settings->get( self::FIELD_SETTINGS, array() );
$settingIndex = $this->settings->get( self::FIELD_SETTING_INDEX, 0 );
$currentSetting = $php_settings[$settingIndex];
if ( isset( $php_settings[$settingIndex][self::FIELD_PHP] ) ) {
    foreach ( $php_settings[$settingIndex][self::FIELD_PHP] as $key => $value ) {
        $settings .= $value . PHP_EOL;
    }
}
$environmentVariables = $currentSetting[self::FIELD_ENV];
?>
<div id="cps-wrap" class="wrap">
    <?php 
do_action( 'custom_php_settings_admin_notices' );
?>
    <?php 
settings_errors();
?>
    <?php 
require_once 'cps-tabs.php';
?>
    <?php 
if ( !cps_fs()->is_paying() ) {
    ?>
    <div class="cps-column">
    <?php 
}
?>
    <form action="<?php 
echo admin_url( 'admin-post.php' );
?>" method="POST" id="main">
        <?php 
wp_nonce_field( 'custom-php-settings-action', 'custom-php-settings-nonce' );
?>
        <input type="hidden" name="action" value="custom_php_settings_save_settings" />
        <?php 
?>
        <table class="form-table">
            <tr>
                <td>
                    <fieldset>
                        <textarea id="code_editor_custom_php_settings"
                                  rows="5"
                                  name="settings"
                                  class="widefat textarea"><?php 
echo $settings;
?></textarea>
                    </fieldset>
                    <p class="description"><?php 
echo __( 'Custom PHP Settings. Each setting should be in the form key=value.', 'custom-php-settings' );
?></p>
                </td>
            </tr>
        </table>


    <?php 
?>

    <table class="form-table">
        <tr>
            <td>
                <input type="checkbox" id="update_config" name="update_config"<?php 
checked( $currentSetting[self::FIELD_UPDATE_CONFIG] );
?> />
                <span class="description"><?php 
echo __( 'Update configuration file.', 'custom-php-settings' );
?></span>
            </td>
        </tr>
        <tr>
            <td>
                <input type="checkbox" id="restore_config" name="restore_config"<?php 
checked( $currentSetting[self::FIELD_RESTORE_CONFIG] );
?> />
                <span class="description"><?php 
echo __( 'The configuration file will be restored when the plugin is deactivated or uninstalled.', 'custom-php-settings' );
?></span>
            </td>
        </tr>
        <tr>
            <td>
                <input type="checkbox" id="trim_comments" name="trim_comments"<?php 
checked( $currentSetting[self::FIELD_TRIM_COMMENTS] );
?> />
                <span class="description"><?php 
echo __( 'Do not store any comments in the configuration file.', 'custom-php-settings' );
?></span>
            </td>
        </tr>
        <tr>
            <td>
                <input type="checkbox" id="trim_whitespaces" name="trim_whitespaces"<?php 
checked( $currentSetting[self::FIELD_TRIM_WHITESPACES] );
?> />
                <span class="description"><?php 
echo __( 'Do not store any blank lines in the configuration file.', 'custom-php-settings' );
?></span>
            </td>
        </tr>
    </table>
    <?php 
echo get_submit_button(
    __( 'Save settings', 'custom-php-settings' ),
    'primary',
    'custom-php-settings',
    false,
    array(
        'form' => 'main',
    )
);
?>
    </form>
    <?php 
if ( !cps_fs()->is_paying() ) {
    ?>
    </div>
    <div id="cps-premium-info" class="cps-column">
        <div>
            <div id="cps-upgrade-box" class="postbox">
                <h3><?php 
    _e( 'Go Professional', 'custom-php-settings' );
    ?></h3>
                <div class="inside">
                    <ul id="cps-features">
                        <li><?php 
    _e( 'Create multiple configurations that can be used to easily switch between different settings.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Set environment variables in your .htaccess file.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Show database information.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Show WordPress information.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Backup your configuration file before applying any changes.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Restore configuration file from backup.', 'custom-php-settings' );
    ?></li>
                        <li><?php 
    _e( 'Extended support.', 'custom-php-settings' );
    ?></li>
                    </ul>
                </div>
                <div id="cps-upgrade">
                    <a href="<?php 
    echo cps_fs()->get_upgrade_url();
    ?>" class="button-secondary cps-upgrade-button"><?php 
    _e( 'Learn More', 'custom-php-settings' );
    ?></a>
                </div>
            </div>
        </div>
    </div>
    <?php 
}
?>
</div>
