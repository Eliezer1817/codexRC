<?php

namespace CustomPhpSettings\Backend;

use CustomPhpSettings\Plugin\Settings\Settings;
use function CustomPhpSettings\cps_fs;
class Backend {
    const VERSION = '2.4.1';

    const SETTINGS_NAME = 'custom_php_settings';

    const MENU_SLUG = 'custom-php-settings';

    const MARKER = 'CUSTOM PHP SETTINGS';

    const CPS_NONCE = 'custom_php_settings';

    const FIELD_SETTINGS = 'settings';

    const FIELD_SETTING_NAME = 'name';

    const FIELD_SETTING_INDEX = 'settingIndex';

    const FIELD_PHP_SETTINGS = 'php_settings';

    const FIELD_PHP = 'php';

    const FIELD_ENV = 'environment';

    const FIELD_UPDATE_CONFIG = 'update_config';

    const FIELD_RESTORE_CONFIG = 'restore_config';

    const FIELD_TRIM_COMMENTS = 'trim_comments';

    const FIELD_TRIM_WHITESPACES = 'trim_whitespaces';

    const FIELD_NOTIFICATIONS = 'notes';

    const FIELD_VERSION = 'version';

    const PLAN_FREE = 'free';

    const PLAN_BASIC = 'basic';

    const PLAN_PROFESSIONAL = 'professional';

    const PLAN_AGENCY = 'agency';

    /**
     *
     * @var Settings
     */
    private $settings;

    /**
     * @var string $capability
     */
    private $capability = 'manage_options';

    /**
     * @var string $currentTab
     */
    private $currentTab = '';

    /**
     * @var string $currentSection
     */
    private $currentSection = '';

    /**
     * @var \WP_Filesystem $fileSystem
     */
    private $fileSystem = null;

    /**
     * @param Settings $settings
     */
    public function __construct( $settings ) {
        // Allow people to change what capability is required to use this plugin.
        $this->capability = apply_filters( 'custom_php_settings_cap', $this->capability );
        $this->settings = $settings;
        $this->checkForUpgrade();
        $this->setTabs();
        $this->addActions();
        $this->addFilters();
        $this->sortSuperGlobals();
    }

    /**
     * Sort super globals.
     */
    protected function sortSuperGlobals() {
        ksort( $_COOKIE );
        ksort( $_ENV );
        ksort( $_SERVER );
    }

    /**
     * Localize plugin.
     */
    public function localize() {
        load_plugin_textdomain( 'custom-php-settings', false, dirname( plugin_basename( __FILE__ ) ) . '/../../languages' );
    }

    /**
     * Add actions.
     */
    public function addActions() {
        add_action( 'init', array($this, 'localize') );
        add_action( 'admin_menu', array($this, 'addMenu') );
        add_action( 'in_admin_header', array($this, 'addHeader') );
        add_action( 'admin_post_custom_php_settings_save_settings', array($this, 'saveSettings') );
        add_action( 'admin_enqueue_scripts', array($this, 'addScripts') );
        add_action( 'custom_php_settings_admin_notices', array($this, 'renderNotices') );
        add_action( 'wp_ajax_custom_php_settings_dismiss_notice', array($this, 'doDismissNotice') );
    }

    /**
     * Add filters.
     */
    public function addFilters() {
        add_filter( 'admin_footer_text', array($this, 'adminFooter') );
        add_filter(
            'plugin_action_links',
            array($this, 'addActionLinks'),
            10,
            2
        );
        add_filter(
            'plugin_row_meta',
            array($this, 'filterPluginRowMeta'),
            10,
            4
        );
    }

    /**
     * Marks a notification as dismissed.
     *
     * @param string $id
     * @return bool
     */
    private function dismissNotice( $id ) {
        $notes = $this->settings->get( 'notes' );
        foreach ( $notes as $key => $note ) {
            if ( $note['id'] === (int) $id ) {
                $notes[$key]['dismissed'] = true;
                $notes[$key]['time'] = time();
                $this->settings->set( 'notes', $notes );
                $this->settings->save();
                return true;
            }
        }
    }

    /**
     * Resets a notification.
     *
     * @param string $id
     * @return bool
     */
    public function resetNotice( $id ) {
        $notes = $this->settings->get( 'notes' );
        foreach ( $notes as $key => $note ) {
            if ( $note['id'] === (int) $id ) {
                $notes[$key]['dismissed'] = false;
                $notes[$key]['time'] = time();
                $this->settings->set( 'notes', $notes );
                $this->settings->save();
                return true;
            }
        }
    }

    /**
     * Returns a notification by name.
     *
     * @param string $name
     * @return mixed|null
     */
    public function getNoticeByName( $name ) {
        $notes = $this->settings->get( 'notes' );
        return ( isset( $notes[$name] ) ? $notes[$name] : null );
    }

    /**
     * Ajax handler for dismissing notifications.
     */
    public function doDismissNotice() {
        check_ajax_referer( self::CPS_NONCE );
        if ( !current_user_can( 'administrator' ) ) {
            return wp_send_json_error( __( 'You are not allowed to perform this action.', 'custom-php-settings' ) );
        }
        if ( !filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT ) ) {
            return wp_send_json_error( __( 'No valid notification id supplied.', 'custom-php-settings' ) );
        }
        if ( !$this->dismissNotice( $_POST['id'] ) ) {
            return wp_send_json_error( __( 'Notification could not be found.', 'custom-php-settings' ) );
        }
        wp_send_json_success();
    }

    /**
     * Render any notifications.
     */
    public function renderNotices() {
        $notes = $this->settings->get( 'notes' );
        usort( $notes, function ( $a, $b ) {
            return ( $a['weight'] === $b['weight'] ? 0 : $a['weight'] - $b['weight'] );
        } );
        foreach ( $notes as $note ) {
            if ( is_callable( [$this, $note['callback']] ) && (!$note['dismissed'] || !$note['persistent'] && time() - $note['time'] > 30 * 24 * 60 * 60) ) {
                ?>
                <div id="note-<?php 
                echo $note['id'];
                ?>" class="custom-php-settings-notice notice notice-<?php 
                echo $note['type'];
                echo ( $note['dismissible'] ? ' is-dismissible' : '' );
                ?>">
                <?php 
                echo call_user_func( array($this, $note['callback']) );
                ?>
                </div>
                <?php 
            }
        }
    }

    /**
     * Adds review admin notification.
     */
    public static function addReviewNotice() {
        ?>
        <h3><?php 
        _e( 'Thank you for using Custom PHP Settings!', 'custom-php-settings' );
        ?></h3>
        <p><?php 
        echo sprintf( __( 'If you use and enjoy Custom PHP Settings, I would be really grateful if you could give it a positive review at <a href="%s" target="_blank">wordpress.org</a>.', 'custom-php-settings' ), 'https://wordpress.org/support/plugin/custom-php-settings/reviews/?rate=5#new-post' );
        ?></p>
        <p><?php 
        _e( 'Doing this would help me keeping the plugin free and up to date.', 'custom-php-settings' );
        ?></p>
        <p><?php 
        _e( 'If you are feeling generous and would like to support me, you can always buy me a coffee at:', 'custom-php-settings' );
        ?> <a target="_blank" href="https://www.buymeacoffee.com/cyclonecode">https://www.buymeacoffee.com/cyclonecode</a></p>
        <p><?php 
        _e( 'Please make sure to leave your e-mail address, and I will make sure to add you to the supporter section in the readme =)', 'custom-php-settings' );
        ?></p>
        <p><?php 
        _e( 'Thank you very much!', 'custom-php-settings' );
        ?></p>
        <?php 
    }

    /**
     * Adds support admin notification.
     */
    public static function addSupportNotice() {
        ?>
        <h3><?php 
        _e( 'Do you have any feedback or need support?', 'custom-php-settings' );
        ?></h3>
        <p><?php 
        echo sprintf( __( 'If you have any requests for improvement or just need some help. Do not hesitate to open a ticket in the <a href="%s" target="_blank">support section</a>.', 'custom-php-settings' ), 'https://wordpress.org/support/plugin/custom-php-settings/#new-topic-0' );
        ?></p>
        <p><?php 
        echo sprintf( __( 'I can also be reached by email at <a href="%s">%s</a>', 'custom-php-settings' ), 'mailto:customphpsettings@gmail.com?subject=Custom PHP Settings Support', 'customphpsettings@gmail.com' );
        ?></p>
        <p><?php 
        echo sprintf( __( 'There is also a Slack channel that you can <a target="_blank" href="%s">join</a>.', 'custom-php-settings' ), 'https://join.slack.com/t/cyclonecode/shared_invite/zt-6bdtbdab-n9QaMLM~exHP19zFDPN~AQ' );
        ?></p>
        <p><?php 
        _e( 'I hope you will have an awesome day!', 'custom-php-settings' );
        ?></p>
        <?php 
    }

    /**
     * Render admin header.
     */
    public function addHeader() {
        if ( get_current_screen()->id !== 'toplevel_page_custom-php-settings' ) {
            return;
        }
        $sectionText = array(
            'general'     => __( 'Editor', 'custom-php-settings' ),
            'backup'      => __( 'Backup', 'custom-php-settings' ),
            'apache'      => __( 'Apache Information', 'custom-php-settings' ),
            'php-info'    => __( 'PHP Information', 'custom-php-settings' ),
            'gd'          => __( 'GD Library', 'custom-php-settings' ),
            'wordpress'   => __( 'WordPress', 'custom-php-settings' ),
            'database'    => __( 'Database', 'custom-php-settings' ),
            'extensions'  => __( 'Loaded Extensions', 'custom-php-settings' ),
            'settings'    => __( 'Current PHP Settings', 'custom-php-settings' ),
            'cookie-vars' => __( '$_COOKIE Variables', 'custom-php-settings' ),
            'server-vars' => __( '$_SERVER Variables', 'custom-php-settings' ),
            'env-vars'    => __( '$_ENV Variables', 'custom-php-settings' ),
            'status'      => __( 'Status', 'custom-php-settings' ),
        );
        if ( $this->currentTab === 'info' && !empty( $this->currentSection ) ) {
            $title = ' | ' . $sectionText[$this->currentSection];
        } else {
            $title = ( $this->currentTab ? ' | ' . $sectionText[$this->currentTab] : '' );
        }
        ?>
        <div id="custom-php-settings-admin-header">
            <div><img width="64" src="<?php 
        echo plugin_dir_url( __FILE__ );
        ?>assets/icon-128x128.png" alt="<?php 
        _e( 'Custom PHP Settings', 'custom-php-settings' );
        ?>" />
                <h1><?php 
        _e( 'Custom PHP Settings', 'custom-php-settings' );
        echo $title;
        ?></h1>
            </div>
        </div>
        <?php 
    }

    /**
     * Add action link on plugins page.
     *
     * @param array $links
     * @param string $file
     *
     * @return mixed
     */
    public function addActionLinks( $links, $file ) {
        $settings_link = '<a href="' . admin_url( 'admin.php?page=' . self::MENU_SLUG ) . '">' . __( 'Settings', 'custom-php-settings' ) . '</a>';
        if ( !cps_fs()->is_free_plan() && $file === 'custom-php-settings-pro/bootstrap.php' ) {
            array_unshift( $links, $settings_link );
        }
        if ( cps_fs()->is_free_plan() && $file === 'custom-php-settings/bootstrap.php' ) {
            array_unshift( $links, $settings_link );
        }
        return $links;
    }

    /**
     * Filters the array of row meta for each plugin in the Plugins list table.
     *
     * @param string[] $plugin_meta An array of the plugin's metadata.
     * @param string   $plugin_file Path to the plugin file relative to the plugins' directory.
     * @return string[] An array of the plugin's metadata.
     */
    public function filterPluginRowMeta( array $plugin_meta, $plugin_file ) {
        if ( $plugin_file !== 'custom-php-settings/bootstrap.php' ) {
            return $plugin_meta;
        }
        $plugin_meta[] = sprintf( '<a target="_blank" href="%1$s"><span class="dashicons dashicons-star-filled" aria-hidden="true" style="font-size:14px;line-height:1.3"></span>%2$s</a>', 'https://www.buymeacoffee.com/cyclonecode', esc_html_x( 'Sponsor', 'verb', 'custom-php-settings' ) );
        $plugin_meta[] = sprintf( '<a target="_blank" href="%1$s"><span class="dashicons dashicons-thumbs-up" aria-hidden="true" style="font-size:14px;line-height:1.3"></span>%2$s</a>', 'https://wordpress.org/support/plugin/custom-php-settings/reviews/?rate=5#new-post', esc_html_x( 'Rate', 'verb', 'custom-php-settings' ) );
        $plugin_meta[] = sprintf( '<a target="_blank" href="%1$s"><span class="dashicons dashicons-editor-help" aria-hidden="true" style="font-size:14px;line-height:1.3"></span>%2$s</a>', 'https://wordpress.org/support/plugin/custom-php-settings/#new-topic-0', esc_html_x( 'Support', 'verb', 'custom-php-settings' ) );
        return $plugin_meta;
    }

    /**
     * Add scripts.
     */
    public function addScripts( $hook ) {
        if ( $hook === 'toplevel_page_custom-php-settings' ) {
            // Added in WordPress 4.1.
            if ( function_exists( 'wp_enqueue_code_editor' ) && ($this->getCurrentTab() === 'general' || $this->getCurrentTab() === 'backup') ) {
                wp_enqueue_code_editor( array() );
            }
            wp_enqueue_script(
                'custom-php-settings',
                plugin_dir_url( __FILE__ ) . 'js/admin.js',
                array('jquery-effects-pulsate'),
                self::VERSION,
                true
            );
            wp_localize_script( 'custom-php-settings', 'cps_params', array(
                '_ajax_nonce' => wp_create_nonce( self::CPS_NONCE ),
                'plan'        => cps_fs()->get_plan_name(),
                'i10n'        => array(
                    'Remove'  => __( 'Remove', 'custom-php-settings' ),
                    'Restore' => __( 'Restore', 'custom-php-settings' ),
                    'Show'    => __( 'Show', 'custom-php-settings' ),
                    'Hide'    => __( 'Hide', 'custom-php-settings' ),
                ),
            ) );
        }
        wp_enqueue_style(
            'custom-php-settings',
            plugin_dir_url( __FILE__ ) . 'css/admin.css',
            array(),
            self::VERSION
        );
    }

    /**
     * Check if any updates needs to be performed.
     */
    public function checkForUpgrade() {
        if ( version_compare( $this->settings->get( 'version', '' ), self::VERSION, '<' ) ) {
            $defaults = array(
                self::FIELD_SETTINGS      => array(array(
                    self::FIELD_SETTING_NAME     => __( 'Default', 'custom-php-settings' ),
                    self::FIELD_PHP              => array(),
                    self::FIELD_ENV              => array(),
                    self::FIELD_UPDATE_CONFIG    => false,
                    self::FIELD_RESTORE_CONFIG   => false,
                    self::FIELD_TRIM_COMMENTS    => true,
                    self::FIELD_TRIM_WHITESPACES => true,
                )),
                self::FIELD_NOTIFICATIONS => array(),
            );
            $defaults['notes']['support'] = array(
                'id'          => 2,
                'weight'      => 2,
                'persistent'  => true,
                'time'        => 0,
                'type'        => 'warning',
                'name'        => 'support',
                'callback'    => 'addSupportNotice',
                'dismissed'   => true,
                'dismissible' => false,
            );
            $defaults['notes']['review'] = array(
                'id'          => 1,
                'weight'      => 1,
                'persistent'  => false,
                'time'        => 0,
                'type'        => 'info',
                'name'        => 'review',
                'callback'    => 'addReviewNotice',
                'dismissed'   => false,
                'dismissible' => true,
            );
            // Update to new settings format.
            if ( $this->settings->get( self::FIELD_VERSION ) < '2.0.0' ) {
                $currentSettings = array(array(
                    self::FIELD_SETTING_NAME     => __( 'Default', 'custom-php-settings' ),
                    self::FIELD_PHP              => $this->settings->get( self::FIELD_PHP_SETTINGS, array() ),
                    self::FIELD_ENV              => array(),
                    self::FIELD_UPDATE_CONFIG    => $this->settings->get( self::FIELD_UPDATE_CONFIG, false ),
                    self::FIELD_RESTORE_CONFIG   => $this->settings->get( self::FIELD_RESTORE_CONFIG, false ),
                    self::FIELD_TRIM_COMMENTS    => $this->settings->get( self::FIELD_TRIM_COMMENTS, true ),
                    self::FIELD_TRIM_WHITESPACES => $this->settings->get( self::FIELD_TRIM_WHITESPACES, true ),
                ));
                $this->settings->remove( self::FIELD_UPDATE_CONFIG );
                $this->settings->remove( self::FIELD_RESTORE_CONFIG );
                $this->settings->remove( self::FIELD_TRIM_COMMENTS );
                $this->settings->remove( self::FIELD_TRIM_WHITESPACES );
                $this->settings->remove( self::FIELD_PHP_SETTINGS );
                $this->settings->set( self::FIELD_SETTINGS, $currentSettings );
                $this->settings->set( self::FIELD_SETTING_INDEX, 0 );
                $this->settings->set( self::FIELD_NOTIFICATIONS, $defaults['notes'] );
            }
            $notes = $this->settings->get( self::FIELD_NOTIFICATIONS );
            // Special handling for persistent notes.
            foreach ( $defaults['notes'] as $id => $note ) {
                if ( $note['persistent'] && isset( $notes[$id] ) ) {
                    $defaults['notes'][$id]['dismissed'] = $notes[$id]['dismissed'];
                }
            }
            $this->settings->set( self::FIELD_NOTIFICATIONS, $defaults['notes'] );
            // Set defaults.
            foreach ( $defaults as $key => $value ) {
                $this->settings->add( $key, $value );
            }
            $this->settings->set( self::FIELD_VERSION, self::VERSION )->save();
        }
    }

    /**
     * Set active tab and section.
     */
    protected function setTabs() {
        $this->currentTab = ( isset( $_GET['tab'] ) ? $_GET['tab'] : 'general' );
        $this->currentSection = ( isset( $_GET['section'] ) ? $_GET['section'] : 'php-info' );
    }

    /**
     * Returns the active tab.
     *
     * @return string
     */
    protected function getCurrentTab() {
        return $this->currentTab;
    }

    /**
     * Returns the active section.
     *
     * @return string
     */
    protected function getCurrentSection() {
        return $this->currentSection;
    }

    /**
     * Triggered when plugin is activated.
     */
    public static function activate() {
    }

    /**
     * Triggered when plugin is deactivated.
     * Removes any changes in the .htaccess file made by the plugin.
     */
    public static function deActivate() {
        self::removeSettings();
    }

    /**
     * Uninstalls the plugin.
     */
    public static function delete() {
        self::removeSettings();
        delete_option( self::SETTINGS_NAME );
    }

    /**
     * Remove any current settings from either .htaccess or user ini file.
     */
    protected static function removeSettings() {
        $settings = new Settings(self::SETTINGS_NAME);
        $settingIndex = $settings->get( self::FIELD_SETTING_INDEX, 0 );
        $currentSetting = $settings->get( self::FIELD_SETTINGS )[$settingIndex];
        if ( $currentSetting[self::FIELD_RESTORE_CONFIG] ) {
            $configFile = self::getConfigFilePath();
            self::addMarker(
                $configFile,
                self::MARKER,
                array(),
                ( self::getCGIMode() ? ';' : '#' )
            );
        }
    }

    /**
     * Adds customized text to footer in admin dashboard.
     *
     * @param string $footer_text
     *
     * @return string
     */
    public function adminFooter( $footer_text ) {
        $screen = get_current_screen();
        if ( $screen->id === 'toplevel_page_custom-php-settings' ) {
            $rate_text = sprintf( __( 'Thank you for using <a href="%1$s" target="_blank">Custom PHP Settings</a>! Please <a href="%2$s" target="_blank">rate us on WordPress.org</a>', 'custom-php-settings' ), 'https://wordpress.org/plugins/custom-php-settings', 'https://wordpress.org/support/plugin/custom-php-settings/reviews/?rate=5#new-post' );
            return '<span>' . $rate_text . '</span>';
        } else {
            return $footer_text;
        }
    }

    /**
     * Add menu item for plugin.
     */
    public function addMenu() {
        add_menu_page(
            __( 'Custom PHP Settings', 'custom-php-settings' ),
            __( 'Custom PHP Settings', 'custom-php-settings' ),
            $this->capability,
            self::MENU_SLUG,
            array($this, 'doSettingsPage'),
            'dashicons-cogwheel'
        );
    }

    /**
     * Add message to be displayed in settings form.
     *
     * @param string $message
     * @param string $type
     */
    protected function addSettingsMessage( $message, $type = 'error' ) {
        add_settings_error(
            'custom-php-settings',
            esc_attr( 'custom-php-settings-updated' ),
            $message,
            $type
        );
    }

    /**
     * Check if PHP is running in CGI/Fast-CGI mode or not.
     *
     * @return bool
     */
    protected static function getCGIMode() {
        return substr( php_sapi_name(), -3 ) === 'cgi';
    }

    /**
     * Gets an array of environment variables to insert into configuration file.
     *
     * @return array
     */
    protected function getVariablesAsArray() {
        $section = array();
        $section[] = '<IfModule mod_env.c>';
        $settingIndex = $this->settings->get( self::FIELD_SETTING_INDEX, 0 );
        foreach ( $this->settings->settings[$settingIndex][self::FIELD_ENV] as $key => $variable ) {
            $name = key( $variable );
            $value = $variable[$name];
            $section[] = 'SetEnv ' . $name . ' ' . $value;
        }
        $section[] = '</IfModule>';
        return $section;
    }

    /**
     * Gets an array of settings to insert into configuration file.
     *
     * @return array
     */
    protected function getSettingsAsArray() {
        $cgiMode = $this->getCGIMode();
        $section = array();
        $settingIndex = $this->settings->get( self::FIELD_SETTING_INDEX, 0 );
        foreach ( $this->settings->settings[$settingIndex][self::FIELD_PHP] as $key => $value ) {
            if ( empty( $value ) ) {
                if ( !$this->settings->settings[$settingIndex][self::FIELD_TRIM_WHITESPACES] ) {
                    $section[] = '';
                }
            } elseif ( $value[0] === '#' ) {
                if ( !$this->settings->settings[$settingIndex][self::FIELD_TRIM_COMMENTS] ) {
                    $section[] = $value;
                }
            } else {
                $setting = explode( '=', trim( $value ) );
                $section[] = ( $cgiMode ? $setting[0] . '=' . $setting[1] : 'php_value ' . $setting[0] . ' ' . $setting[1] );
            }
        }
        return $section;
    }

    /**
     * Inserts an array of strings into a file (.htaccess ), placing it between
     * BEGIN and END markers.
     *
     * Replaces existing marked info. Retains surrounding
     * data. Creates file if none exists.
     *
     * This is a customized version of insert_with_markers in core.
     *
     * @param string $filename Filename to alter.
     * @param string $marker The marker to alter.
     * @param array|string $insertion The new content to insert.
     * @param string $comment Type of character to use for comments.
     * @return bool True on write success, false on failure.
     */
    protected static function addMarker(
        $filename,
        $marker,
        $insertion,
        $comment = '#'
    ) {
        if ( !is_array( $insertion ) ) {
            $insertion = explode( "\n", $insertion );
        }
        $start_marker = "{$comment} BEGIN {$marker}";
        $end_marker = "{$comment} END {$marker}";
        $fp = @fopen( $filename, 'r+' );
        if ( !$fp ) {
            return false;
        }
        // Attempt to get a lock. If the filesystem supports locking, this will block until the lock is acquired.
        flock( $fp, LOCK_EX );
        $lines = array();
        while ( !feof( $fp ) ) {
            $lines[] = rtrim( fgets( $fp ), "\r\n" );
        }
        // Split out the existing file into the preceding lines, and those that appear after the marker
        $pre_lines = $post_lines = $existing_lines = array();
        $found_marker = $found_end_marker = false;
        foreach ( $lines as $line ) {
            if ( !$found_marker && false !== strpos( $line, $start_marker ) ) {
                $found_marker = true;
                continue;
            } elseif ( !$found_end_marker && false !== strpos( $line, $end_marker ) ) {
                $found_end_marker = true;
                continue;
            }
            if ( !$found_marker ) {
                $pre_lines[] = $line;
            } elseif ( $found_marker && $found_end_marker ) {
                $post_lines[] = $line;
            } else {
                $existing_lines[] = $line;
            }
        }
        // Check to see if there was a change
        if ( $existing_lines === $insertion ) {
            flock( $fp, LOCK_UN );
            fclose( $fp );
            return true;
        }
        // Generate the new file data
        $new_file_data = implode( "\n", array_merge(
            $pre_lines,
            array($start_marker),
            $insertion,
            array($end_marker),
            $post_lines
        ) );
        // Write to the start of the file, and truncate it to that length
        fseek( $fp, 0 );
        $bytes = fwrite( $fp, $new_file_data );
        if ( $bytes ) {
            ftruncate( $fp, ftell( $fp ) );
        }
        fflush( $fp );
        flock( $fp, LOCK_UN );
        fclose( $fp );
        return (bool) $bytes;
    }

    /**
     * Try to store settings in either .htaccess or .ini file.
     */
    protected function updateConfigFile( $fileName = null ) {
        $configFile = ( $fileName ?: self::getConfigFilePath() );
        if ( self::createIfNotExist( $configFile ) === false ) {
            /* translators: %s: Name of configuration file */
            $this->addSettingsMessage( sprintf( __( '%s does not exists or is not writable.', 'custom-php-settings' ), $configFile ) );
            return;
        }
        $section = $this->getSettingsAsArray();
        if ( !$fileName ) {
            /* translators: %s: Name of configuration file */
            $message = sprintf( __( 'Settings updated and stored in %s.', 'custom-php-settings' ), $configFile );
            if ( self::getCGIMode() ) {
                $message .= '<br />' . sprintf( __( 'You may need to wait for up to %d seconds before any changes takes effect.', 'custom-php-settings' ), ini_get( 'user_ini.cache_ttl' ) );
            }
            $this->addSettingsMessage( $message, 'updated' );
        }
        self::addMarker(
            $configFile,
            self::MARKER,
            $section,
            ( self::getCGIMode() ? ';' : '#' )
        );
    }

    /**
     * Check so file exists and is writable.
     *
     * @param string $filename
     *
     * @return bool
     */
    protected static function createIfNotExist( $filename ) {
        $fp = null;
        if ( !file_exists( $filename ) ) {
            if ( !is_writable( dirname( $filename ) ) ) {
                return false;
            }
            if ( !touch( $filename ) ) {
                return false;
            }
            // Make sure the file is created with a minimum set of permissions.
            $perms = fileperms( $filename );
            if ( $perms ) {
                chmod( $filename, $perms | 0644 );
            }
        } elseif ( !($fp = @fopen( $filename, 'a' )) ) {
            return false;
        }
        if ( $fp ) {
            fclose( $fp );
        }
    }

    /**
     * Return information about the WordPress environment.
     *
     * @return array
     */
    protected function getWordPressInfo() {
        $fields = array(
            __( 'Version', 'custom-php-settings' )                 => 'version',
            __( 'Name', 'custom-php-settings' )                    => 'name',
            __( 'Description', 'custom-php-settings' )             => 'description',
            __( 'WordPress Address (URL)', 'custom-php-settings' ) => 'wpurl',
            __( 'Site Address (URL)', 'custom-php-settings' )      => 'url',
            __( 'Stylesheet URL', 'custom-php-settings' )          => 'stylesheet_url',
            __( 'Stylesheet Directory', 'custom-php-settings' )    => 'stylesheet_directory',
            __( 'Template URL', 'custom-php-settings' )            => 'template_url',
            __( 'Pingback URL', 'custom-php-settings' )            => 'pingback_url',
            __( 'Admin Email', 'custom-php-settings' )             => 'admin_email',
            __( 'Charset', 'custom-php-settings' )                 => 'charset',
            __( 'HTML Type', 'custom-php-settings' )               => 'html_type',
            __( 'Language', 'custom-php-settings' )                => 'language',
        );
        $data = array();
        foreach ( $fields as $key => $field ) {
            $data[$key] = get_bloginfo( $field );
        }
        $data = array_merge( $data, array(
            __( 'Text Direction', 'custom-php-settings' )   => ( is_rtl() ? 'rtl' : 'ltr' ),
            __( 'Multisite', 'custom-php-settings' )        => __( ( is_multisite() ? 'yes' : 'no' ), 'custom-php-settings' ),
            __( 'Debug mode', 'custom-php-settings' )       => __( ( WP_DEBUG ? 'yes' : 'no' ), 'custom-php-settings' ),
            __( 'Memory limit', 'custom-php-settings' )     => WP_MEMORY_LIMIT,
            __( 'Cron', 'custom-php-settings' )             => __( ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ? 'disabled' : 'enabled' ), 'custom-php-settings' ),
            __( 'Timezone', 'custom-php-settings' )         => wp_timezone_string(),
            __( 'Development Mode', 'custom-php-settings' ) => wp_get_development_mode(),
            __( 'Environment Type', 'custom-php-settings' ) => wp_get_environment_type(),
            __( 'Server Software', 'custom-php-settings' )  => ( isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : 'N/A' ),
        ) );
        return $data;
    }

    /**
     * Returns information about the database environment.
     *
     * @return array
     */
    protected function getDatabaseInfo() {
        global $wpdb;
        $host = $wpdb->dbhost;
        $host = explode( ':', $host );
        $port = 3306;
        if ( count( $host ) > 1 ) {
            $port = (int) $host[1];
        }
        $host = $host[0];
        return array(
            __( 'Version', 'custom-php-settings' )   => $wpdb->db_server_info(),
            __( 'Database', 'custom-php-settings' )  => $wpdb->dbname,
            __( 'User', 'custom-php-settings' )      => $wpdb->dbuser,
            __( 'Password', 'custom-php-settings' )  => $wpdb->dbpassword,
            __( 'Host', 'custom-php-settings' )      => $host,
            __( 'Port', 'custom-php-settings' )      => $port,
            __( 'Prefix', 'custom-php-settings' )    => $wpdb->get_blog_prefix( get_current_blog_id() ),
            __( 'Charset', 'custom-php-settings' )   => $wpdb->charset,
            __( 'Collation', 'custom-php-settings' ) => $wpdb->collate,
        );
    }

    /**
     * Validates so a line is either a comment, blank line or a valid setting.
     *
     * @param string $setting
     *
     * @return int
     */
    protected function isValidSetting( $setting ) {
        $iniSettings = array_keys( $this->getIniSettings() );
        $setting = explode( '=', preg_replace( '/("[^"\\r\\n]+")|\\s*/', '\\1', html_entity_decode( $setting ) ) );
        // Lock down for specific settings for the free version.
        $lockedSettings = array();
        $lockedSettings = [
            'max_file_uploads',
            'max_input_vars',
            'max_input_time',
            'post_max_size'
        ];
        $iniSettings = array_filter( $iniSettings, function ( $setting ) use($lockedSettings) {
            return !in_array( $setting, $lockedSettings );
        } );
        if ( count( $setting ) === 1 ) {
            if ( strlen( $setting[0] ) === 0 ) {
                // This is a blank line.
                return 2;
            } elseif ( $setting[0][0] === '#' ) {
                // This is a comment.
                return 2;
            } elseif ( in_array( $setting[0], $iniSettings ) ) {
                /* translators: %s: Name of PHP setting */
                $this->addSettingsMessage( sprintf( __( '%s must be in the format: key=value', 'custom-php-settings' ), $setting[0] ) . '<br />' );
                return -2;
            }
        } elseif ( count( $setting ) === 2 ) {
            if ( !cps_fs()->is__premium_only() && in_array( $setting[0], $lockedSettings ) ) {
                /* translators: %s: Name of PHP setting */
                $this->addSettingsMessage( sprintf( __( 'You need to use the <a href="' . cps_fs()->get_upgrade_url() . '">premium version</a> to change the %s value.', 'custom-php-settings' ), $setting[0] ) . '<br />' );
                return -1;
            }
            if ( in_array( $setting[0], $iniSettings ) ) {
                // This is a valid setting.
                return 1;
            } elseif ( $setting[0][0] === '#' ) {
                // this is a comment
                return 2;
            }
        }
        /* translators: %s: Name of PHP setting */
        $this->addSettingsMessage( sprintf( __( '%s is not a valid setting.', 'custom-php-settings' ), $setting[0] ) . '<br />' );
        return -1;
    }

    /**
     * Check if a setting with the specific name exists.
     *
     * @param string $name
     * @return bool
     */
    protected function settingExists( $name ) {
        $names = array_map( function ( $setting ) {
            return $setting[self::FIELD_SETTING_NAME];
        }, $this->settings->get( self::FIELD_SETTINGS ) );
        return in_array( $name, $names );
    }

    /**
     * Returns the current active setting array.
     *
     * @return mixed
     */
    protected function getCurrentSetting() {
        $settingIndex = $this->settings->get( self::FIELD_SETTING_INDEX, 0 );
        return $this->settings->get( self::FIELD_SETTINGS )[$settingIndex];
    }

    /**
     * Handle form data for configuration page.
     */
    public function saveSettings() {
        // Verify nonce and referer.
        check_admin_referer( 'custom-php-settings-action', 'custom-php-settings-nonce' );
        // Validate so user has correct privileges.
        if ( !current_user_can( $this->capability ) ) {
            die( __( 'You are not allowed to perform this action.', 'custom-php-settings' ) );
        }
        if ( filter_input( INPUT_POST, 'custom-php-settings', FILTER_UNSAFE_RAW ) ) {
            // Filter and sanitize form values.
            $settings = array();
            $raw_settings = filter_input( INPUT_POST, 'settings', FILTER_UNSAFE_RAW );
            $raw_settings = array_map( 'trim', explode( PHP_EOL, trim( $raw_settings ) ) );
            foreach ( $raw_settings as $key => $value ) {
                if ( ($type = $this->isValidSetting( $value )) > 0 ) {
                    if ( $type === 1 ) {
                        // Remove whitespaces in everything but quotes.
                        $setting = explode( '=', preg_replace( '/("[^"\\r\\n]+")|\\s*/', '\\1', html_entity_decode( $value ) ) );
                        $settings[$key] = str_replace( ';', '', implode( '=', $setting ) );
                    } else {
                        $settings[$key] = str_replace( ';', '', $value );
                    }
                }
            }
            $currentSettings = $this->settings->get( self::FIELD_SETTINGS );
            $settingIndex = $this->settings->get( self::FIELD_SETTING_INDEX, 0 );
            $currentSettings[$settingIndex][self::FIELD_PHP] = $settings;
            $currentSettings[$settingIndex][self::FIELD_UPDATE_CONFIG] = (bool) filter_input( INPUT_POST, 'update_config', FILTER_VALIDATE_BOOLEAN );
            $currentSettings[$settingIndex][self::FIELD_RESTORE_CONFIG] = (bool) filter_input( INPUT_POST, 'restore_config', FILTER_VALIDATE_BOOLEAN );
            $currentSettings[$settingIndex][self::FIELD_TRIM_COMMENTS] = (bool) filter_input( INPUT_POST, 'trim_comments', FILTER_VALIDATE_BOOLEAN );
            $currentSettings[$settingIndex][self::FIELD_TRIM_WHITESPACES] = (bool) filter_input( INPUT_POST, 'trim_whitespaces', FILTER_VALIDATE_BOOLEAN );
            $this->settings->set( self::FIELD_SETTINGS, $currentSettings );
            $this->settings->save();
            if ( $currentSettings[$settingIndex][self::FIELD_UPDATE_CONFIG] ) {
                $this->updateConfigFile();
            }
            // Check if we should activate the support notification.
            if ( ($notice = $this->getNoticeByName( 'support' )) && $notice['time'] === 0 ) {
                $this->resetNotice( $notice['id'] );
            }
        }
        set_transient( 'cps_settings_errors', get_settings_errors() );
        wp_safe_redirect( wp_get_referer() );
    }

    /**
     * Returns absolute path to configuration file.
     */
    protected static function getConfigFilePath() {
        return get_home_path() . (( self::getCGIMode() ? ini_get( 'user_ini.filename' ) : '.htaccess' ));
    }

    /**
     * Get all non-system settings.
     *
     * @return array
     */
    protected function getIniSettings() {
        return array_filter( ini_get_all(), function ( $item ) {
            return $item['access'] !== INI_SYSTEM;
        } );
    }

    /**
     * Display the settings page.
     */
    public function doSettingsPage() {
        // Display any settings messages
        $setting_errors = get_transient( 'cps_settings_errors' );
        if ( $setting_errors ) {
            foreach ( $setting_errors as $error ) {
                $this->addSettingsMessage( $error['message'], $error['type'] );
            }
            delete_transient( 'cps_settings_errors' );
        }
        if ( $this->getCurrentTab() === 'info' && $this->getCurrentSection() ) {
            $template = __DIR__ . '/views/cps-' . $this->currentSection . '.php';
        } else {
            $template = __DIR__ . '/views/cps-' . $this->currentTab . '.php';
        }
        if ( file_exists( $template ) ) {
            require_once $template;
        }
    }

    /**
     * Format bytes
     *
     * @param $bytes
     * @param int $precision
     * @return string
     */
    public function formatBytes( $bytes, $precision = 2 ) {
        $units = array(
            'B',
            'KB',
            'MB',
            'GB',
            'TB'
        );
        $bytes = max( $bytes, 0 );
        $pow = floor( (( $bytes ? log( $bytes ) : 0 )) / log( 1024 ) );
        $pow = min( $pow, count( $units ) - 1 );
        $bytes /= pow( 1024, $pow );
        // $bytes /= (1 << (10 * $pow));
        return round( $bytes, $precision ) . ' ' . $units[$pow];
    }

}
