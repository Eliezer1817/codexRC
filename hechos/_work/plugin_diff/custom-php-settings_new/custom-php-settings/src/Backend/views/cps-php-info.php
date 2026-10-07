<?php
$env = array(
    __('System name', 'custom-php-settings') => php_uname(),
    __('Architecture', 'custom-php-settings') => PHP_INT_SIZE === 8 ? 'x64' : 'x86',
    __('PHP Version', 'custom-php-settings') => phpversion(),
    __('Debug build', 'custom-php-settings') => __(defined('ZEND_DEBUG_BUILD') && ZEND_DEBUG_BUILD ? 'yes' : 'no', 'custom-php-settings'),
    __('Zend Engine version', 'custom-php-settings') => zend_version(),
    __('Server Api', 'custom-php-settings') => php_sapi_name(),
    __('Configuration File (php.ini) Path', 'custom-php-settings') => defined('PHP_CONFIG_FILE_PATH') ? PHP_CONFIG_FILE_PATH : '',
    __('Extension directory', 'custom-php-settings') => defined('PHP_EXTENSION_DIR') ? PHP_EXTENSION_DIR : '',
    __('Loaded configuration file', 'custom-php-settings') => php_ini_loaded_file(),
    __('Additional configuration files', 'custom-php-settings') => php_ini_scanned_files(),
    __('Include path', 'custom-php-settings') => get_include_path(),
    __('PHP Script Owner', 'custom-php-settings') => get_current_user(),
    __('PHP Script Owner UID', 'custom-php-settings') => getmyuid(),
    __('PHP Script Owner GUID', 'custom-php-settings') => getmygid(),
    __('PHP process ID', 'custom-php-settings') => getmypid(),
    __('Memory usage', 'custom-php-settings') => $this->formatBytes(memory_get_usage()),
    __('Memory peak usage', 'custom-php-settings') => $this->formatBytes(memory_get_peak_usage()),
    __('Temporary directory', 'custom-php-settings') => sys_get_temp_dir(),
    __('User INI file', 'custom-php-settings') => ini_get('user_ini.filename'),
    __('User INI file cache TTL', 'custom-php-settings') => ini_get('user_ini.cache_ttl'),
    __('Thread Safety', 'custom-php-settings') => __(defined('ZEND_THREAD_SAFE') && ZEND_THREAD_SAFE ? 'enabled' : 'disabled', 'custom-php-settings'),
    __('IPv6 Support', 'custom-php-settings') => __(extension_loaded('sockets') && defined('AF_INET6') ? 'enabled' : 'disabled', 'custom-php-settings'),
    __('PHP Streams', 'custom-php-settings') => implode(', ', stream_get_wrappers()),
    __('Stream Socket Transports', 'custom-php-settings') => implode(', ', stream_get_transports()),
    __('Stream Filters', 'custom-php-settings') => implode(', ', stream_get_filters()),
    __('GC enabled', 'custom-php-settings') => __(gc_enabled() ? 'enabled' : 'disabled', 'custom-php-settings'),
);
?>
<div class="wrap">
    <?php require_once('cps-tabs.php'); ?>
    <table class="custom-php-settings-table widefat">
        <thead>
            <th><?php echo __('Name', 'custom-php-settings'); ?></th>
            <th><?php echo __('Value', 'custom-php-settings'); ?></th>
        </thead>
        <?php foreach ($env as $key => $value) : ?>
        <tr>
            <td><?php echo esc_html($key); ?></td>
            <td><?php echo esc_html($value); ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>
