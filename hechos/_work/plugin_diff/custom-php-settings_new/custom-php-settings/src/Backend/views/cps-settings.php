<?php
$ini_settings = $this->getIniSettings();
?>
<div class="wrap custom-php-settings">
    <?php require_once('cps-tabs.php'); ?>
    <input type="text" id="search" name="search" placeholder="<?php _e('Search for settings', 'custom-php-settings'); ?>" />
    <input type="checkbox" id="cbkModified" /> Show customized
    <table class="custom-php-settings-table widefat">
        <thead>
            <th><?php echo __('Name', 'custom-php-settings'); ?></th>
            <th><?php echo __('Value', 'custom-php-settings'); ?></th>
            <th><?php echo __('Default', 'custom-php-settings'); ?></th>
            <th></th>
        </thead>
        <?php foreach ($ini_settings as $key => $value) : ?>
        <?php $class = ($value['global_value'] !== $value['local_value'] ? 'modified' : ''); ?>
        <tr class="<?php echo $class; ?>">
            <td><?php echo $key; ?></td>
            <td><?php echo $value['local_value']; ?></td>
            <td><?php echo $value['global_value']; ?></td>
            <td><span title="<?php _e('Copy', 'custom-php-settings'); ?>" class="dashicons dashicons-clipboard"></span></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>
