<?php
$settings = array(
    __('Version', 'custom-php-settings') => apache_get_version(),
    __('Loaded Modules', 'custom-php-settings') => implode(', ', apache_get_modules()),
);
?>
<div class="wrap">
    <?php require_once('cps-tabs.php'); ?>
    <table class="custom-php-settings-table widefat">
        <thead>
            <th><?php echo __('Name', 'custom-php-settings'); ?></th>
            <th><?php echo __('Value', 'custom-php-settings'); ?></th>
        </thead>
        <?php foreach ($settings as $key => $value) : ?>
            <tr>
                <td><?php echo $key; ?></td>
                <td><?php echo $value; ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
</div>
