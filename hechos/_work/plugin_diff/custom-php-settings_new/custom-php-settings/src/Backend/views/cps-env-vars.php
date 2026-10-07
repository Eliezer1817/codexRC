<div class="wrap">
    <?php require_once('cps-tabs.php'); ?>
    <table class="custom-php-settings-table widefat">
        <thead>
            <th><?php echo __('Name', 'custom-php-settings'); ?></th>
            <th><?php echo __('Value', 'custom-php-settings'); ?></th>
        </thead>
        <?php foreach ($_ENV as $name => $value) : ?>
        <tr>
            <td><?php echo esc_html($name); ?></td>
            <td><?php echo esc_html($value); ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>
