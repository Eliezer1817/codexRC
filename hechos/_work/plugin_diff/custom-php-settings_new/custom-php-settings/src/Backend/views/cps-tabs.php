<?php

use function CustomPhpSettings\cps_fs;
$variables_order = ini_get( 'variables_order' );
$tabs = array(
    'general'  => array(
        'label' => __( 'Editor', 'custom-php-settings' ),
    ),
    'settings' => array(
        'label' => __( 'Settings', 'custom-php-settings' ),
    ),
    'info'     => array(
        'label'    => __( 'PHP Information', 'custom-php-settings' ),
        'children' => array(
            'php-info'   => array(
                'label' => __( 'PHP', 'custom-php-settings' ),
            ),
            'extensions' => array(
                'label' => __( 'Extensions', 'custom-php-settings' ),
            ),
        ),
    ),
);
if ( strstr( php_sapi_name(), 'apache' ) ) {
    $tabs['apache'] = array(
        'label' => __( 'Apache', 'custom-php-settings' ),
    );
}
if ( strchr( $variables_order, 'C' ) && !empty( $_COOKIE ) ) {
    $tabs['info']['children']['cookie-vars'] = array(
        'label' => __( '$_COOKIE', 'custom-php-settings' ),
    );
}
if ( strchr( $variables_order, 'S' ) && !empty( $_SERVER ) ) {
    $tabs['info']['children']['server-vars'] = array(
        'label' => __( '$_SERVER', 'custom-php-settings' ),
    );
}
if ( strchr( $variables_order, 'E' ) && !empty( $_ENV ) ) {
    $tabs['info']['children']['env-vars'] = array(
        'label' => __( '$_ENV', 'custom-php-settings' ),
    );
}
$tabs['status'] = array(
    'label' => __( 'Status', 'custom-php-settings' ),
);
?>
<h2></h2>
<h2 class="nav-tab-wrapper">
    <?php 
foreach ( $tabs as $key => $item ) {
    ?>
        <?php 
    $active = ( $key === $this->getCurrentTab() ? ' nav-tab-active' : '' );
    ?>
        <a class="nav-tab<?php 
    echo $active;
    ?>"
           href="<?php 
    echo admin_url( 'admin.php?page=custom-php-settings&tab=' . $key );
    ?>"><?php 
    echo $item['label'];
    ?></a>
    <?php 
}
?>
    <?php 
foreach ( $tabs as $key => $item ) {
    ?>
        <?php 
    $active = ( $key === $this->getCurrentTab() ? ' nav-tab-active' : '' );
    ?>
        <?php 
    if ( $active && isset( $item['children'] ) ) {
        ?>
            <h3 class="nav-tab-wrapper">
                <?php 
        foreach ( $item['children'] as $subKey => $subItem ) {
            ?>
                    <?php 
            $active = ( $subKey === $this->getCurrentSection() ? ' nav-tab-active' : '' );
            ?>
                    <a class="nav-tab nav-tab-small<?php 
            echo $active;
            ?>"
                       href="<?php 
            echo admin_url( 'admin.php?page=custom-php-settings&tab=' . $key . '&section=' . $subKey );
            ?>">
                        <?php 
            echo $subItem['label'];
            ?>
                    </a>
                <?php 
        }
        ?>
            </h3>
        <?php 
    }
    ?>
    <?php 
}
?>
</h2>
