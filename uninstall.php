<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) exit;
delete_option('brea_options');
if ( function_exists('is_multisite') && is_multisite() ) {
    delete_site_option('brea_network_options');
}
