<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'analytical_spam_filter_salt' );
delete_option( 'analytical_spam_filter_hash_field_id' );
delete_option( 'analytical_spam_filter_honeypot_field_id' );
delete_option( 'analytical_spam_filter_duration_field_id' );
delete_option( 'analytical_spam_filter_settings_db' );
delete_option( 'analytical_spam_filter_database_version' );

global $wpdb;

$sql = "DROP TABLE IF EXISTS `{$wpdb->prefix}analytical_spam_filter_submitter_history`;";
$wpdb->query( $sql );

$sql = "DROP TABLE IF EXISTS `{$wpdb->prefix}analytical_spam_filter_content_history`;";
$wpdb->query( $sql );
