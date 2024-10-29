<?php
/**
 * Plugin Name: Analytical Spam Filter
 * Plugin URI: https://wordpress.org/plugins/analytical-spam-filter/
 * Description: Block WordPress comment, trackback, and pingback spam through logical reasoning instead of interactive challenge response tests.
 * Version: 1.0.13
 * Author: John Dalesandro
 * Author URI: https://johndalesandro.com/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: analytical-spam-filter
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'ANALYTICAL_SPAM_FILTER_FILE' ) ) {
	define( 'ANALYTICAL_SPAM_FILTER_FILE', __FILE__ );
}

if ( ! class_exists( 'Analytical_Spam_Filter' ) ) {
	require_once trailingslashit( dirname( ANALYTICAL_SPAM_FILTER_FILE ) ) . 'classes/class-analytical-spam-filter.php';
}

if ( is_admin() && ! class_exists( 'Analytical_Spam_Filter_Settings' ) ) {
	require_once trailingslashit( dirname( ANALYTICAL_SPAM_FILTER_FILE ) ) . 'classes/class-analytical-spam-filter-settings.php';
}
