<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Analytical_Spam_Filter_Settings' ) ) {
	class Analytical_Spam_Filter_Settings {
		private $options;

		public function __construct() {
			add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );
			add_action( 'admin_init', array( $this, 'page_init' ) );
			add_filter( 'plugin_action_links_' . plugin_basename( ANALYTICAL_SPAM_FILTER_FILE ), array( $this, 'plugin_action_links_handler' ) );
		}

		private function database_get_max_age_date( $age, $time_interval ) {
			global $wpdb;

			if ( in_array( $time_interval, array( 'MINUTE', 'HOUR', 'DAY', 'WEEK', 'MONTH', 'YEAR' ), true ) ) {
				if ( $age > 0 ) {
					$sql = 'SELECT %s - INTERVAL %d ' . esc_attr( $time_interval ) . ';';
					return $wpdb->get_var( $wpdb->prepare( $sql, current_time( 'mysql' ), $age ) );
				} else {
					return 0;
				}
			} else {
				return 0;
			}

			return 0;
		}

		public function add_plugin_page() {
			add_options_page( __( 'Analytical Spam Filter', 'analytical-spam-filter' ), __( 'Analytical Spam Filter', 'analytical-spam-filter' ), 'manage_options', 'analytical-spam-filter-settings', array( $this, 'create_admin_page' ) );
		}

		public function create_admin_page() {
			$this->options = get_option( 'analytical_spam_filter_settings_db' );

			echo( '<div class="wrap"><h1>' . esc_html__( 'Analytical Spam Filter', 'analytical-spam-filter' ) . '</h1><form method="post" action="options.php">' );

			settings_fields( 'analytical-spam-filter-settings-group' );
			do_settings_sections( 'analytical-spam-filter-settings' );
			submit_button();

			echo( '</form></div>' );
		}

		public function page_init() {
			register_setting( 'analytical-spam-filter-settings-group', 'analytical_spam_filter_settings_db', array( $this, 'sanitize' ) );

			add_settings_section( 'analytical-spam-filter-settings-section-general', __( 'General Settings', 'analytical-spam-filter' ), array( $this, 'print_section_info_general' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'notify_admin_spam_only_diagnostic', __( 'Notify Administrator For Blocked Spam Only (Diagnostic Information)?', 'analytical-spam-filter' ), array( $this, 'notify_admin_spam_only_diagnostic_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );
			add_settings_field( 'notify_admin_valid_only_diagnostic', __( 'Notify Administrator For Valid Submissions Only (Diagnostic Information)?', 'analytical-spam-filter' ), array( $this, 'notify_admin_valid_only_diagnostic_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );
			add_settings_field( 'notify_admin_all_diagnostic', __( 'Notify Administrator For All Submissions (Diagnostic Information)?', 'analytical-spam-filter' ), array( $this, 'notify_admin_all_diagnostic_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );
			add_settings_field( 'expose_rejection_reasons', __( 'Expose Comment Rejection Reasons to Submitter?', 'analytical-spam-filter' ), array( $this, 'expose_rejection_reasons_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );
			add_settings_field( 'flag_as_spam', __( 'Flag Comment as Spam?', 'analytical-spam-filter' ), array( $this, 'flag_as_spam_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );
			add_settings_field( 'use_ajax', __( 'Enable Cache Compatibility?', 'analytical-spam-filter' ), array( $this, 'use_ajax_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-general' );

			add_settings_section( 'analytical-spam-filter-settings-section-basic', __( 'Basic Blocking Techniques', 'analytical-spam-filter' ), array( $this, 'print_section_info_basic' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'trackbacks_allowed', __( 'Allow Trackbacks?', 'analytical-spam-filter' ), array( $this, 'trackbacks_allowed_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-basic' );
			add_settings_field( 'pingbacks_allowed', __( 'Allow Pingbacks?', 'analytical-spam-filter' ), array( $this, 'pingbacks_allowed_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-basic' );
			add_settings_field( 'user_agent_required', __( 'User-Agent Required?', 'analytical-spam-filter' ), array( $this, 'user_agent_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-basic' );
			add_settings_field( 'check_referer', __( 'Check Referer?', 'analytical-spam-filter' ), array( $this, 'check_referer_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-basic' );
			add_settings_field( 'use_honeypot_blocking', __( 'Use Honeypot Blocking?', 'analytical-spam-filter' ), array( $this, 'use_honeypot_blocking_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-basic' );

			add_settings_section( 'analytical-spam-filter-settings-section-timestamp', __( 'Timestamp Blocking', 'analytical-spam-filter' ), array( $this, 'print_section_info_timestamp' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'use_timestamp_blocking', __( 'Use Timestamp Blocking?', 'analytical-spam-filter' ), array( $this, 'use_timestamp_blocking_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );
			add_settings_field( 'timestamp_allowed_age_min', __( 'Minimum Time between Initial Page Load and Form Submission (Seconds)', 'analytical-spam-filter' ), array( $this, 'timestamp_allowed_age_min_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );
			add_settings_field( 'timestamp_allowed_age_max', __( 'Maximum Time between Initial Page Load and Form Submission (Seconds)', 'analytical-spam-filter' ), array( $this, 'timestamp_allowed_age_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );

			add_settings_field( 'use_duration_blocking', __( 'Use Duration Blocking?', 'analytical-spam-filter' ), array( $this, 'use_duration_blocking_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );
			add_settings_field( 'duration_allowed_age_min', __( 'Minimum Time Spent Actively Completing Form (Seconds)', 'analytical-spam-filter' ), array( $this, 'duration_allowed_age_min_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );
			add_settings_field( 'duration_allowed_age_max', __( 'Maximum Time Spent Actively Completing Form (Seconds)', 'analytical-spam-filter' ), array( $this, 'duration_allowed_age_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-timestamp' );

			add_settings_section( 'analytical-spam-filter-settings-section-url', __( 'URL Blocking', 'analytical-spam-filter' ), array( $this, 'print_section_info_url' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'use_url_count_blocking', __( 'Use URL Count Blocking?', 'analytical-spam-filter' ), array( $this, 'use_url_count_blocking_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-url' );
			add_settings_field( 'number_of_urls_allowed', __( 'Number of URLs Allowed', 'analytical-spam-filter' ), array( $this, 'number_of_urls_allowed_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-url' );

			add_settings_section( 'analytical-spam-filter-settings-section-submitter', __( 'IP Blocking', 'analytical-spam-filter' ), array( $this, 'print_section_info_submitter' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'count_submissions', __( 'Count Spam Submissions Per Submitter?', 'analytical-spam-filter' ), array( $this, 'use_history_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-submitter' );
			add_settings_field( 'submissions_allowed_count_max', __( 'Maximum Number of Allowed Spam Submissions', 'analytical-spam-filter' ), array( $this, 'submissions_allowed_count_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-submitter' );
			add_settings_field( 'submissions_allowed_age_max', __( 'How Long to Track Spam Submissions Per Submitter', 'analytical-spam-filter' ), array( $this, 'allowed_age_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-submitter' );
			add_settings_field( 'submissions_allowed_age_max_interval', __( 'Time Interval', 'analytical-spam-filter' ), array( $this, 'submissions_allowed_age_max_interval_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-submitter' );
			add_settings_field( 'do_not_notify_admin_submitter_spam', __( 'Do Not Notify Administrator After Submitter Spam Exceeds Threshold', 'analytical-spam-filter' ), array( $this, 'do_not_notify_admin_submitter_spam_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-submitter' );

			add_settings_section( 'analytical-spam-filter-settings-section-content', __( 'Content Blocking', 'analytical-spam-filter' ), array( $this, 'print_section_info_content' ), 'analytical-spam-filter-settings' );

			add_settings_field( 'similar_submissions', __( 'Track Spam Submissions By Content?', 'analytical-spam-filter' ), array( $this, 'similar_submissions_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-content' );
			add_settings_field( 'similar_submissions_allowed_count_max', __( 'Maximum Number of Similar Submissions By Content', 'analytical-spam-filter' ), array( $this, 'similar_submissions_allowed_count_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-content' );
			add_settings_field( 'similar_submissions_allowed_age_max', __( 'How Long to Track Spam Submissions By Content', 'analytical-spam-filter' ), array( $this, 'similar_submissions_allowed_age_max_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-content' );
			add_settings_field( 'similar_submissions_allowed_age_max_interval', __( 'Time Interval', 'analytical-spam-filter' ), array( $this, 'similar_submissions_allowed_age_max_interval_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-content' );
			add_settings_field( 'do_not_notify_admin_similar_spam', __( 'Do Not Notify Administrator After Similar Spam Exceeds Threshold', 'analytical-spam-filter' ), array( $this, 'do_not_notify_admin_similar_spam_callback' ), 'analytical-spam-filter-settings', 'analytical-spam-filter-settings-section-content' );
		}

		public function plugin_action_links_handler( $links ) {
			$settings_link = '<a href="' . admin_url( 'options-general.php?page=analytical-spam-filter-settings' ) . '">' . esc_html__( 'Settings', 'analytical-spam-filter' ) . '</a>';
			array_unshift( $links, $settings_link );

			return $links;
		}

		public function print_section_info_general() {
			esc_html_e( 'Configure general settings for notifications, flagging, and cache compatibility.', 'analytical-spam-filter' );
		}

		public function print_section_info_basic() {
			esc_html_e( 'Configure basic techniques to block spam submissions.', 'analytical-spam-filter' );
		}

		public function print_section_info_timestamp() {
			esc_html_e( 'Configure timestamp-based spam blocking. Automated submissions typically occur in less than 1 second. This technique attempts to block bots by establishing minimum and maximum time thresholds for submissions.', 'analytical-spam-filter' );
		}

		public function print_section_info_url() {
			esc_html_e( 'Configure URL-based spam blocking. Spam submissions typically include many URLs or links. This technique uses a more aggressive counting method than the default WordPress option to identify spam submissions.', 'analytical-spam-filter' );
		}

		public function print_section_info_submitter() {
			esc_html_e( 'Configure IP-based spam blocking. Technique tracks spam submissions based on IP address over time. IP addresses with previously approved submissions are never flagged as spam.', 'analytical-spam-filter' );
		}

		public function print_section_info_content() {
			esc_html_e( 'Configure content-based spam blocking. Technique tracks spam submissions based on content. Spam submissions from different IP addresses but containing the same message are blocked. Submissions containing previously approved content are never flagged as spam.', 'analytical-spam-filter' );
		}

		public function use_timestamp_blocking_callback() {
			echo( '<input type="checkbox" id="use_timestamp_blocking" name="analytical_spam_filter_settings_db[use_timestamp_blocking]" value="1"' . checked( 1, ( isset( $this->options['use_timestamp_blocking'] ) ? esc_attr( $this->options['use_timestamp_blocking'] ) : 1 ), false ) . '/>' );
			echo( '<label for="use_timestamp_blocking">' . esc_html__( 'This method tracks the time spent between the initial page load and the form submission.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function use_duration_blocking_callback() {
			echo( '<input type="checkbox" id="use_duration_blocking" name="analytical_spam_filter_settings_db[use_duration_blocking]" value="1"' . checked( 1, ( isset( $this->options['use_duration_blocking'] ) ? esc_attr( $this->options['use_duration_blocking'] ) : 1 ), false ) . '/>' );
			echo( '<label for="use_duration_blocking">' . esc_html__( 'This method tracks the time spent by the submitter actively completing the form; JavaScript, jQuery, and Ajax are required.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function use_honeypot_blocking_callback() {
			echo( '<input type="checkbox" id="use_honeypot_blocking" name="analytical_spam_filter_settings_db[use_honeypot_blocking]" value="1"' . checked( 1, ( isset( $this->options['use_honeypot_blocking'] ) ? esc_attr( $this->options['use_honeypot_blocking'] ) : 1 ), false ) . '/>' );
			echo( '<label for="use_honeypot_blocking">' . esc_html__( 'This method adds a field to the form that is hidden from view. It is meant to trap bots that add data to all available fields (including the honeypot).', 'analytical-spam-filter' ) . '</label>' );
		}

		public function use_url_count_blocking_callback() {
			echo( '<input type="checkbox" id="use_url_count_blocking" name="analytical_spam_filter_settings_db[use_url_count_blocking]" value="1"' . checked( 1, ( isset( $this->options['use_url_count_blocking'] ) ? esc_attr( $this->options['use_url_count_blocking'] ) : 1 ), false ) . '/>' );
		}

		public function check_referer_callback() {
			echo( '<input type="checkbox" id="check_referer" name="analytical_spam_filter_settings_db[check_referer]" value="1"' . checked( 1, ( isset( $this->options['check_referer'] ) ? esc_attr( $this->options['check_referer'] ) : 1 ), false ) . '/>' );
			echo( '<label for="check_referer">' . esc_html__( 'Checks if the submission is from a valid referring page. This method excludes trackbacks and pingbacks.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function user_agent_callback() {
			echo( '<input type="checkbox" id="user_agent_required" name="analytical_spam_filter_settings_db[user_agent_required]" value="1"' . checked( 1, ( isset( $this->options['user_agent_required'] ) ? esc_attr( $this->options['user_agent_required'] ) : 1 ), false ) . '/>' );
			echo( '<label for="user_agent_required">' . esc_html__( 'Requires the submitter to have a browser User-Agent string. This method excludes trackbacks and pingbacks.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function trackbacks_allowed_callback() {
			echo( '<input type="checkbox" id="trackbacks_allowed" name="analytical_spam_filter_settings_db[trackbacks_allowed]" value="1"' . checked( 1, ( isset( $this->options['trackbacks_allowed'] ) ? esc_attr( $this->options['trackbacks_allowed'] ) : 0 ), false ) . '/>' );
		}

		public function pingbacks_allowed_callback() {
			echo( '<input type="checkbox" id="pingbacks_allowed" name="analytical_spam_filter_settings_db[pingbacks_allowed]" value="1"' . checked( 1, ( isset( $this->options['pingbacks_allowed'] ) ? esc_attr( $this->options['pingbacks_allowed'] ) : 0 ), false ) . '/>' );
		}

		public function expose_rejection_reasons_callback() {
			echo( '<input type="checkbox" id="expose_rejection_reasons" name="analytical_spam_filter_settings_db[expose_rejection_reasons]" value="1"' . checked( 1, ( isset( $this->options['expose_rejection_reasons'] ) ? esc_attr( $this->options['expose_rejection_reasons'] ) : 0 ), false ) . '/>' );
			echo( '<label for="expose_rejection_reasons">' . esc_html__( 'In addition to the standard rejection message, display all reasons for the comment rejection to the submitter. This setting is ignored if the "Flag Comment as Spam" setting is active.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function notify_admin_spam_only_diagnostic_callback() {
			echo( '<input type="checkbox" id="notify_admin_spam_only_diagnostic" name="analytical_spam_filter_settings_db[notify_admin_spam_only_diagnostic]" value="1"' . checked( 1, ( isset( $this->options['notify_admin_spam_only_diagnostic'] ) ? esc_attr( $this->options['notify_admin_spam_only_diagnostic'] ) : 1 ), false ) . '/>' );
			echo( '<label for="notify_admin_spam_only_diagnostic">' . esc_html__( 'Site administrator receives e-mail containing diagnostic information for submissions identified as spam.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function notify_admin_valid_only_diagnostic_callback() {
			echo( '<input type="checkbox" id="notify_admin_valid_only_diagnostic" name="analytical_spam_filter_settings_db[notify_admin_valid_only_diagnostic]" value="1"' . checked( 1, ( isset( $this->options['notify_admin_valid_only_diagnostic'] ) ? esc_attr( $this->options['notify_admin_valid_only_diagnostic'] ) : 1 ), false ) . '/>' );
			echo( '<label for="notify_admin_valid_only_diagnostic">' . esc_html__( 'Site administrator receives e-mail containing diagnostic information for submissions not identified as spam, e.g. valid submissions that passed the spam filters.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function notify_admin_all_diagnostic_callback() {
			echo( '<input type="checkbox" id="notify_admin_all_diagnostic" name="analytical_spam_filter_settings_db[notify_admin_all_diagnostic]" value="1"' . checked( 1, ( isset( $this->options['notify_admin_all_diagnostic'] ) ? esc_attr( $this->options['notify_admin_all_diagnostic'] ) : 1 ), false ) . '/>' );
			echo( '<label for="notify_admin_all_diagnostic">' . esc_html__( 'Site administrator receives e-mail containing diagnostic information for all submissions (both valid and spam).', 'analytical-spam-filter' ) . '</label>' );
		}

		public function flag_as_spam_callback() {
			echo( '<input type="checkbox" id="flag_as_spam" name="analytical_spam_filter_settings_db[flag_as_spam]" value="1"' . checked( 1, ( isset( $this->options['flag_as_spam'] ) ? esc_attr( $this->options['flag_as_spam'] ) : 1 ), false ) . '/>' );
			echo( '<label for="flag_as_spam">' . esc_html__( 'Option adds the comment to the spam queue; unchecking will block the comment entirely.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function use_ajax_callback() {
			echo( '<input type="checkbox" id="use_ajax" name="analytical_spam_filter_settings_db[use_ajax]" value="1"' . checked( 1, ( isset( $this->options['use_ajax'] ) ? esc_attr( $this->options['use_ajax'] ) : 1 ), false ) . '/>' );
			echo( '<label for="use_ajax">' . esc_html__( 'Option enables compatibility with caching plugins; JavaScript, jQuery, and Ajax are required. Option may be used as an additional spam filter, even if the site does not use caching, since bots do not typically use JavaScript.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function timestamp_allowed_age_min_callback() {
			echo( '<input type="text" id="timestamp_allowed_age_min" name="analytical_spam_filter_settings_db[timestamp_allowed_age_min]" value="' . ( isset( $this->options['timestamp_allowed_age_min'] ) ? esc_attr( $this->options['timestamp_allowed_age_min'] ) : 8 ) . '" />' );
			echo( '<label for="timestamp_allowed_age_min">' . esc_html__( '(in seconds)', 'analytical-spam-filter' ) . '</label>' );
		}

		public function timestamp_allowed_age_max_callback() {
			echo( '<input type="text" id="timestamp_allowed_age_max" name="analytical_spam_filter_settings_db[timestamp_allowed_age_max]" value="' . ( isset( $this->options['timestamp_allowed_age_max'] ) ? esc_attr( $this->options['timestamp_allowed_age_max'] ) : 172800 ) . '" />' );
			echo( '<label for="timestamp_allowed_age_max">' . esc_html__( '(in seconds)', 'analytical-spam-filter' ) . '</label>' );
		}

		public function duration_allowed_age_min_callback() {
			echo( '<input type="text" id="duration_allowed_age_min" name="analytical_spam_filter_settings_db[duration_allowed_age_min]" value="' . ( isset( $this->options['duration_allowed_age_min'] ) ? esc_attr( $this->options['duration_allowed_age_min'] ) : 2 ) . '" />' );
			echo( '<label for="duration_allowed_age_min">' . esc_html__( '(in seconds)', 'analytical-spam-filter' ) . '</label>' );
		}

		public function duration_allowed_age_max_callback() {
			echo( '<input type="text" id="duration_allowed_age_max" name="analytical_spam_filter_settings_db[duration_allowed_age_max]" value="' . ( isset( $this->options['duration_allowed_age_max'] ) ? esc_attr( $this->options['duration_allowed_age_max'] ) : 7200 ) . '" />' );
			echo( '<label for="duration_allowed_age_max">' . esc_html__( '(in seconds)', 'analytical-spam-filter' ) . '</label>' );
		}

		public function number_of_urls_allowed_callback() {
			echo( '<input type="text" id="number_of_urls_allowed" name="analytical_spam_filter_settings_db[number_of_urls_allowed]" value="' . ( isset( $this->options['number_of_urls_allowed'] ) ? esc_attr( $this->options['number_of_urls_allowed'] ) : 1 ) . '" />' );
			echo( '<label for="number_of_urls_allowed">' . esc_html__( 'Method validates against the Author Name and Comment fields.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function use_history_callback() {
			echo( '<input type="checkbox" id="use_history" name="analytical_spam_filter_settings_db[use_history]" value="1"' . checked( 1, ( isset( $this->options['use_history'] ) ? esc_attr( $this->options['use_history'] ) : 1 ), false ) . '/>' );
			echo( '<label for="use_history">' . esc_html__( 'Option tracks the number of blocked spam submissions per submitter; automatically flag additional submissions after the specified count is reached within the specified time period.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function submissions_allowed_count_max_callback() {
			echo( '<input type="text" id="submissions_allowed_count_max" name="analytical_spam_filter_settings_db[submissions_allowed_count_max]" value="' . ( isset( $this->options['submissions_allowed_count_max'] ) ? esc_attr( $this->options['submissions_allowed_count_max'] ) : 2 ) . '" />' );
			echo( '<label for="submissions_allowed_count_max">' . esc_html__( 'Number of submissions allowed per submitter before additional submissions are automatically flagged as spam (must be greater than zero).', 'analytical-spam-filter' ) . '</label>' );
		}

		public function allowed_age_max_callback() {
			echo( '<input type="text" id="submissions_allowed_age_max" name="analytical_spam_filter_settings_db[submissions_allowed_age_max]" value="' . ( isset( $this->options['submissions_allowed_age_max'] ) ? esc_attr( $this->options['submissions_allowed_age_max'] ) : 0 ) . '" />' );
			echo( '<label for="submissions_allowed_age_max">' . esc_html__( 'Count the number of spam submissions by submitter in the defined time duration? Zero uses all available data.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function submissions_allowed_age_max_interval_callback() {
			$b_use_default = false;
			$selected = ' selected';

			if ( ! isset( $this->options['submissions_allowed_age_max_interval'] ) || empty( $this->options['submissions_allowed_age_max_interval'] ) ) {
				$b_use_default = true;
			}

			echo( '<select id="submissions_allowed_age_max_interval" name="analytical_spam_filter_settings_db[submissions_allowed_age_max_interval]">' );
			echo( '<option value="MINUTE"' . ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'MINUTE' == $this->options['submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'MINUTE', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="HOUR"' . ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'HOUR' == $this->options['submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'HOUR', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="DAY"' . ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'DAY' == $this->options['submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'DAY', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="WEEK"' . ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'WEEK' == $this->options['submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'WEEK', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="MONTH"' . ( ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'MONTH' == $this->options['submissions_allowed_age_max_interval'] ) || $b_use_default ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'MONTH', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="YEAR"' . ( ( isset( $this->options['submissions_allowed_age_max_interval'] ) && 'YEAR' == $this->options['submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'YEAR', 'analytical-spam-filter' ) . '</option>' );
			echo( '</select>' );

			$age = ( isset( $this->options['submissions_allowed_age_max'] ) ? $this->options['submissions_allowed_age_max'] : 0 );
			$time_interval = ( isset( $this->options['submissions_allowed_age_max_interval'] ) ? $this->options['submissions_allowed_age_max_interval'] : 'MONTH' );
			$expiry_timestamp = $this->database_get_max_age_date( $age, $time_interval );

			if ( ! empty( $expiry_timestamp ) ) {
				$date_format = get_option( 'date_format' );
				$time_format = get_option( 'time_format' );
				$expiry = date_format( date_create( $expiry_timestamp ), $date_format . ' ' . $time_format );

				/* translators: %s: expiry date and time */
				echo( '<label for="submissions_allowed_age_max_interval">' . esc_html( sprintf( __( 'Time interval to count within. Currently configured to remove entries older than %s.', 'analytical-spam-filter' ), $expiry ) ) . '</label>' );
			} else {
				echo( '<label for="submissions_allowed_age_max_interval">' . esc_html__( 'Time interval to count within. Currently configured to never remove entries.', 'analytical-spam-filter' ) . '</label>' );
			}
		}

		public function do_not_notify_admin_submitter_spam_callback() {
			echo( '<input type="text" id="do_not_notify_admin_submitter_spam" name="analytical_spam_filter_settings_db[do_not_notify_admin_submitter_spam]" value="' . ( isset( $this->options['do_not_notify_admin_submitter_spam'] ) ? esc_attr( $this->options['do_not_notify_admin_submitter_spam'] ) : 0 ) . '" />' );
			echo( '<label for="do_not_notify_admin_submitter_spam">' . esc_html__( 'Do not notify the site administrator after the number of spam submissions by a submitter exceeds this threshold. Zero ignores this setting and follows the Notify Administrator With Blocked Spam setting.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function similar_submissions_callback() {
			echo( '<input type="checkbox" id="similar_submissions" name="analytical_spam_filter_settings_db[similar_submissions]" value="1"' . checked( 1, ( isset( $this->options['similar_submissions'] ) ? esc_attr( $this->options['similar_submissions'] ) : 1 ), false ) . '/>' );
			echo( '<label for="similar_submissions">' . esc_html__( 'Option tracks the number of blocked spam submissions based on content; automatically flag additional submissions after the specified count is reached within the specified time period.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function similar_submissions_allowed_count_max_callback() {
			echo( '<input type="text" id="similar_submissions_allowed_count_max" name="analytical_spam_filter_settings_db[similar_submissions_allowed_count_max]" value="' . ( isset( $this->options['similar_submissions_allowed_count_max'] ) ? esc_attr( $this->options['similar_submissions_allowed_count_max'] ) : 2 ) . '" />' );
			echo( '<label for="similar_submissions_allowed_count_max">' . esc_html__( 'Number of similar submissions allowed before additional submissions are automatically flagged as spam (must be greater than zero).', 'analytical-spam-filter' ) . '</label>' );
		}

		public function similar_submissions_allowed_age_max_callback() {
			echo( '<input type="text" id="similar_submissions_allowed_age_max" name="analytical_spam_filter_settings_db[similar_submissions_allowed_age_max]" value="' . ( isset( $this->options['similar_submissions_allowed_age_max'] ) ? esc_attr( $this->options['similar_submissions_allowed_age_max'] ) : 0 ) . '" />' );
			echo( '<label for="similar_submissions_allowed_age_max">' . esc_html__( 'Count the number of spam submissions with similar content in the defined time duration? Zero uses all available data.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function similar_submissions_allowed_age_max_interval_callback() {
			$b_use_default = false;
			$selected = ' selected';

			if ( ! isset( $this->options['similar_submissions_allowed_age_max_interval'] ) || empty( $this->options['similar_submissions_allowed_age_max_interval'] ) ) {
				$b_use_default = true;
			}

			echo( '<select id="similar_submissions_allowed_age_max_interval" name="analytical_spam_filter_settings_db[similar_submissions_allowed_age_max_interval]">' );
			echo( '<option value="MINUTE"' . ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'MINUTE' == $this->options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'MINUTE', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="HOUR"' . ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'HOUR' == $this->options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'HOUR', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="DAY"' . ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'DAY' == $this->options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'DAY', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="WEEK"' . ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'WEEK' == $this->options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'WEEK', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="MONTH"' . ( ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'MONTH' == $this->options['similar_submissions_allowed_age_max_interval'] ) || $b_use_default ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'MONTH', 'analytical-spam-filter' ) . '</option>' );
			echo( '<option value="YEAR"' . ( ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) && 'YEAR' == $this->options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $selected ) : '' ) . '>' . esc_html__( 'YEAR', 'analytical-spam-filter' ) . '</option>' );
			echo( '</select>' );

			$age = ( isset( $this->options['similar_submissions_allowed_age_max'] ) ? $this->options['similar_submissions_allowed_age_max'] : 0 );
			$time_interval = ( isset( $this->options['similar_submissions_allowed_age_max_interval'] ) ? $this->options['similar_submissions_allowed_age_max_interval'] : 'MONTH' );
			$expiry_timestamp = $this->database_get_max_age_date( $age, $time_interval );

			if ( ! empty( $expiry_timestamp ) ) {
				$date_format = get_option( 'date_format' );
				$time_format = get_option( 'time_format' );
				$expiry = date_format( date_create( $expiry_timestamp ), $date_format . ' ' . $time_format );

				/* translators: %s: expiry date and time */
				echo( '<label for="similar_submissions_allowed_age_max_interval">' . esc_html( sprintf( __( 'Time interval to count within. Currently configured to remove entries older than %s.', 'analytical-spam-filter' ), $expiry ) ) . '</label>' );
			} else {
				echo( '<label for="similar_submissions_allowed_age_max_interval">' . esc_html__( 'Time interval to count within. Currently configured to never remove entries.', 'analytical-spam-filter' ) . '</label>' );
			}
		}

		public function do_not_notify_admin_similar_spam_callback() {
			echo( '<input type="text" id="do_not_notify_admin_similar_spam" name="analytical_spam_filter_settings_db[do_not_notify_admin_similar_spam]" value="' . ( isset( $this->options['do_not_notify_admin_similar_spam'] ) ? esc_attr( $this->options['do_not_notify_admin_similar_spam'] ) : 0 ) . '" />' );
			echo( '<label for="do_not_notify_admin_similar_spam">' . esc_html__( 'Do not notify the site administrator after the number of spam submissions with similar content exceeds this threshold. Zero ignores this setting and follows the Notify Administrator With Blocked Spam setting.', 'analytical-spam-filter' ) . '</label>' );
		}

		public function sanitize( $input ) {
			$b_use_timestamp_blocking = 1;
			$b_use_duration_blocking = 1;
			$b_use_honeypot_blocking = 1;
			$b_use_url_count_blocking = 1;
			$b_check_referer = 1;
			$b_user_agent_required = 1;
			$b_trackbacks_allowed = 0;
			$b_pingbacks_allowed = 0;
			$b_expose_rejection_reasons = 0;
			$b_notify_admin_spam_only_diagnostic = 1;
			$b_notify_admin_valid_only_diagnostic = 1;
			$b_notify_admin_all_diagnostic = 1;
			$b_flag_as_spam = 1;
			$b_use_ajax = 1;
			$timestamp_allowed_age_min = 8;
			$timestamp_allowed_age_max = 172800;
			$duration_allowed_age_min = 2;
			$duration_allowed_age_max = 7200;
			$number_of_urls_allowed = 1;
			$b_use_history = 1;
			$submissions_allowed_count_max = 2;
			$submissions_allowed_age_max = 0;
			$submissions_allowed_age_max_interval = 'MONTH';
			$do_not_notify_admin_submitter_spam = 0;
			$b_use_similar_message_filter = 1;
			$similar_submissions_allowed_count_max = 2;
			$similar_submissions_allowed_age_max = 0;
			$similar_submissions_allowed_age_interval = 'MONTH';
			$do_not_notify_admin_similar_spam = 0;

			$sanitized_input = array();

			if ( isset( $input['use_timestamp_blocking'] ) ) {
				if ( 1 == intval( $input['use_timestamp_blocking'] ) ) {
					$b_use_timestamp_blocking = 1;
				} else {
					$b_use_timestamp_blocking = 0;
				}
			} else {
				$b_use_timestamp_blocking = 0;
			}
			$sanitized_input['use_timestamp_blocking'] = $b_use_timestamp_blocking;

			if ( isset( $input['use_duration_blocking'] ) ) {
				if ( 1 == intval( $input['use_duration_blocking'] ) ) {
					$b_use_duration_blocking = 1;
				} else {
					$b_use_duration_blocking = 0;
				}
			} else {
				$b_use_duration_blocking = 0;
			}
			$sanitized_input['use_duration_blocking'] = $b_use_duration_blocking;

			if ( isset( $input['use_honeypot_blocking'] ) ) {
				if ( 1 == intval( $input['use_honeypot_blocking'] ) ) {
					$b_use_honeypot_blocking = 1;
				} else {
					$b_use_honeypot_blocking = 0;
				}
			} else {
				$b_use_honeypot_blocking = 0;
			}
			$sanitized_input['use_honeypot_blocking'] = $b_use_honeypot_blocking;

			if ( isset( $input['use_url_count_blocking'] ) ) {
				if ( 1 == intval( $input['use_url_count_blocking'] ) ) {
					$b_use_url_count_blocking = 1;
				} else {
					$b_use_url_count_blocking = 0;
				}
			} else {
				$b_use_url_count_blocking = 0;
			}
			$sanitized_input['use_url_count_blocking'] = $b_use_url_count_blocking;

			if ( isset( $input['check_referer'] ) ) {
				if ( 1 == intval( $input['check_referer'] ) ) {
					$b_check_referer = 1;
				} else {
					$b_check_referer = 0;
				}
			} else {
				$b_check_referer = 0;
			}
			$sanitized_input['check_referer'] = $b_check_referer;

			if ( isset( $input['user_agent_required'] ) ) {
				if ( 1 == intval( $input['user_agent_required'] ) ) {
					$b_user_agent_required = 1;
				} else {
					$b_user_agent_required = 0;
				}
			} else {
				$b_user_agent_required = 0;
			}
			$sanitized_input['user_agent_required'] = $b_user_agent_required;

			if ( isset( $input['trackbacks_allowed'] ) ) {
				if ( 1 == intval( $input['trackbacks_allowed'] ) ) {
					$b_trackbacks_allowed = 1;
				} else {
					$b_trackbacks_allowed = 0;
				}
			} else {
				$b_trackbacks_allowed = 0;
			}
			$sanitized_input['trackbacks_allowed'] = $b_trackbacks_allowed;

			if ( isset( $input['pingbacks_allowed'] ) ) {
				if ( 1 == intval( $input['pingbacks_allowed'] ) ) {
					$b_pingbacks_allowed = 1;
				} else {
					$b_pingbacks_allowed = 0;
				}
			} else {
				$b_pingbacks_allowed = 0;
			}
			$sanitized_input['pingbacks_allowed'] = $b_pingbacks_allowed;

			if ( isset( $input['expose_rejection_reasons'] ) ) {
				if ( 1 == intval( $input['expose_rejection_reasons'] ) ) {
					$b_expose_rejection_reasons = 1;
				} else {
					$b_expose_rejection_reasons = 0;
				}
			} else {
				$b_expose_rejection_reasons = 0;
			}
			$sanitized_input['expose_rejection_reasons'] = $b_expose_rejection_reasons;

			if ( isset( $input['notify_admin_spam_only_diagnostic'] ) ) {
				if ( 1 == intval( $input['notify_admin_spam_only_diagnostic'] ) ) {
					$b_notify_admin_spam_only_diagnostic = 1;
				} else {
					$b_notify_admin_spam_only_diagnostic = 0;
				}
			} else {
				$b_notify_admin_spam_only_diagnostic = 0;
			}
			$sanitized_input['notify_admin_spam_only_diagnostic'] = $b_notify_admin_spam_only_diagnostic;

			if ( isset( $input['notify_admin_valid_only_diagnostic'] ) ) {
				if ( 1 == intval( $input['notify_admin_valid_only_diagnostic'] ) ) {
					$b_notify_admin_valid_only_diagnostic = 1;
				} else {
					$b_notify_admin_valid_only_diagnostic = 0;
				}
			} else {
				$b_notify_admin_valid_only_diagnostic = 0;
			}
			$sanitized_input['notify_admin_valid_only_diagnostic'] = $b_notify_admin_valid_only_diagnostic;

			if ( isset( $input['notify_admin_all_diagnostic'] ) ) {
				if ( 1 == intval( $input['notify_admin_all_diagnostic'] ) ) {
					$b_notify_admin_all_diagnostic = 1;
				} else {
					$b_notify_admin_all_diagnostic = 0;
				}
			} else {
				$b_notify_admin_all_diagnostic = 0;
			}
			$sanitized_input['notify_admin_all_diagnostic'] = $b_notify_admin_all_diagnostic;

			if ( isset( $input['flag_as_spam'] ) ) {
				if ( 1 == intval( $input['flag_as_spam'] ) ) {
					$b_flag_as_spam = 1;
				} else {
					$b_flag_as_spam = 0;
				}
			} else {
				$b_flag_as_spam = 0;
			}
			$sanitized_input['flag_as_spam'] = $b_flag_as_spam;

			if ( isset( $input['use_ajax'] ) ) {
				if ( 1 == intval( $input['use_ajax'] ) ) {
					$b_use_ajax = 1;
				} else {
					$b_use_ajax = 0;
				}
			} else {
				$b_use_ajax = 0;
			}
			$sanitized_input['use_ajax'] = $b_use_ajax;

			if ( isset( $input['use_history'] ) ) {
				if ( 1 == intval( $input['use_history'] ) ) {
					$b_use_history = 1;
				} else {
					$b_use_history = 0;
				}
			} else {
				$b_use_history = 0;
			}
			$sanitized_input['use_history'] = $b_use_history;

			if ( isset( $input['timestamp_allowed_age_min'] ) ) {
				$timestamp_allowed_age_min = absint( $input['timestamp_allowed_age_min'] );

				if ( 0 == $timestamp_allowed_age_min ) {
					$timestamp_allowed_age_min = 8;
				}
			}
			$sanitized_input['timestamp_allowed_age_min'] = $timestamp_allowed_age_min;

			if ( isset( $input['timestamp_allowed_age_max'] ) ) {
				$timestamp_allowed_age_max = absint( $input['timestamp_allowed_age_max'] );

				if ( 0 == $timestamp_allowed_age_max ) {
					$timestamp_allowed_age_max = 172800;
				}

				if ( $timestamp_allowed_age_max <= $timestamp_allowed_age_min ) {
					$timestamp_allowed_age_max = $timestamp_allowed_age_min + 1;
				}
			}
			$sanitized_input['timestamp_allowed_age_max'] = $timestamp_allowed_age_max;

			if ( isset( $input['duration_allowed_age_min'] ) ) {
				$duration_allowed_age_min = absint( $input['duration_allowed_age_min'] );

				if ( 0 == $duration_allowed_age_min ) {
					$duration_allowed_age_min = 2;
				}
			}
			$sanitized_input['duration_allowed_age_min'] = $duration_allowed_age_min;

			if ( isset( $input['duration_allowed_age_max'] ) ) {
				$duration_allowed_age_max = absint( $input['duration_allowed_age_max'] );

				if ( 0 == $duration_allowed_age_max ) {
					$duration_allowed_age_max = 7200;
				}

				if ( $duration_allowed_age_max <= $duration_allowed_age_min ) {
					$duration_allowed_age_max = $duration_allowed_age_min + 1;
				}
			}
			$sanitized_input['duration_allowed_age_max'] = $duration_allowed_age_max;

			if ( isset( $input['number_of_urls_allowed'] ) ) {
				$number_of_urls_allowed = absint( $input['number_of_urls_allowed'] );
			}
			$sanitized_input['number_of_urls_allowed'] = $number_of_urls_allowed;

			if ( isset( $input['submissions_allowed_count_max'] ) ) {
				$submissions_allowed_count_max = absint( $input['submissions_allowed_count_max'] );
			}
			$sanitized_input['submissions_allowed_count_max'] = $submissions_allowed_count_max;

			if ( isset( $input['submissions_allowed_age_max'] ) ) {
				$submissions_allowed_age_max = absint( $input['submissions_allowed_age_max'] );
			}
			$sanitized_input['submissions_allowed_age_max'] = $submissions_allowed_age_max;

			if ( isset( $input['do_not_notify_admin_submitter_spam'] ) ) {
				$do_not_notify_admin_submitter_spam = absint( $input['do_not_notify_admin_submitter_spam'] );
			}
			$sanitized_input['do_not_notify_admin_submitter_spam'] = $do_not_notify_admin_submitter_spam;

			if ( isset( $input['similar_submissions'] ) ) {
				if ( 1 == intval( $input['similar_submissions'] ) ) {
					$b_use_similar_message_filter = 1;
				} else {
					$b_use_similar_message_filter = 0;
				}
			} else {
				$b_use_similar_message_filter = 0;
			}
			$sanitized_input['similar_submissions'] = $b_use_similar_message_filter;

			if ( isset( $input['similar_submissions_allowed_count_max'] ) ) {
				$similar_submissions_allowed_count_max = absint( $input['similar_submissions_allowed_count_max'] );
			}
			$sanitized_input['similar_submissions_allowed_count_max'] = $similar_submissions_allowed_count_max;

			if ( isset( $input['similar_submissions_allowed_age_max'] ) ) {
				$similar_submissions_allowed_age_max = absint( $input['similar_submissions_allowed_age_max'] );
			}
			$sanitized_input['similar_submissions_allowed_age_max'] = $similar_submissions_allowed_age_max;

			if ( isset( $input['submissions_allowed_age_max_interval'] ) ) {
				if ( in_array( $input['submissions_allowed_age_max_interval'], array( 'MINUTE', 'HOUR', 'DAY', 'WEEK', 'MONTH', 'YEAR' ), true ) ) {
					$submissions_allowed_age_max_interval = $input['submissions_allowed_age_max_interval'];
				} else {
					$submissions_allowed_age_max_interval = 'MONTH';
				}
			} else {
				$submissions_allowed_age_max_interval = 'MONTH';
			}
			$sanitized_input['submissions_allowed_age_max_interval'] = $submissions_allowed_age_max_interval;

			if ( isset( $input['similar_submissions_allowed_age_max_interval'] ) ) {
				if ( in_array( $input['similar_submissions_allowed_age_max_interval'], array( 'MINUTE', 'HOUR', 'DAY', 'WEEK', 'MONTH', 'YEAR' ), true ) ) {
					$similar_submissions_allowed_age_interval = $input['similar_submissions_allowed_age_max_interval'];
				} else {
					$similar_submissions_allowed_age_interval = 'MONTH';
				}
			} else {
				$similar_submissions_allowed_age_interval = 'MONTH';
			}
			$sanitized_input['similar_submissions_allowed_age_max_interval'] = $similar_submissions_allowed_age_interval;

			if ( isset( $input['do_not_notify_admin_similar_spam'] ) ) {
				$do_not_notify_admin_similar_spam = absint( $input['do_not_notify_admin_similar_spam'] );
			}
			$sanitized_input['do_not_notify_admin_similar_spam'] = $do_not_notify_admin_similar_spam;

			return $sanitized_input;
		}
	}
}

if ( class_exists( 'Analytical_Spam_Filter_Settings' ) ) {
	if ( is_admin() ) {
		$analytical_spam_filter_settings = new Analytical_Spam_Filter_Settings();
	}
}
