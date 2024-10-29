<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Analytical_Spam_Filter' ) ) {
	class Analytical_Spam_Filter {

		public function __construct() {
			add_action( 'init', array( $this, 'init' ) );
		}

		public function activate() {
			update_option( 'analytical_spam_filter_salt', $this->generate_salt() );
			update_option( 'analytical_spam_filter_hash_field_id', $this->generate_random_string( 12 ) );
			update_option( 'analytical_spam_filter_honeypot_field_id', $this->generate_random_string( 12 ) );
			update_option( 'analytical_spam_filter_duration_field_id', $this->generate_random_string( 12 ) );

			$this->database_create_submitter_spam_history_table();
			$this->database_create_content_spam_history_table();
			$this->database_update_version();

			if ( ! wp_next_scheduled( 'analytical_spam_filter_cron_hook' ) ) {
				wp_schedule_event( time(), 'daily', 'analytical_spam_filter_cron_hook' );
			}
		}

		public function deactivate() {
			$timestamp = wp_next_scheduled( 'analytical_spam_filter_cron_hook' );
			wp_unschedule_event( $timestamp, 'analytical_spam_filter_cron_hook' );
		}

		public function init() {
			add_action( 'plugins_loaded', array( $this, 'load_textdomain_handler' ) );
			add_action( 'wp_loaded', array( $this, 'insert_hooks_in_forms' ) );
			add_action( 'analytical_spam_filter_cron_hook', array( $this, 'database_cron_maintenance' ) );
			add_action( 'unspammed_comment', array( $this, 'database_delete_unspammed_spam_content_history' ), 10, 2 );
			add_action( 'spammed_comment', array( $this, 'database_insert_spammed_content_history' ), 10, 2 );
		}

		private function sanitize_ip( $ip ) {
			$ip = trim( preg_replace( '~[^0-9a-fA-F:., ]~', '', $ip ) );

			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			} else {
				return '';
			}
		}

		private function database_does_table_exist( $table_name ) {
			global $wpdb;

			if ( empty( $table_name ) ) {
				return false;
			}

			$sql = 'SHOW TABLES LIKE %s;';

			if ( $wpdb->get_var( $wpdb->prepare( $sql, $wpdb->esc_like( $table_name ) ) ) == $table_name ) {
				return true;
			}

			return false;
		}

		private function database_create_submitter_spam_history_table() {
			global $wpdb;

			$charset_collate = $wpdb->get_charset_collate();

			if ( ! $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_submitter_history" ) ) {
				$sql = "CREATE TABLE {$wpdb->prefix}analytical_spam_filter_submitter_history (
						id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
						submitter varbinary(16) NOT NULL,
						time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
						PRIMARY KEY  (id)
						) {$charset_collate};";

				include_once ABSPATH . 'wp-admin/includes/upgrade.php';
				dbDelta( $sql );
			}
		}

		private function database_create_content_spam_history_table() {
			global $wpdb;

			$charset_collate = $wpdb->get_charset_collate();

			if ( ! $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) ) {
				$sql = "CREATE TABLE {$wpdb->prefix}analytical_spam_filter_content_history (
						id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
						hash_val binary(64) NOT NULL,
						time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
						PRIMARY KEY  (id)
						) {$charset_collate};";

				include_once ABSPATH . 'wp-admin/includes/upgrade.php';
				dbDelta( $sql );
			}
		}

		private function database_update_version() {
			update_option( 'analytical_spam_filter_database_version', '1.0.0' );
		}

		private function database_insert_submitter_spam_history_record( $submitter ) {
			global $wpdb;

			$approved_count = 0;

			$submitter = $this->sanitize_ip( $submitter );

			if ( $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "SELECT COUNT(*) FROM `{$wpdb->comments}` WHERE comment_approved = '1' and comment_author_IP = %s;";
				$approved_count = $wpdb->get_var( $wpdb->prepare( $sql, $submitter ) );
			}

			if ( empty( $approved_count ) ) {
				if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_submitter_history" ) ) {
					$sql = "INSERT INTO `{$wpdb->prefix}analytical_spam_filter_submitter_history` (submitter, time) VALUES (inet6_aton(%s), %s);";
					$wpdb->query( $wpdb->prepare( $sql, $submitter, current_time( 'mysql' ) ) );
				}
			}
		}

		private function database_insert_content_spam_history_record( $message ) {
			global $wpdb;

			$approved_count = 0;

			if ( $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "SELECT COUNT(*) FROM `{$wpdb->comments}` WHERE comment_approved = '1' and LOWER(TRIM(comment_content)) = %s;";
				$approved_count = $wpdb->get_var( $wpdb->prepare( $sql, strtolower( trim( $message ) ) ) );
			}

			if ( empty( $approved_count ) ) {
				if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) ) {
					$sql = "INSERT INTO `{$wpdb->prefix}analytical_spam_filter_content_history` (hash_val, time) VALUES (UNHEX(SHA2(LOWER(TRIM(%s)), 512)), %s);";
					$wpdb->query( $wpdb->prepare( $sql, strtolower( trim( $message ) ), current_time( 'mysql' ) ) );
				}
			}
		}

		private function database_get_submitter_spam_history_count( $age, $time_interval, $submitter ) {
			global $wpdb;

			$approved_count = 0;

			$submitter = $this->sanitize_ip( $submitter );

			if ( $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "SELECT COUNT(*) FROM `{$wpdb->comments}` WHERE comment_approved = '1' and comment_author_IP = %s;";
				$approved_count = $wpdb->get_var( $wpdb->prepare( $sql, $submitter ) );
			}

			if ( empty( $approved_count ) ) {
				if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_submitter_history" ) ) {
					if ( $age > 0 ) {
						$sql = "SELECT COUNT(*) FROM `{$wpdb->prefix}analytical_spam_filter_submitter_history` WHERE submitter = inet6_aton(%s) AND time >= %s - INTERVAL %d " . esc_attr( $time_interval ) . ';';
						return $wpdb->get_var( $wpdb->prepare( $sql, $submitter, current_time( 'mysql' ), $age ) );
					} else {
						$sql = "SELECT COUNT(*) FROM `{$wpdb->prefix}analytical_spam_filter_submitter_history` WHERE submitter = inet6_aton(%s);";
						return $wpdb->get_var( $wpdb->prepare( $sql, $submitter ) );
					}
				} else {
					return -1;
				}
			} else {
				return -1;
			}

			return -1;
		}

		private function database_get_content_spam_history_count( $age, $time_interval, $message ) {
			global $wpdb;

			$approved_count = 0;

			if ( $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "SELECT COUNT(*) FROM `{$wpdb->comments}` WHERE comment_approved = '1' and LOWER(TRIM(comment_content)) = %s;";
				$approved_count = $wpdb->get_var( $wpdb->prepare( $sql, strtolower( trim( $message ) ) ) );
			}

			if ( empty( $approved_count ) ) {
				if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) ) {
					if ( $age > 0 ) {
						$sql = "SELECT COUNT(*) FROM `{$wpdb->prefix}analytical_spam_filter_content_history` WHERE hash_val = UNHEX(SHA2(LOWER(TRIM(%s)), 512)) AND time >= %s - INTERVAL %d " . esc_attr( $time_interval ) . ';';
						return $wpdb->get_var( $wpdb->prepare( $sql, strtolower( trim( $message ) ), current_time( 'mysql' ), $age ) );
					} else {
						$sql = "SELECT COUNT(*) FROM `{$wpdb->prefix}analytical_spam_filter_content_history` WHERE hash_val = UNHEX(SHA2(LOWER(TRIM(%s)), 512));";
						return $wpdb->get_var( $wpdb->prepare( $sql, strtolower( trim( $message ) ) ) );
					}
				} else {
					return -1;
				}
			} else {
				return -1;
			}

			return -1;
		}

		public function database_delete_unspammed_spam_content_history( $comment_id, $comment ) {
			global $wpdb;

			if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) ) {
				if ( $comment ) {
					$sql = "DELETE FROM `{$wpdb->prefix}analytical_spam_filter_content_history` WHERE hash_val = UNHEX(SHA2(LOWER(TRIM(%s)), 512));";
					$wpdb->query( $wpdb->prepare( $sql, strtolower( trim( $comment->comment_content ) ) ) );
				}
			}
		}

		public function database_insert_spammed_content_history( $comment_id, $comment ) {
			global $wpdb;

			if ( $comment ) {
				$this->database_insert_content_spam_history_record( $comment->comment_content );
			}
		}

		public function database_cron_maintenance() {
			$this->database_cron_maintenance_delete_expired_spam_submitter_history();
			$this->database_cron_maintenance_delete_expired_spam_content_history();
			$this->database_cron_maintenance_delete_submitter_history_where_approved();
			$this->database_cron_maintenance_delete_spam_content_history_where_approved();
		}

		private function database_cron_maintenance_delete_expired_spam_submitter_history() {
			global $wpdb;

			$options = get_option( 'analytical_spam_filter_settings_db' );
			$submissions_allowed_age_max = ( isset( $options['submissions_allowed_age_max'] ) ? esc_attr( $options['submissions_allowed_age_max'] ) : 0 );
			$submissions_allowed_age_max_interval = ( isset( $options['submissions_allowed_age_max_interval'] ) ? esc_attr( $options['submissions_allowed_age_max_interval'] ) : 'MONTH' );

			if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_submitter_history" ) ) {
				if ( $submissions_allowed_age_max > 0 ) {
					$sql = "DELETE FROM `{$wpdb->prefix}analytical_spam_filter_submitter_history` WHERE time < %s - INTERVAL %d " . esc_attr( $submissions_allowed_age_max_interval ) . ';';
					$wpdb->query( $wpdb->prepare( $sql, current_time( 'mysql' ), $submissions_allowed_age_max ) );
				}
			}
		}

		private function database_cron_maintenance_delete_expired_spam_content_history() {
			global $wpdb;

			$options = get_option( 'analytical_spam_filter_settings_db' );
			$similar_submissions_allowed_age_max = ( isset( $options['similar_submissions_allowed_age_max'] ) ? esc_attr( $options['similar_submissions_allowed_age_max'] ) : 0 );
			$similar_submissions_allowed_age_max_interval = ( isset( $options['similar_submissions_allowed_age_max_interval'] ) ? esc_attr( $options['similar_submissions_allowed_age_max_interval'] ) : 'MONTH' );

			if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) ) {
				if ( $similar_submissions_allowed_age_max > 0 ) {
					$sql = "DELETE FROM `{$wpdb->prefix}analytical_spam_filter_content_history` WHERE time < %s - INTERVAL %d " . esc_attr( $similar_submissions_allowed_age_max_interval ) . ';';
					$wpdb->query( $wpdb->prepare( $sql, current_time( 'mysql' ), $similar_submissions_allowed_age_max ) );
				}
			}
		}

		private function database_cron_maintenance_delete_submitter_history_where_approved() {
			global $wpdb;

			if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_submitter_history" ) && $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "DELETE `{$wpdb->prefix}analytical_spam_filter_submitter_history` FROM `{$wpdb->prefix}analytical_spam_filter_submitter_history` INNER JOIN `{$wpdb->comments}` WHERE `{$wpdb->prefix}analytical_spam_filter_submitter_history`.submitter = inet6_aton(`{$wpdb->comments}`.comment_author_IP) AND `{$wpdb->comments}`.comment_approved = '1';";
				$wpdb->query( $sql );
			}
		}

		private function database_cron_maintenance_delete_spam_content_history_where_approved() {
			global $wpdb;

			if ( $this->database_does_table_exist( "{$wpdb->prefix}analytical_spam_filter_content_history" ) && $this->database_does_table_exist( "{$wpdb->comments}" ) ) {
				$sql = "DELETE `{$wpdb->prefix}analytical_spam_filter_content_history` FROM `{$wpdb->prefix}analytical_spam_filter_content_history` INNER JOIN `{$wpdb->comments}` WHERE `{$wpdb->prefix}analytical_spam_filter_content_history`.hash_val = UNHEX(SHA2(LOWER(TRIM(`{$wpdb->comments}`.comment_content)), 512)) AND `{$wpdb->comments}`.comment_approved = '1';";
				$wpdb->query( $sql );
			}
		}

		public function insert_hooks_in_forms() {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_use_ajax = ( isset( $options['use_ajax'] ) ? esc_attr( $options['use_ajax'] ) : 1 );
			$b_use_honeypot_blocking = ( isset( $options['use_honeypot_blocking'] ) ? esc_attr( $options['use_honeypot_blocking'] ) : 1 );
			$b_use_timestamp_blocking = ( isset( $options['use_timestamp_blocking'] ) ? esc_attr( $options['use_timestamp_blocking'] ) : 1 );
			$b_use_duration_blocking = ( isset( $options['use_duration_blocking'] ) ? esc_attr( $options['use_duration_blocking'] ) : 1 );

			if ( $b_use_ajax || $b_use_duration_blocking ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'load_external_scripts' ) );
				add_action( 'wp_footer', array( $this, 'load_external_scripts' ) );

				if ( $b_use_honeypot_blocking || $b_use_timestamp_blocking || $b_use_duration_blocking ) {
					add_action( 'wp_ajax_analytical_spam_filter_form_handler', array( $this, 'add_special_fields_to_form_handler' ) );
					add_action( 'wp_ajax_nopriv_analytical_spam_filter_form_handler', array( $this, 'add_special_fields_to_form_handler' ) );
					add_action( 'wp_ajax_analytical_spam_filter_duration_field_handler', array( $this, 'duration_field_handler' ) );
					add_action( 'wp_ajax_nopriv_analytical_spam_filter_duration_field_handler', array( $this, 'duration_field_handler' ) );
				}
			} else {
				add_action( 'comment_form', array( $this, 'add_special_fields_to_form' ) );
				add_action( 'addtl_micro_contact_form_elements', array( $this, 'add_special_fields_to_form' ) );
			}

			add_filter( 'preprocess_comment', array( $this, 'preprocess_comment_handler' ) );
			add_filter( 'preprocess_micro_contact_form_data', array( $this, 'preprocess_micro_contact_form_data_handler' ), 10, 2 );
		}

		public function load_textdomain_handler() {
			load_plugin_textdomain( 'analytical-spam-filter', false, trailingslashit( dirname( plugin_basename( ANALYTICAL_SPAM_FILTER_FILE ) ) ) . 'languages/' );
		}

		public function load_external_scripts() {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_use_honeypot_blocking = ( isset( $options['use_honeypot_blocking'] ) ? esc_attr( $options['use_honeypot_blocking'] ) : 1 );
			$b_use_timestamp_blocking = ( isset( $options['use_timestamp_blocking'] ) ? esc_attr( $options['use_timestamp_blocking'] ) : 1 );
			$b_use_duration_blocking = ( isset( $options['use_duration_blocking'] ) ? esc_attr( $options['use_duration_blocking'] ) : 1 );

			if ( $b_use_honeypot_blocking || $b_use_timestamp_blocking || $b_use_duration_blocking ) {
				if ( ( is_singular() && ( comments_open() || has_shortcode( get_the_content(), 'micro_contact_form' ) ) ) || ( class_exists( 'Micro_Contact_Form' ) && property_exists( 'Micro_Contact_Form', 'b_already_executed' ) && Micro_Contact_Form::$b_already_executed ) ) {
					wp_enqueue_script( 'analytical_spam_filter_scripts', trailingslashit( plugin_dir_url( ANALYTICAL_SPAM_FILTER_FILE ) ) . 'js/analytical-spam-filter-script.js', array( 'jquery' ) );
					wp_localize_script( 'analytical_spam_filter_scripts', 'analytical_spam_filter_ajax', array( 'url' => admin_url( 'admin-ajax.php' ) ) );
				}
			}
		}

		public function add_special_fields_to_form_handler() {
			$this->add_special_fields_to_form();

			wp_die();
		}

		public function duration_field_handler() {
			$form_duration_field_id = get_option( 'analytical_spam_filter_duration_field_id', 'analytical_spam_filter_duration' );

			echo( esc_attr( $form_duration_field_id ) );

			wp_die();
		}

		public function add_special_fields_to_form() {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_use_honeypot_blocking = ( isset( $options['use_honeypot_blocking'] ) ? esc_attr( $options['use_honeypot_blocking'] ) : 1 );
			$b_use_timestamp_blocking = ( isset( $options['use_timestamp_blocking'] ) ? esc_attr( $options['use_timestamp_blocking'] ) : 1 );
			$b_use_duration_blocking = ( isset( $options['use_duration_blocking'] ) ? esc_attr( $options['use_duration_blocking'] ) : 1 );

			if ( $b_use_honeypot_blocking ) {
				echo( '<div hidden>' );
				echo( '<label for="' . esc_attr( get_option( 'analytical_spam_filter_honeypot_field_id', 'analytical_spam_filter_hp' ) ) . '">' . esc_html__( 'Do Not Use', 'analytical-spam-filter' ) . '</label>' );
				echo( '<textarea id="' . esc_attr( get_option( 'analytical_spam_filter_honeypot_field_id', 'analytical_spam_filter_hp' ) ) . '" name="' . esc_attr( get_option( 'analytical_spam_filter_honeypot_field_id', 'analytical_spam_filter_hp' ) ) . '"></textarea>' );
				echo( '</div>' );
			}

			if ( $b_use_timestamp_blocking ) {
				echo( '<input type="hidden" id="' . esc_attr( get_option( 'analytical_spam_filter_hash_field_id', 'analytical_spam_filter_hash' ) ) . '" name="' . esc_attr( get_option( 'analytical_spam_filter_hash_field_id', 'analytical_spam_filter_hash' ) ) . '" value="' . esc_attr( $this->get_hash() ) . '" />' );
			}

			if ( $b_use_duration_blocking ) {
				echo( '<input type="hidden" id="' . esc_attr( get_option( 'analytical_spam_filter_duration_field_id', 'analytical_spam_filter_duration' ) ) . '" name="' . esc_attr( get_option( 'analytical_spam_filter_duration_field_id', 'analytical_spam_filter_duration' ) ) . '" value="" />' );
			}
		}

		private function generate_salt() {
			return bin2hex( openssl_random_pseudo_bytes( 64 ) );
		}

		private function generate_random_string( $length ) {
			$valid_characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
			$number_valid_characters = strlen( $valid_characters );
			$random_string = '';

			for ( $i = 0; $i < $length; $i++ ) {
				$random_string .= $valid_characters[ mt_rand( 1, $number_valid_characters ) - 1 ];
			}

			return $random_string;
		}

		private function get_remote_addr() {
			$remote_addr = '';

			$remote_addr = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '';

			if ( strpos( $remote_addr, ',' ) > 0 ) {
				$remote_addr = array_shift( explode( ',', $remote_addr ) );
			}

			$remote_addr = $this->sanitize_ip( wp_unslash( $remote_addr ) );

			return $remote_addr;
		}

		private function get_http_referer() {
			$http_referer = '';

			if ( isset( $_SERVER['HTTP_REFERER'] ) ) {
				$http_referer = sanitize_url( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
			}

			return $http_referer;
		}

		private function get_http_user_agent() {
			$http_user_agent = '';

			if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
				$http_user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
			}

			return $http_user_agent;
		}

		private function get_hash() {
			$timestamp = time();

			return base64_encode( hash( 'sha3-512', $timestamp . $this->get_remote_addr() . get_option( 'analytical_spam_filter_salt' ) ) . ',' . $timestamp );
		}

		private function get_form_hash_field_value() {
			$form_hash_field_id = esc_attr( get_option( 'analytical_spam_filter_hash_field_id', 'analytical_spam_filter_hash' ) );
			$form_hash_field_value = '';

			if ( isset( $_POST[ $form_hash_field_id ] ) ) {
				$form_hash_field_value = base64_decode( wp_unslash( $_POST[ $form_hash_field_id ] ) );
			}

			return $form_hash_field_value;
		}

		private function get_form_duration_field_value() {
			$form_duration_field_id = esc_attr( get_option( 'analytical_spam_filter_duration_field_id', 'analytical_spam_filter_duration' ) );
			$form_duration_field_value = 0;

			if ( isset( $_POST[ $form_duration_field_id ] ) ) {
				$form_duration_field_value = sanitize_text_field( wp_unslash( $_POST[ $form_duration_field_id ] ) );
			}

			if ( ! is_numeric( $form_duration_field_value ) ) {
				$form_duration_field_value = 0;
			} else {
				$form_duration_field_value = (float) $form_duration_field_value;
			}

			return $form_duration_field_value;
		}

		private function get_form_honeypot_field_value() {
			$form_honeypot_field_id = esc_attr( get_option( 'analytical_spam_filter_honeypot_field_id', 'analytical_spam_filter_hp' ) );
			$form_honeypot_field_value = null;

			if ( isset( $_POST[ $form_honeypot_field_id ] ) ) {
				$form_honeypot_field_value = wp_unslash( $_POST[ $form_honeypot_field_id ] );
			}

			return $form_honeypot_field_value;
		}

		public function preprocess_comment_handler( $commentdata ) {
			if ( isset( $commentdata['comment_type'] ) ) {
				$entry_type = $commentdata['comment_type'];
			} else {
				$entry_type = 'comment';
			}

			$text_to_search = $commentdata['comment_author'] . "\r\n" . $commentdata['comment_content'];

			if ( ! empty( $commentdata['user_id'] ) && ! empty( $commentdata['user_ID'] ) ) {
				$b_known_user = true;
			} else {
				$b_known_user = false;
			}

			$this->process_results( $entry_type, $commentdata, $commentdata['comment_content'], $text_to_search, $b_known_user );

			return $commentdata;
		}

		public function preprocess_micro_contact_form_data_handler( $approved, $form_data ) {
			$entry_type = 'micro_contact_form';
			$text_to_search = $form_data['from_name'] . "\r\n" . $form_data['subject'] . "\r\n" . $form_data['message'];

			return $this->process_results( $entry_type, $form_data, $form_data['message'], $text_to_search );
		}

		private function process_results( $entry_type, $form_data, $message, $text_to_search, $b_known_user = false ) {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_notify_admin_spam_only_diagnostic = ( isset( $options['notify_admin_spam_only_diagnostic'] ) ? $options['notify_admin_spam_only_diagnostic'] : 1 );
			$b_notify_admin_valid_only_diagnostic = ( isset( $options['notify_admin_valid_only_diagnostic'] ) ? $options['notify_admin_valid_only_diagnostic'] : 1 );
			$b_notify_admin_all_diagnostic = ( isset( $options['notify_admin_all_diagnostic'] ) ? $options['notify_admin_all_diagnostic'] : 1 );
			$b_flag_as_spam = ( isset( $options['flag_as_spam'] ) ? $options['flag_as_spam'] : 1 );
			$b_expose_rejection_reasons = ( isset( $options['expose_rejection_reasons'] ) ? $options['expose_rejection_reasons'] : 0 );
			$b_use_history = ( isset( $options['use_history'] ) ? $options['use_history'] : 1 );
			$b_use_similar_message_filter = ( isset( $options['similar_submissions'] ) ? $options['similar_submissions'] : 1 );
			$do_not_notify_admin_submitter_spam = ( isset( $options['do_not_notify_admin_submitter_spam'] ) ? $options['do_not_notify_admin_submitter_spam'] : 0 );
			$do_not_notify_admin_similar_spam = ( isset( $options['do_not_notify_admin_similar_spam'] ) ? $options['do_not_notify_admin_similar_spam'] : 0 );

			$processed_form_results = $this->analyze( $entry_type, $message, $text_to_search, $b_known_user );

			$spam_reasons = $processed_form_results['spam_reasons'];
			$reason_count = $processed_form_results['reason_count'];
			$timestamp_initial = $processed_form_results['timestamp_initial'];
			$timestamp_current = $processed_form_results['timestamp_current'];
			$timestamp_difference = $processed_form_results['timestamp_difference'];
			$duration = $processed_form_results['duration'];
			$num_of_submitter_spam_comments = $processed_form_results['num_of_submitter_spam_comments'];
			$num_of_similar_spam_comments = $processed_form_results['num_of_similar_spam_comments'];

			if ( $reason_count > 0 ) {
				if ( $b_use_history ) {
					$this->database_insert_submitter_spam_history_record( $this->get_remote_addr() );
				}

				if ( $b_use_similar_message_filter ) {
					$this->database_insert_content_spam_history_record( $message );
				}

				if ( ( $b_notify_admin_spam_only_diagnostic ) || ( $b_notify_admin_all_diagnostic ) ) {
					if ( ! ( ( ( $b_use_history ) && ( $do_not_notify_admin_submitter_spam > 0 ) && ( $num_of_submitter_spam_comments >= $do_not_notify_admin_submitter_spam ) ) || ( ( $b_use_similar_message_filter ) && ( $do_not_notify_admin_similar_spam > 0 ) && ( $num_of_similar_spam_comments >= $do_not_notify_admin_similar_spam ) ) ) ) {
						$this->notify_admin( $form_data, $spam_reasons, $timestamp_initial, $timestamp_current, $timestamp_difference, $duration, $b_known_user );
					}
				}

				if ( 'comment' == $entry_type ) {
					if ( $b_flag_as_spam ) {
						add_filter( 'pre_comment_approved', array( $this, 'pre_comment_approved_spam_handler' ), 99, 2 );
					} else {
						if ( $b_expose_rejection_reasons ) {
							$message = '<p>' . esc_html( _n( 'Comment has been rejected for the following reason:', 'Comment has been rejected for the following reasons:', $reason_count, 'analytical-spam-filter' ) ) . '</p>' . "\r\n";
							$message .= '<ul>' . "\r\n";
							foreach ( $spam_reasons as $key => $value ) {
								$message .= '<li>' . esc_html( $value ) . '</li>' . "\r\n";
							}
							$message .= '</ul>' . "\r\n";
							wp_die( wp_kses_post( $message ) );
						} else {
							wp_die( esc_html__( 'Comment has been rejected.', 'analytical-spam-filter' ) );
						}
					}
				}

				return false;
			} else {
				if ( ( $b_notify_admin_valid_only_diagnostic ) || ( $b_notify_admin_all_diagnostic ) ) {
					$this->notify_admin( $form_data, $spam_reasons, $timestamp_initial, $timestamp_current, $timestamp_difference, $duration, $b_known_user );
				}

				return true;
			}

			return false;
		}

		private function analyze( $entry_type, $message, $text_to_search, $b_known_user = false ) {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_use_timestamp_blocking = ( isset( $options['use_timestamp_blocking'] ) ? $options['use_timestamp_blocking'] : 1 );
			$b_use_duration_blocking = ( isset( $options['use_duration_blocking'] ) ? $options['use_duration_blocking'] : 1 );
			$b_use_honeypot_blocking = ( isset( $options['use_honeypot_blocking'] ) ? $options['use_honeypot_blocking'] : 1 );
			$b_use_url_count_blocking = ( isset( $options['use_url_count_blocking'] ) ? $options['use_url_count_blocking'] : 1 );
			$timestamp_allowed_age_min = ( isset( $options['timestamp_allowed_age_min'] ) ? $options['timestamp_allowed_age_min'] : 8 );
			$timestamp_allowed_age_max = ( isset( $options['timestamp_allowed_age_max'] ) ? $options['timestamp_allowed_age_max'] : 172800 );
			$duration_allowed_age_min = ( isset( $options['duration_allowed_age_min'] ) ? $options['duration_allowed_age_min'] : 2 );
			$duration_allowed_age_max = ( isset( $options['duration_allowed_age_max'] ) ? $options['duration_allowed_age_max'] : 7200 );
			$number_of_urls_allowed = ( isset( $options['number_of_urls_allowed'] ) ? $options['number_of_urls_allowed'] : 1 );
			$b_check_referer = ( isset( $options['check_referer'] ) ? $options['check_referer'] : 1 );
			$b_user_agent_required = ( isset( $options['user_agent_required'] ) ? $options['user_agent_required'] : 1 );
			$b_trackbacks_allowed = ( isset( $options['trackbacks_allowed'] ) ? $options['trackbacks_allowed'] : 0 );
			$b_pingbacks_allowed = ( isset( $options['pingbacks_allowed'] ) ? $options['pingbacks_allowed'] : 0 );
			$b_use_history = ( isset( $options['use_history'] ) ? $options['use_history'] : 1 );
			$submissions_allowed_count_max = ( isset( $options['submissions_allowed_count_max'] ) ? $options['submissions_allowed_count_max'] : 2 );
			$submissions_allowed_age_max = ( isset( $options['submissions_allowed_age_max'] ) ? $options['submissions_allowed_age_max'] : 0 );
			$submissions_allowed_age_max_interval = ( isset( $options['submissions_allowed_age_max_interval'] ) ? $options['submissions_allowed_age_max_interval'] : 'MONTH' );
			$b_use_similar_message_filter = ( isset( $options['similar_submissions'] ) ? $options['similar_submissions'] : 1 );
			$similar_submissions_allowed_count_max = ( isset( $options['similar_submissions_allowed_count_max'] ) ? $options['similar_submissions_allowed_count_max'] : 2 );
			$similar_submissions_allowed_age_max = ( isset( $options['similar_submissions_allowed_age_max'] ) ? $options['similar_submissions_allowed_age_max'] : 0 );
			$similar_submissions_allowed_age_max_interval = ( isset( $options['similar_submissions_allowed_age_max_interval'] ) ? $options['similar_submissions_allowed_age_max_interval'] : 'MONTH' );
			$b_is_valid_timestamp = 0;
			$timestamp_difference = 0;
			$timestamp_current = 0;
			$timestamp_initial = 0;
			$duration = 0;
			$duration_seconds = 0;
			$b_is_valid_duration = 0;
			$b_is_valid_number_of_urls = 0;
			$url_count = 0;
			$num_of_spam_comments = 0;
			$num_of_similar_spam_comments = 0;
			$spam_reasons = array();
			$reason_count = 0;
			$home_url_for_referer_check = '';
			$b_javascript_enabled = 1;

			if ( ! is_admin() ) {
				if ( ! ( $this->is_trackback( $entry_type ) ) && ! ( $this->is_pingback( $entry_type ) ) ) {
					if ( $b_use_timestamp_blocking ) {
						list($b_is_valid_timestamp, $timestamp_difference, $timestamp_current, $timestamp_initial) = $this->is_valid_timestamp( $timestamp_allowed_age_min, $timestamp_allowed_age_max );

						if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
							if ( ! ( $b_is_valid_timestamp ) ) {
								/* translators: %d: timestamp difference */
								$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Invalid Timestamp Threshold (Time Spent Between Initial Page Load and Form Submission): %d second', 'Invalid Timestamp Threshold (Time Spent Between Page Load and Form Submission): %d seconds', $timestamp_difference, 'analytical-spam-filter' ), $timestamp_difference );
							}

							if ( 0 == $timestamp_initial ) {
								$b_javascript_enabled = 0;
							}
						}
					}

					if ( $b_use_duration_blocking ) {
						$duration = $this->get_form_duration_field_value();
						$duration_seconds = ( (float) $duration ) / 1000;

						if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
							$b_is_valid_duration = $this->is_valid_duration( $duration_allowed_age_min, $duration_allowed_age_max, $duration );

							if ( ! ( $b_is_valid_duration ) ) {
								/* translators: %f: time spent actively completing form */
								$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Invalid Duration Threshold (Time Spent Actively Completing Form): %f second', 'Invalid Duration Threshold (Time Spent Actively Completing Form): %f seconds', $duration_seconds, 'analytical-spam-filter' ), $duration_seconds );
							}

							if ( 0 == $duration ) {
								   $b_javascript_enabled = 0;
							}
						}
					}

					if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
						if ( ! ( $b_javascript_enabled ) ) {
							$spam_reasons[ $reason_count++ ] = __( 'JavaScript is Not Enabled', 'analytical-spam-filter' );
						}
					}

					if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
						if ( $b_use_honeypot_blocking ) {
							if ( ! ( $this->is_valid_honeypot() ) ) {
								   $spam_reasons[ $reason_count++ ] = __( 'Invalid Honeypot Value', 'analytical-spam-filter' );
							}
						}
					}

					if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
						if ( $b_check_referer ) {
							$http_referer = $this->get_http_referer();

							if ( empty( $http_referer ) ) {
								$spam_reasons[ $reason_count++ ] = __( 'Referer Information is Missing', 'analytical-spam-filter' );
							} else {
								$home_url_for_referer_check = str_replace( '.', '[.]', home_url() );
								if ( ! ( preg_match( '~^' . $home_url_for_referer_check . '/?~i', $http_referer ) ) ) {
									/* translators: %s: site home url */
									$spam_reasons[ $reason_count++ ] = sprintf( __( 'Referer Does Not Match Site URL: %s', 'analytical-spam-filter' ), $home_url_for_referer_check );
								}
							}
						}
					}

					if ( ! ( is_user_logged_in() ) && ! $b_known_user ) {
						if ( $b_user_agent_required ) {
							if ( empty( $this->get_http_user_agent() ) ) {
								$spam_reasons[ $reason_count++ ] = __( 'User-Agent String is Missing', 'analytical-spam-filter' );
							}
						}
					}
				}

				if ( $b_use_url_count_blocking ) {
					if ( $number_of_urls_allowed >= 0 ) {
						list($b_is_valid_number_of_urls, $url_count) = $this->is_valid_number_of_urls( $number_of_urls_allowed, $text_to_search );

						if ( ! ( $b_is_valid_number_of_urls ) ) {
							/* translators: %d: number of urls found */
							$spam_reasons[ $reason_count++ ] = sprintf( __( 'Excessive URLs: %d found', 'analytical-spam-filter' ), $url_count );
						}
					}
				}

				if ( $b_use_history ) {
					$num_of_spam_comments = $this->database_get_submitter_spam_history_count( $submissions_allowed_age_max, $submissions_allowed_age_max_interval, $this->get_remote_addr() );
					if ( ! empty( $num_of_spam_comments ) && ( $num_of_spam_comments >= $submissions_allowed_count_max ) ) {
						if ( $submissions_allowed_age_max > 0 ) {
							if ( 1 == $submissions_allowed_age_max ) {
								switch ( $submissions_allowed_age_max_interval ) {
									case 'MINUTE':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Minute', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Minute', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'HOUR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Hour', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Hour', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'DAY':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Day', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Day', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'WEEK':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Week', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Week', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'MONTH':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Month', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Month', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'YEAR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Year', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Year', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
								}
							} else {
								switch ( $submissions_allowed_age_max_interval ) {
									case 'MINUTE':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Minutes', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Minutes', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'HOUR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Hours', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Hours', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'DAY':
										  /* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										  $spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Days', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Days', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'WEEK':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Weeks', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Weeks', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'MONTH':
										   /* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										   $spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Months', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Months', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
									case 'YEAR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %1$d Submission Within %2$d Years', 'Submitter Flagged For Repeated Spam: %1$d Submissions Within %2$d Years', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments, $submissions_allowed_age_max );
										break;
								}
							}
						} else {
							/* translators: %d: number of actual spam submissions */
							$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Submitter Flagged For Repeated Spam: %d Submission', 'Submitter Flagged For Repeated Spam: %d Submissions', $num_of_spam_comments, 'analytical-spam-filter' ), $num_of_spam_comments );
						}
					}
				}

				if ( $b_use_similar_message_filter ) {
					$num_of_similar_spam_comments = $this->database_get_content_spam_history_count( $similar_submissions_allowed_age_max, $similar_submissions_allowed_age_max_interval, $message );
					if ( ! empty( $num_of_similar_spam_comments ) && ( $num_of_similar_spam_comments >= $similar_submissions_allowed_count_max ) ) {
						if ( $similar_submissions_allowed_age_max > 0 ) {
							if ( 1 == $similar_submissions_allowed_age_max ) {
								switch ( $submissions_allowed_age_max_interval ) {
									case 'MINUTE':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Minute', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Minute', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'HOUR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Hour', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Hour', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'DAY':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Day', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Day', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'WEEK':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Week', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Week', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'MONTH':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Month', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Month', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'YEAR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Year', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Year', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
								}
							} else {
								switch ( $submissions_allowed_age_max_interval ) {
									case 'MINUTE':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Minutes', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Minutes', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'HOUR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Hours', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Hours', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'DAY':
										  /* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										  $spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Days', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Days', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'WEEK':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Weeks', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Weeks', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'MONTH':
										   /* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										   $spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Months', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Months', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
									case 'YEAR':
										/* translators: %1$d: number of actual spam submissions, %2$d: maximum time threshold */
										$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %1$d Submission Within %2$d Years', 'Similar To Prior Spam Submissions: %1$d Submissions Within %2$d Years', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments, $similar_submissions_allowed_age_max );
										break;
								}
							}
						} else {
							/* translators: %d: number of actual spam submissions */
							$spam_reasons[ $reason_count++ ] = sprintf( _n( 'Similar To Prior Spam Submissions: %d Submission', 'Similar To Prior Spam Submissions: %d Submissions', $num_of_similar_spam_comments, 'analytical-spam-filter' ), $num_of_similar_spam_comments );
						}
					}
				}

				if ( ! ( $b_trackbacks_allowed ) ) {
					if ( $this->is_trackback( $entry_type ) ) {
						$spam_reasons[ $reason_count++ ] = __( 'Trackback Submissions Are Not Permitted', 'analytical-spam-filter' );
					}
				}

				if ( ! ( $b_pingbacks_allowed ) ) {
					if ( $this->is_pingback( $entry_type ) ) {
						$spam_reasons[ $reason_count++ ] = __( 'Pingback Submissions Are Not Permitted', 'analytical-spam-filter' );
					}
				}
			}

			return array(
				'spam_reasons' => $spam_reasons,
				'reason_count' => $reason_count,
				'timestamp_initial' => $timestamp_initial,
				'timestamp_current' => $timestamp_current,
				'timestamp_difference' => $timestamp_difference,
				'duration' => $duration,
				'num_of_submitter_spam_comments' => $num_of_spam_comments,
				'num_of_similar_spam_comments' => $num_of_similar_spam_comments,
			);
		}

		public function pre_comment_approved_spam_handler( $approved, $commentdata ) {
			return 'spam';
		}

		private function is_valid_timestamp( $timestamp_allowed_age_min, $timestamp_allowed_age_max ) {
			$salt = get_option( 'analytical_spam_filter_salt' );
			$timestamp_current = time();
			$timestamp_initial = 0;
			$timestamp_difference = 0;
			$b_valid = 0;

			$form_hash_field_value = $this->get_form_hash_field_value();
			$data = explode( ',', $form_hash_field_value );

			if ( 2 == count( $data ) ) {
				if ( hash( 'sha3-512', $data[1] . $this->get_remote_addr() . $salt ) == $data[0] ) {
					$timestamp_initial = $data[1];

					if ( is_numeric( $timestamp_initial ) ) {
						$timestamp_difference = $timestamp_current - $timestamp_initial;

						if ( ( $timestamp_difference > $timestamp_allowed_age_min ) && ( $timestamp_difference < $timestamp_allowed_age_max ) ) {
							   $b_valid = 1;
						}
					}
				}
			}

			return array( $b_valid, $timestamp_difference, $timestamp_current, $timestamp_initial );
		}

		private function is_valid_duration( $duration_allowed_age_min, $duration_allowed_age_max, $duration ) {
			$b_valid = 0;

			if ( ( $duration > ( $duration_allowed_age_min * 1000 ) ) && ( $duration < ( $duration_allowed_age_max * 1000 ) ) ) {
				$b_valid = 1;
			}

			return $b_valid;
		}

		private function is_valid_honeypot() {
			$b_valid = 0;
			$form_honeypot_field_value = $this->get_form_honeypot_field_value();

			if ( isset( $form_honeypot_field_value ) ) {
				if ( 0 == strlen( $form_honeypot_field_value ) ) {
					$b_valid = 1;
				}
			}

			return $b_valid;
		}

		private function is_valid_number_of_urls( $number_of_urls_allowed, $text_to_search ) {
			$matches = null;
			$count = 0;
			$b_valid = 0;

			$count = preg_match_all( '~\b(?:(https?|ftps?):\/\/(?:(?:[\p{L}\p{N}\p{M}\p{S}\%])+(?:\:[\p{L}\p{N}\p{M}\p{S}\%]*)?\@)?)?(?:(?:[\p{L}\p{N}\p{M}\p{S}][\p{L}\p{N}\p{M}\p{S}\-\_]{0,61}[\p{L}\p{N}\p{M}\p{S}]|[\p{L}\p{N}\p{M}\p{S}])[.])*(?:(?:[\p{L}\p{N}\p{M}\p{S}][\p{L}\p{N}\p{M}\p{S}\-\_]{0,61}[\p{L}\p{N}\p{M}\p{S}]|[\p{L}\p{N}\p{M}\p{S}])[.])(?(1)(?:[\p{L}\p{N}\p{M}\p{S}][\p{L}\p{N}\p{M}\p{S}\-]{0,61}[\p{L}\p{N}\p{M}\p{S}]|[\p{N}])|(?:xn--[a-z0-9\-]+|onion|online|review|email|store|tokyo|asia|buzz|casa|club|host|info|life|link|live|shop|site|surf|tech|work|app|biz|cam|com|edu|fit|gov|icu|int|mil|net|org|pro|top|vip|xyz|ai|br|cc|cf|cn|co|de|do|fr|ga|gd|gg|gq|id|jp|kr|ly|me|ml|ru|su|tk|uk|us))(?:\:[\p{N}]{1,5})?(?:\/[\p{L}\p{N}\p{M}\p{S}\-\_\~\?.\%\!\$\&\'\(\)\*\+\,\;\=\:\@\#]*)*\b~isu', $text_to_search, $matches );

			if ( $count <= $number_of_urls_allowed ) {
				$b_valid = 1;
			}

			return array( $b_valid, $count );
		}

		private function is_trackback( $entry_type ) {
			$b_trackback = 0;

			if ( 'trackback' == $entry_type ) {
				$b_trackback = 1;
			}

			return $b_trackback;
		}

		private function is_pingback( $entry_type ) {
			$b_pingback = 0;

			if ( 'pingback' == $entry_type ) {
				$b_pingback = 1;
			}

			return $b_pingback;
		}

		private function notify_admin( $data, $spam_reasons, $timestamp_initial, $timestamp_current, $timestamp_difference, $duration, $b_known_user ) {
			$options = get_option( 'analytical_spam_filter_settings_db' );
			$b_use_timestamp_blocking = ( isset( $options['use_timestamp_blocking'] ) ? esc_attr( $options['use_timestamp_blocking'] ) : 1 );
			$b_use_duration_blocking = ( isset( $options['use_duration_blocking'] ) ? esc_attr( $options['use_duration_blocking'] ) : 1 );
			$site_title = get_bloginfo( 'name' );
			$to_email = get_option( 'admin_email' );
			$date_format = get_option( 'date_format' );
			$time_format = get_option( 'time_format' );
			$is_comment = false;
			$remote_addr = $this->get_remote_addr();
			$http_user_agent = $this->get_http_user_agent();
			$http_referer = $this->get_http_referer();
			$duration_seconds = ( (float) $duration ) / 1000;

			if ( isset( $data['comment_post_ID'] ) ) {
				$is_comment = true;
				$post = get_post( $data['comment_post_ID'] );
			}

			if ( count( $spam_reasons ) > 0 ) {
				if ( $is_comment ) {
					/* translators: %s: blog name */
					$subject = sprintf( __( '[%s] Spam Comment Blocked', 'analytical-spam-filter' ), $site_title );
					/* translators: %s: post title */
					$message = sprintf( __( 'A new comment on the post "%s" was blocked.', 'analytical-spam-filter' ), $post->post_title ) . "\r\n\r\n";
				} else {
					/* translators: %s: blog name */
					$subject = sprintf( __( '[%s] Spam Submission Blocked', 'analytical-spam-filter' ), $site_title );
					$message = __( 'A contact form submission was blocked.', 'analytical-spam-filter' ) . "\r\n\r\n";
				}

				$message .= _n( 'Submission was marked as spam due to the following reason:', 'Submission was marked as spam due to the following reasons:', count( $spam_reasons ), 'analytical-spam-filter' ) . "\r\n";
				foreach ( $spam_reasons as $key => $value ) {
					$message .= $value . "\r\n";
				}
				$message .= "\r\n\r\n";
			} else {
				/* translators: %s: blog name */
				$subject = sprintf( __( '[%s] Submission Diagnostics', 'analytical-spam-filter' ), $site_title );

				if ( $is_comment ) {
					/* translators: %s: post title */
					$message = sprintf( __( 'A new comment on the post "%s" was submitted. It was not marked as spam.', 'analytical-spam-filter' ), $post->post_title ) . "\r\n\r\n";
				} else {
					$message = __( 'A contact form was submitted. It was not marked as spam.', 'analytical-spam-filter' ) . "\r\n\r\n";
				}
			}

			$message .= __( '****** Additional Diagnostics ******', 'analytical-spam-filter' ) . "\r\n";
			/* translators: %s: Remote IP Address */
			$message .= sprintf( __( 'IP: %s', 'analytical-spam-filter' ), $remote_addr ) . "\r\n";
			/* translators: %s: User-Agent String */
			$message .= sprintf( __( 'User-Agent String: %s', 'analytical-spam-filter' ), $http_user_agent ) . "\r\n";
			/* translators: %s: HTTP REFERER */
			$message .= sprintf( __( 'HTTP_REFERER: %s', 'analytical-spam-filter' ), $http_referer ) . "\r\n";
			/* translators: %s: WP Referer */
			$message .= sprintf( __( 'WP Referer: %s', 'analytical-spam-filter' ), wp_get_referer() ) . "\r\n\r\n";

			if ( $b_use_timestamp_blocking ) {
				if ( ! $b_known_user ) {
					if ( 0 == $timestamp_initial ) {
						/* translators: %d: numeric initial timestamp in seconds */
						$message .= sprintf( __( 'Initial Page Load Timestamp: Invalid Timestamp (%d)', 'analytical-spam-filter' ), $timestamp_initial ) . "\r\n";
					} else {
						/* translators: %1$s: formatted initial timestamp, %2$d: numeric initial timestamp in seconds */
						$message .= sprintf( __( 'Initial Page Load Timestamp: %1$s (%2$d)', 'analytical-spam-filter' ), wp_date( $date_format . ' ' . $time_format, $timestamp_initial ), $timestamp_initial ) . "\r\n";
					}

					/* translators: %1$s: formatted submission timestamp, %2$d: numeric submission timestamp in seconds */
					$message .= sprintf( __( 'Submission Timestamp: %1$s (%2$d)', 'analytical-spam-filter' ), wp_date( $date_format . ' ' . $time_format, $timestamp_current ), $timestamp_current ) . "\r\n";
					/* translators: %d: length of time to submit form */
					$message .= sprintf( _n( 'Time Spent Between Initial Page Load and Form Submission: %d second', 'Time Spent Between Initial Page Load and Form Submission: %d seconds', $timestamp_difference, 'analytical-spam-filter' ), $timestamp_difference ) . "\r\n";
				}
			}

			if ( $b_use_duration_blocking ) {
				if ( ! $b_known_user ) {
					/* translators: %f: length of time user spent entering text */
					$message .= sprintf( _n( 'Time Spent Actively Completing Form: %f second', 'Time Spent Actively Completing Form: %f seconds', $duration_seconds, 'analytical-spam-filter' ), $duration_seconds ) . "\r\n\r\n";
				}
			}

			$message .= __( 'Submission Data:', 'analytical-spam-filter' ) . "\r\n";
			foreach ( $data as $key => $value ) {
				/* translators: %1$s: submission data array key name, %2$s: submission data array key value */
				$message .= sprintf( __( '[%1$s] = %2$s', 'analytical-spam-filter' ), sanitize_key( $key ), wp_kses_post( wp_unslash( $value ) ) ) . "\r\n";
			}
			$message .= "\r\n\r\n";

			@wp_mail( $to_email, $subject, $message );
		}
	}
}

if ( class_exists( 'Analytical_Spam_Filter' ) ) {
	$analytical_spam_filter = new Analytical_Spam_Filter();
	register_activation_hook( ANALYTICAL_SPAM_FILTER_FILE, array( $analytical_spam_filter, 'activate' ) );
	register_deactivation_hook( ANALYTICAL_SPAM_FILTER_FILE, array( $analytical_spam_filter, 'deactivate' ) );
}
