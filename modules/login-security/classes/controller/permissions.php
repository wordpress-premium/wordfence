<?php

namespace WordfenceLS;

class Controller_Permissions {
	const CAP_ACTIVATE_2FA_SELF = 'wf2fa_activate_2fa_self'; //Activate 2FA on its own user account
	const CAP_ACTIVATE_2FA_OTHERS = 'wf2fa_activate_2fa_others'; //Activate 2FA on user accounts other than its own
	const CAP_MANAGE_SETTINGS = 'wf2fa_manage_settings'; //Edit settings for the plugin
	
	/**
	 * Returns the singleton Controller_Permissions.
	 *
	 * @return Controller_Permissions
	 */
	public static function shared() {
		static $_shared = null;
		if ($_shared === null) {
			$_shared = new Controller_Permissions();
		}
		return $_shared;
	}
	
	public function install() {
		if (is_multisite()) {
			//Super Admin automatically gets all capabilities, so we don't need to explicitly add them
			$this->_add_cap_multisite('administrator', self::CAP_ACTIVATE_2FA_SELF);
		}
		else {
			$this->_add_cap('administrator', self::CAP_ACTIVATE_2FA_SELF);
			$this->_add_cap('administrator', self::CAP_ACTIVATE_2FA_OTHERS);
			$this->_add_cap('administrator', self::CAP_MANAGE_SETTINGS);
		}
	}
	
	public function allow_2fa_self($role_name) {
		if (is_multisite()) {
			$this->_add_cap_multisite($role_name, self::CAP_ACTIVATE_2FA_SELF);
		}
		else {
			$this->_add_cap($role_name, self::CAP_ACTIVATE_2FA_SELF);
		}
	}
	
	public function disallow_2fa_self($role_name) {
		if (is_multisite()) {
			$this->_remove_cap_multisite($role_name, self::CAP_ACTIVATE_2FA_SELF);
		}
		else {
			if ($role_name == 'administrator') {
				return;
			}
			$this->_remove_cap($role_name, self::CAP_ACTIVATE_2FA_SELF);
		}
	}
	
	public function can_manage_settings($user = false) {
		if ($user === false) {
			$user = wp_get_current_user();
		}
		
		if (!($user instanceof \WP_User)) {
			return false;
		}
		return $user->has_cap(self::CAP_MANAGE_SETTINGS);
	}
	
	private function _wp_roles($site_id = null) {
		require(ABSPATH . 'wp-includes/version.php'); /** @var string $wp_version */
		if (version_compare($wp_version, '4.9', '>=')) {
			return new \WP_Roles($site_id);
		}
		
		//\WP_Roles in WP < 4.9 initializes based on the current blog ID 
		global $wpdb;
		$current_site = $wpdb->set_blog_id($site_id);
		$wp_roles = new \WP_Roles();
		$wpdb->set_blog_id($current_site);
		return $wp_roles;
	}
	
	private function _add_cap_multisite($role_name, $cap) {
		global $wpdb;
		$blogs = $wpdb->get_col("SELECT `blog_id` FROM `{$wpdb->blogs}` WHERE `deleted` = 0");
		foreach ($blogs as $id) {
			$wp_roles = $this->_wp_roles($id);
			$current_site = $wpdb->set_blog_id($id); //We have to set the blog ID for $wpdb because \WP_Roles does not set it prior to saving a multisite role
			$this->_add_cap($role_name, $cap, $wp_roles);
			$wpdb->set_blog_id($current_site);
		}
	}
	
	private function _add_cap($role_name, $cap, $wp_roles = null) {
		if ($wp_roles === null) { $wp_roles = $this->_wp_roles(); }
		$role = $wp_roles->get_role($role_name);
		if ($role === null) {
			return false;
		}
		
		$wp_roles->add_cap($role_name, $cap);
		return true;
	}
	
	private function _remove_cap_multisite($role_name, $cap) {
		global $wpdb;
		$blogs = $wpdb->get_col("SELECT `blog_id` FROM `{$wpdb->blogs}` WHERE `deleted` = 0");
		foreach ($blogs as $id) {
			$wp_roles = $this->_wp_roles($id);
			$current_site = $wpdb->set_blog_id($id); //We have to set the blog ID for $wpdb because \WP_Roles does not set it prior to saving a multisite role
			$this->_remove_cap($role_name, $cap, $wp_roles);
			$wpdb->set_blog_id($current_site);
		}
	}
	
	private function _remove_cap($role_name, $cap, $wp_roles = null) {
		if ($wp_roles === null) { $wp_roles = $this->_wp_roles(); }
		$role = $wp_roles->get_role($role_name);
		if ($role === null) {
			return false;
		}
		
		$wp_roles->remove_cap($role_name, $cap);
		return true;
	}
}