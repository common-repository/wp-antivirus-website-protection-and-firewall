<?php
class Siteguarding_Wordpress_Core_Check {


	private $core = array();
	private $plugins = array();
	private $themes = array();
	private $admins = array();


	/**
	 * Check for any core, plugin or theme updates.
	 *
	 * @return $this
	 */
	public function checkAllinWP() {
		return $this->checkCoreWP()
			->checkPlugins()
			->checkThemes()
			->checkAdmins();
	}

	/**
	 * Check if there is an update to the WordPress core.
	 *
	 * @return $this
	 */
	public function checkCoreWP() {
		

		if (!function_exists('wp_version_check')) {
			require_once(ABSPATH . WPINC . '/update.php');
		}
		if (!function_exists('get_preferred_from_update_core')) {
			require_once(ABSPATH . 'wp-admin/includes/update.php');
		}
		
		include( ABSPATH . WPINC . '/version.php' ); //defines $wp_version
		

		wp_version_check();
		$update_core = get_preferred_from_update_core();



		$this->core['current_ver'] = get_bloginfo('version') ? get_bloginfo('version') : 'unknown';
		$this->core['latest_ver'] = $update_core->current ? $update_core->current : 'unknown';


		return $this;
	}

	/**
	 * Check if any plugins need an update.
			 *
			 * @return $this
			 */
	public function checkPlugins() {
		$activeSlugs = array();
		$activePlugins = get_option('active_plugins'); 
		foreach ($activePlugins as $plugin) {
			$tmpslug = explode("/", $plugin);
			$activeSlugs[] = $tmpslug[0];
		}

		if (!function_exists('wp_update_plugins')) {
			require_once(ABSPATH . WPINC . '/update.php');
		}

		if (!function_exists('plugins_api')) {
			require_once(ABSPATH . '/wp-admin/includes/plugin-install.php');
		}
		

		wp_update_plugins();
		$update_plugins = get_site_transient('update_plugins');

		
		//Get the full plugin list
		if (!function_exists('get_plugins')) {
			require_once(ABSPATH . '/wp-admin/includes/plugin.php');
		}
		$installedPlugins = get_plugins();

		if ($update_plugins && !empty($update_plugins->response)) {
			foreach ($update_plugins->response as $plugin => $vals) {
				
				if (!function_exists('get_plugin_data')) {
					require_once ABSPATH . '/wp-admin/includes/plugin.php';
				}
				

				
				$pluginFile = WP_PLUGIN_DIR . DIRSEP . $plugin;
				if (!file_exists($pluginFile)) { //Plugin has been removed since the update status was pulled
					unset($installedPlugins[$plugin]);
					continue;
				}

				$valsArray = (array) $vals;
				
				$slug = (isset($valsArray['slug']) ? $valsArray['slug'] : null);
				if ($slug === null) { //Plugin may have been removed from the repo or was never in it so guess
					if (preg_match('/^([^\/]+)\//', $pluginFile, $matches)) {
						$slug = $matches[1];
					}
					else if (preg_match('/^([^\/.]+)\.php$/', $pluginFile, $matches)) {
						$slug = $matches[1];
					}
				}
				
				$pluginData = get_plugin_data($pluginFile);
				
				$data['slug'] = $slug;
				$data['name'] = $pluginData['Name'];
				$data['active'] = (in_array($slug, $activeSlugs)) ? 1 : 0;
				$data['current_ver'] = $pluginData['Version'];;
				$data['latest_ver'] = (isset($valsArray['new_version']) ? $valsArray['new_version'] : 'Unknown');


				
				if ($slug !== null) {
					$this->plugins[$slug] = $data;
				}
			
				unset($installedPlugins[$plugin]);
			}
		}
		
		//We have to grab the slugs from the update response because no built-in function exists to return the true slug from the local files
		if ($update_plugins && !empty($update_plugins->no_update)) {
			foreach ($update_plugins->no_update as $plugin => $vals) {
				if (!function_exists('get_plugin_data')) {
					require_once ABSPATH . '/wp-admin/includes/plugin.php';
				}
				
				$pluginFile = WP_PLUGIN_DIR . DIRSEP  . $plugin;
				if (!file_exists($pluginFile)) { //Plugin has been removed since the update status was pulled
					unset($installedPlugins[$plugin]);
					continue;
				}
				
				$valsArray = (array) $vals;
				
				$pluginData = get_plugin_data($pluginFile);
				
				$data['slug'] = (isset($valsArray['slug']) ? $valsArray['slug'] : null);
				$data['name'] = $pluginData['Name'];
				$data['active'] = (in_array($slug, $activeSlugs)) ? 1 : 0;
				$data['current_ver'] = $pluginData['Version'];;
				$data['latest_ver'] = (isset($valsArray['new_version']) ? $valsArray['new_version'] : 'Unknown');

				
				if (isset($valsArray['slug'])) {
					$this->plugins[$valsArray['slug']] = $data;
				}
				
				unset($installedPlugins[$plugin]);
			}	
		}


		return $this;
	}

	
	public function checkAdmins() {
            $args = array(
            	'role'         => 'administrator',
            	'fields'       => 'all'
             ); 
            $wp_users = get_users( $args );

			foreach ($wp_users as $user) {
				$this->admins[] = array('username' => $user->user_login, 'email' => $user->user_email);
			}
			return $this;
	}
	/**
	 * Check if any themes need an update.
	 *
	 * @return $this
	 */
	public function checkThemes() {
		$this->themes = array();

		if (!function_exists('wp_update_themes')) {
			require_once(ABSPATH . WPINC . '/update.php');
		}

		wp_update_themes();
		$update_themes = get_site_transient('update_themes');

		if ($update_themes) {
			if (!function_exists('wp_get_themes')) {
				require_once ABSPATH . '/wp-includes/theme.php';
			}
			$themes = wp_get_themes();
			$current = wp_get_theme()->template;

			foreach ($update_themes->checked as $theme => $currentVersion) {
				
				$this->themes[] = array(

					'name'       => $theme,
					'active'       => ($theme == $current) ? 1 : 0,
					'current_ver'    => $currentVersion,
					'latest_ver' => (isset($update_themes->response[$theme]) ? $update_themes->response[$theme]['new_version'] : $currentVersion),
				);

			}
		}

		return $this;
		
	}



	/**
	 * @return int
	 */
	public function getCoreCheckResult() {
		return $this->core;
	}

	/**
	 * @return array
	 */
	public function getPluginsCheckResult() {
		return $this->plugins;
	}
	

	/**
	 * @return array
	 */
	public function getThemesCheckResult() {
		return $this->themes;
	}	

	/**
	 * @return array
	 */
	public function getAdminsCheckResult() {
		return $this->admins;
	}
	
	/**
	 * @return array
	 */
	public function getFullResultsToArray() {
		$this->checkAllinWP();
		
		$result['core'] = $this->getCoreCheckResult();
		$result['plugins'] = $this->getPluginsCheckResult();
		$result['themes'] = $this->getThemesCheckResult();
		$result['admins'] = $this->getAdminsCheckResult();
		
		return $result;
	}
}
?>