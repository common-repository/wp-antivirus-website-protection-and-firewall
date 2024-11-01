<?php
class SGAVP_FIREWALL
{
    public static function HTML_firewall_page()
    {
		wp_enqueue_style( 'plgavp_LoadStyle' );
		
		?>
			<h2 class="avp_header icon_radar">WP Antivirus Site Protection (Firewall section)</h2>
			
		<?php
        if (isset($_REQUEST['action'])) $action = sanitize_text_field(trim($_REQUEST['action']));
        $viewlog_arr = array();
        if ($action != '')
        {
            switch ($action)
            {
                case 'Save_rules_params':
                    if (check_admin_referer( 'name_F8F1EEB45FC3' ))
                    {
                        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/';
                        
                        $files = array(
                            'rules_allowed_ip',
                            'rules_blocked_ip',
                            'rules_blocked_files',
                            'rules_blocked_urls'
                        );
                        
                        $full_rules_txt = '';
                        foreach ($files as $file)
                        {
                            $filename = $folder.$file.".txt";
                            $txt = '';
                            if (isset($_POST[$file]))
                            {
                                $txt = trim($_POST[$file]);
                            }
                            else $txt = '';
                            
                            $fp = fopen($filename, 'w');
                            fwrite($fp, $txt);
                            fclose($fp);
                        }
                        
                        self::CombineFirewallRules();

                        
                        ?>
                        <div class="updated settings-error notice is-dismissible"> 
                        <p><strong>Settings saved.</strong></p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>
                        <?php
                    }
                    break;
                    
                    
                case 'firewall':
                    if (wp_verify_nonce($_GET['name_54276D2FA1EE'], 'a'))
                    {
                        $status = intval($_REQUEST['status']);
                        if ($status == 1) self::Firewall_Install();
                        if ($status == 0) self::Firewall_Remove(); 
                        self::CombineFirewallRules();
                    }
                    break;


                case 'clear_all_logs':
                    if (wp_verify_nonce($_GET['name_724526A7F187'], 'a'))
                    {
                        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/logs/';
                        foreach (glob($folder."*.log.php") as $filename) 
                        {
                            unlink($filename);
                        }
                        $file = $folder.'_blocked.log';
                        if (file_exists($file))
                        {
                            unlink($file);
                        }

                        ?>
                        <div class="updated settings-error notice is-dismissible"> 
                        <p><strong>All logs deleted.</strong></p><button type="button" class="notice-dismiss"><span class="screen-reader-text">All logs removed</span></button></div>
                        <?php
                    }
                    break;
                    
                    
                case 'deletelog':
                    if (wp_verify_nonce($_GET['name_0FB374B3287E'], 'a'))
                    {
                        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/logs/';
                        if (isset($_GET['file']))
                        {
                            unlink($folder.$_GET['file']);
                            
                            ?>
                            <div class="updated settings-error notice is-dismissible"> 
                            <p><strong>Log file deleted.</strong></p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Removed</span></button></div>
                            <?php
                        }
                    }
                    break;
                    
                case 'viewlog':
                    if (wp_verify_nonce($_GET['name_0FB374B3287E'], 'a'))
                    {
                        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/logs/';
                        if (isset($_GET['file']))
                        {
                            $file = $folder.$_GET['file'];
                            if (file_exists($file))
                            {
                                $handle = fopen($file, "r");
                                $content = fread($handle, filesize($file));
                                fclose($handle);

                                $rows = explode("\n", $content);
                                for ($i = 0; $i <= 2; $i++)
                                {
                                    if ($rows[$i][0] == "<" || $rows[$i][0] == "/") unset($rows[$i]);
                                }
                                
                                foreach($rows as $k => $row)
                                {
                                    if (trim($row) == '') unset($rows[$k]);
                                }
                                
                                if (isset($_GET['viewall']) && intval($_GET['viewall']) == 1)
                                {
                                    
                                }
                                else $rows = array_slice($rows, -100);
                                $rows = array_reverse($rows);
                                
                                $viewlog_arr = $rows;
                            }
                        }
                    }
                    break;
            }
        }
        
        
        
        $tab_id = intval($_GET['tab']);
        $tab_array = array(0 => '', 1 => '', 2 => '' );
        $tab_array[$tab_id] = 'active ';
       ?>
<script>
function InfoBlock(id)
{
    jQuery("#"+id).toggle();
}
</script>
<div class="ui grid max-box">

<div class="row">


<div class="ui top attached tabular menu">
        <a href="admin.php?page=plgavp_Antivirus_firewall_page&tab=0" class="<?php echo $tab_array[0]; ?> item"><i class="heartbeat icon"></i> Firewall Status</a>
        <a href="admin.php?page=plgavp_Antivirus_firewall_page&tab=1" class="<?php echo $tab_array[1]; ?> item"><i class="file text outline icon"></i> Firewall Logs</a>
        <a href="admin.php?page=plgavp_Antivirus_firewall_page&tab=2" class="<?php echo $tab_array[2]; ?> item"><i class="configure icon"></i> Firewall Rules</a>
</div>
<div class="ui bottom attached segment">
<?php
if ($tab_id == 0)
{
    ?>
    <h3 class="ui header">Status</h3>
    
    <?php
    if ($action == 'firewall' && isset($_REQUEST['status']))
    {
    ?>
        <script type="text/javascript">
        window.setTimeout(function(){ document.location.href='admin.php?page=plgavp_Antivirus_firewall_page&tab=0'; }, 2000);
        </script>
        <p style="text-align: center;">
            <img width="120" height="120" src="<?php echo plugins_url('images/ajax_loader.svg', __FILE__); ?>" />
            <br /><br />
            Please wait, it will take approximately 2-3 seconds.
        </p>
    <?php
    }
    else {
        $firewall_status = self::CheckFirewallStatus();
        if (!$firewall_status)
        {
            $message_data = array(
                'type' => 'alert',
                'header' => 'Firewall is not activated',
                'message' => 'Website is not protected. Firewall does not filter any trafic.<br>If you need help please contact <a href="https://www.siteguarding.com/en/contacts" target="_blank">SiteGuarding.com Support</a>',
                'button_text' => 'Activate',
                'button_url_target' => false,
                'button_url' => wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=0&action=firewall&status=1'), 'a', 'name_54276D2FA1EE'),
                'help_text' => ''
            );
        }
        else {
            $message_data = array(
                'type' => 'ok',
                'header' => 'Firewall is activate',
                'message' => 'Your website is protected. Firewall filters the traffic and collects the logs.<br><b>Please note:</b> Firewall can not guarantee that website will never got hacked. If you need professional security services and monitoring, please <a target="_blank" href="https://www.siteguarding.com/en/protect-your-website">review this page</a>',
                'button_text' => 'Turn off',
                'button_url_target' => false,
                'button_url' => wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=0&action=firewall&status=0'), 'a', 'name_54276D2FA1EE'),
                'help_text' => ''
            );
        }
        self::PrintIconMessage($message_data); 
        
        
        $file = WP_CONTENT_DIR.'/siteguarding_firewall/logs/_blocked.log';
        if (file_exists($file))
        {
            $message_data = array(
                'type' => 'alert',
                'header' => 'Firewall blocked some activity',
                'message' => 'Firewall blocked some requests and activities on your website. Please study Logs sections for more details.<br>If you need help please contact <a href="https://www.siteguarding.com/en/contacts" target="_blank">SiteGuarding.com Support</a>',
                'button_text' => 'Logs',
                'button_url_target' => false,
                'button_url' => 'admin.php?page=plgavp_Antivirus_firewall_page&tab=1',
                'help_text' => ''
            );
            self::PrintIconMessage($message_data); 
        }
        
    }
}




if ($tab_id == 1)
{
    ?>
    
    <h3 class="ui header">Available log files</h3>
    <?php
    $i = count($viewlog_arr);
    if (count($viewlog_arr))
    {
        if ($i <= 100) $txt_limit = '(Latest 100 records) <a href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=viewlog&viewall=1&file='.$_GET['file']), 'a', 'name_0FB374B3287E').'">View All</a>';
        ?>
        <h4>View log: <?php echo $_GET['file']; ?></h4>
        <p>
        <?php
        echo '<a style="text-decoration: none;" href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=deletelog&file='.$_GET['file']), 'a', 'name_0FB374B3287E').'"><i class="trash outline icon"></i> Delete this log file</a>';
        ?>
        </p>
        
        <table class="ui celled table"><thead><tr><th width="50">#</th><th>Log data <?php echo $txt_limit; ?></th></tr></thead><tbody>
        <?php
        foreach ($viewlog_arr as $row)
        {
            $row = explode("|", $row);
            if (count($row) < 3) continue;
            ?>
            <tr><td><?php echo $i; ?></td>
            <td>
            <?php
            $row[3] = str_replace(ABSPATH, "/", $row[3]);
            echo 'Date: '.$row[0]."<br>";
            echo 'IP: '.$row[1]."<br>";
            echo 'URL: '.$row[2]."<br>";
            echo 'File: '.$row[3];
            if (isset($row[4])) echo "<br>".'Reason: '.$row[4];
            ?>
            </td></tr>
            <?php
            
            $i--;
        }
        ?>
        </tbody></table>
        <?php
    }
    
    
    $folder = WP_CONTENT_DIR.'/siteguarding_firewall/logs/';
    $files = array();
    foreach (glob($folder."*.log.php") as $filename) 
    {
        $f = explode(".php_", $filename);
        $f_short = trim($f[0]).'.php';
        $f_short = str_replace($folder, "", $f_short);
        $files[$f_short] = array(
            'size' => filesize($filename),
            'fname' => basename($filename)
        );
    }
    
    $list_html = '<table class="ui celled table"><thead><tr><th>Log file <a style="text-decoration: none;" href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=clear_all_logs'), 'a', 'name_724526A7F187').'"><i class="trash outline icon"></i> Clean All Logs</a></th><th style="width:20%">Size</th></tr></thead><tbody>';
    
    $file = WP_CONTENT_DIR.'/siteguarding_firewall/logs/_blocked.log';
    if (file_exists($file))
    {
        $filesize = round(filesize($file) / 1024, 2);
        $list_html .= '<tr><td><a style="text-decoration: none;" href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=deletelog&file=_blocked.log'), 'a', 'name_0FB374B3287E').'"><i class="trash outline icon"></i></a> <a href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=viewlog&file=_blocked.log'), 'a', 'name_0FB374B3287E').'"><b><span style="color:#DD3D36">Blocked actions</span></b></a></td><td>'.$filesize.' Kb</td></tr>';
    }
    foreach ($files as $file => $file_info)
    {
        $filesize = round($file_info['size'] / 1024, 2);
        $list_html .= '<tr><td><a style="text-decoration: none;" href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=deletelog&file='.$file_info['fname']), 'a', 'name_0FB374B3287E').'"><i class="trash outline icon"></i></a> <a href="'.wp_nonce_url(admin_url('admin.php?page=plgavp_Antivirus_firewall_page&tab=1&action=viewlog&file='.$file_info['fname']), 'a', 'name_0FB374B3287E').'">'.$file.'</a></td><td>'.$filesize.' Kb</td></tr>';
    }
    $list_html .= '</tbody></table>';
    
    echo $list_html;

}




if ($tab_id == 2)
{
    $myIP = self::GetMyIP();
    $rules = self::ReadFirewallRules();
    
    //print_r($rules);
    
    ?>
    <p class="ui header">Your IP is <b><?php echo $myIP; ?></b></p>
    
    <form method="post" action="admin.php?page=plgavp_Antivirus_firewall_page&tab=2">
        <h4 class="ui header">Block by IP address</h4>
        
        <div class="ui ignored message">
              <i class="help circle icon"></i>e.g. 200.150.160.1 or 200.150.160.* or or 200.150.*.*
        </div>
        
        <div class="ui input" style="width: 100%;margin-bottom:10px">
            <textarea name="rules_blocked_ip" style="width: 100%;height:200px" placeholder="Insert IP addresses or range you want to block, one by line"><?php echo $rules['rules_blocked_ip.txt']; ?></textarea>
        </div>
        
        
        <h4 class="ui header">Allowed IP addresses</h4>
        
        <div class="ui ignored message">
              <i class="help circle icon"></i>e.g. 200.150.160.1 or 200.150.160.* or or 200.150.*.*
        </div>
        
        <div class="ui input" style="width: 100%;margin-bottom:10px">
            <textarea name="rules_allowed_ip" style="width: 100%;height:200px" placeholder="Insert IP addresses or range you want to allow for any action, one by line"><?php echo $rules['rules_allowed_ip.txt']; ?></textarea>
        </div>
        
        
        <h4 class="ui header">Block access to the files</h4>
        
        <div class="ui ignored message">
              <i class="help circle icon"></i>e.g. /wp-config.php
        </div>
        
        <div class="ui input" style="width: 100%;margin-bottom:10px">
            <textarea name="rules_blocked_files" style="width: 100%;height:200px" placeholder="Insert the files you want to block for direct access, one by line"><?php echo $rules['rules_blocked_files.txt']; ?></textarea>
        </div>
        
        
        <h4 class="ui header">Block access to the URLs</h4>
        
        <div class="ui ignored message">
              <i class="help circle icon"></i>e.g. /wp-admin/ (nobody will be able to login to /wp-admin/, don't forget to allow your IP)
        </div>
        
        <div class="ui input" style="width: 100%;margin-bottom:10px">
            <textarea name="rules_blocked_urls" style="width: 100%;height:200px" placeholder="Insert the URLs you want to block for direct access, one by line"><?php echo $rules['rules_blocked_urls.txt']; ?></textarea>
        </div>
        
        <input type="submit" name="submit" id="submit" class="ui green button" value="Save & Apply">
	<?php
	wp_nonce_field( 'name_F8F1EEB45FC3' );
	?>
	<input type="hidden" name="page" value="plgavp_Antivirus_firewall_page"/>
	<input type="hidden" name="action" value="Save_rules_params"/>
	</form>
    <?php
}

?>

</div>
       
    
</div>
</div>	


		
		<?php
        
        
               
        self::HelpBlock();      

    }
    
    
    
    public static function Firewall_Install()
    {
        //wp_remote_get
        
        $file = WP_CONTENT_DIR.'/siteguarding_firewall/firewall.php';
        
        if (!file_exists($file))
        {
            copy(dirname(__FILE__).'/firewall.php', $file);
        }

        $scan_path = ABSPATH;

        // Create php.ini
        $php_user_ini_line = 'auto_prepend_file = "'.$file.'"';
        if (file_exists($scan_path."php.ini"))
        {
            $filename_original = $scan_path."php.ini";
            $filename_backup = $scan_path."php.ini.bak_".date("Ymd");
            copy($filename_original, $filename_backup);
            $lines = self::Read_File($scan_path, 'php.ini');
            self::CreateFile($scan_path, 'php.ini', $lines.$php_user_ini_line);
        }
        else self::CreateFile($scan_path, 'php.ini', $php_user_ini_line);
        // Test HTTP
        if (!self::TestPHP_auto_prepend_file($filename_original, $filename_backup))
		{
            // Create .user.ini
            $php_user_ini_line = 'auto_prepend_file = "'.$file.'"';
            if (file_exists($scan_path.".user.ini"))
            {
                $filename_original = $scan_path.".user.ini";
                $filename_backup = $scan_path.".user.ini.bak_".date("Ymd");
                copy($filename_original, $filename_backup);
                $lines = self::Read_File($scan_path, '.user.ini');
                self::CreateFile($scan_path, '.user.ini', $lines.$php_user_ini_line);
            }
            else self::CreateFile($scan_path, '.user.ini', $php_user_ini_line);
            // Test HTTP
            if (!self::TestPHP_auto_prepend_file($filename_original, $filename_backup))
			{
                // Create .htaccess
                $php_user_ini_line = 'php_value auto_prepend_file '.$file;
                if (file_exists($scan_path.".htaccess"))
                {
                    $filename_original = $scan_path.".htaccess";
                    $filename_backup = $scan_path.".htaccess.bak_".date("Ymd");
                    copy($filename_original, $filename_backup);
                    $lines = self::Read_File($scan_path, '.htaccess');
                    self::CreateFile($scan_path, '.htaccess', $lines.$php_user_ini_line);
                }
                else self::CreateFile($scan_path, '.htaccess', $php_user_ini_line);
                // Test HTTP
                self::TestPHP_auto_prepend_file($filename_original, $filename_backup);
			}
        }
    }
    
    
    public static function Firewall_Remove()
    {
        $file = WP_CONTENT_DIR.'/siteguarding_firewall/firewall.php';
        $scan_path = ABSPATH;
        
        $php_user_ini_line = 'auto_prepend_file = "'.$file.'"';
        if (file_exists($scan_path.".user.ini"))
        {
            $lines = self::Read_File($scan_path, '.user.ini');
            $lines = str_replace($php_user_ini_line, "", $lines);
            self::CreateFile($scan_path, '.user.ini', $lines);
        }
        
        if (file_exists($scan_path."php.ini"))
        {
            $lines = self::Read_File($scan_path, 'php.ini');
            $lines = str_replace($php_user_ini_line, "", $lines);
            self::CreateFile($scan_path, 'php.ini', $lines);
        }
        
        $php_user_ini_line = 'php_value auto_prepend_file '.$file;
        if (file_exists($scan_path.".htaccess"))
        {
            $lines = self::Read_File($scan_path, '.htaccess');
            $lines = str_replace($php_user_ini_line, "", $lines);
            self::CreateFile($scan_path, '.htaccess', $lines);
        }
        
    }
    

    function TestPHP_auto_prepend_file($filename_original, $filename_backup)
    {
        if (!class_exists('EasyRequest'))
        {
            include_once(dirname(__FILE__).'/EasyRequest.min.php');
        }
        
        $link = get_site_url().'?firewall_httptest=1&anticache='.time().'-'.rand(1, 10000);
        
        $client = EasyRequest::create($link);
        $client->send();
        $http_status = $client->getResponseStatus();
        if ($http_status == 500)
        {
            unlink($filename_original);
            if (file_exists($filename_backup)) copy($filename_backup, $filename_original);
        }
    
        $content = trim($client->getResponseBody());
        
        
        if (strpos($content, "STATUS:") !== false)
        {
            if (strpos($content, "firewall.php") !== false)
            {
                return true;
            }
            else return false;
        }
        else {
            unlink($filename_original);
            if (file_exists($filename_backup)) copy($filename_backup, $filename_original);
        }
    }


    public static function Read_File($path, $file)
    {
        $contents = '';
        
        $filename = $path.'/'.$file;
        if (file_exists($filename))
        {
            $fp = fopen($filename, "r");
            $contents = fread($fp, filesize($filename));
            fclose($fp); 
            
            $contents .= "\n\n";       
        }
        
        return $contents;
    }


    public static function CreateFile($path, $file, $content)
    {
        if (file_exists($path.'/'.$file)) unlink($path.'/'.$file);
        $fp = fopen($path.'/'.$file, 'w');
        $status = fwrite($fp, $content);
        fclose($fp);
    
        return $status;
    }


    public static function CheckFirewallStatus()
    {
        // Check module file
        $file = WP_CONTENT_DIR.'/siteguarding_firewall/firewall.php';
        if (!file_exists($file))
        {
            copy(dirname(__FILE__).'/firewall.php', $file);
            
            if (!file_exists($file)) return false;
        }
        
        // Check php ini
        $v = trim(ini_get('auto_prepend_file'));
        if ($v == '') return false;
        
        if (strpos($v, '/siteguarding_firewall/firewall.php') !== false || strpos($v, '/webanalyze/firewall/firewall.php') !== false) return true;
        
        return false;
    }
    
    
    public static function GetMyIP()
    {
        return $_SERVER["REMOTE_ADDR"];
    }
    
	public static function InstallFirewallFolder()
	{
        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/';
        if (!file_exists($folder)) mkdir($folder);
        
        $file = $folder.'.htaccess';
        if (!file_exists($file))
        {
            $fp = fopen($file, 'w');
            $t = '<Limit GET POST>
order deny,allow
deny from all
</Limit>';
            fwrite($fp, $t);
            fclose($fp);
        }
        
        $file = $folder.'rules_requests.txt';
        if (!file_exists($file))
        {
            $fp = fopen($file, 'w');
            $t = 'cDF8Kg0KKnxiYXNlNjRfZGVjb2RlDQoqfHN0cl9yb3QxMw0KKnw8P3BocA0KKnxldmFsKA0KKnxGaWxlc01hbg0KKnxlZG9jZWRfNDZlc2FiDQoqfG1vdmVfdXBsb2FkZWRfZmlsZQ0KKnxleHRyYWN0KCRfQ09PS0lFKQ0KbG9nfHdwdXBkYXRlc3RyZWFtDQpleGVjdXRlfHdwX2luc2VydF91c2VyDQpsb2d8d3AuDQp1c2VybmFtZXxqb29tbGEu';
            $t = base64_decode($t);
            fwrite($fp, $t);
            fclose($fp);
        }
        
        $files = array(
            'rules_allowed_ip.txt',
            'rules_blocked_ip.txt',
            'rules_blocked_files.txt',
            'rules_blocked_urls.txt'
        );
        foreach ($files as $file)
        {
            $file = $folder.$file;
            if (!file_exists($file))
            {
                $fp = fopen($file, 'w');
                fwrite($fp, '');
                fclose($fp);
            }
        }
        
        $folder = $folder.'/logs/';
        if (!file_exists($folder)) mkdir($folder);
        
        $file = $folder.'.htaccess';
        if (!file_exists($file))
        {
            $fp = fopen($file, 'w');
            $t = '<Limit GET POST>
order deny,allow
deny from all
</Limit>';
            fwrite($fp, $t);
            fclose($fp);
        }
	}



	public static function ReadFirewallRules()
	{
	    $a = array();
        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/';
        if (!file_exists($folder)) self::InstallFirewallFolder();
        
        $files = array(
            'rules_allowed_ip.txt',
            'rules_blocked_ip.txt',
            'rules_blocked_files.txt',
            'rules_blocked_urls.txt',
            'rules_requests.txt'
        );
        foreach ($files as $file)
        {
            if (file_exists($folder.$file))
            {
                $filename = $folder.$file;
                $handle = fopen($filename, "r");
                $contents = fread($handle, filesize($filename));
                fclose($handle);
                
                $a[$file] = $contents;
            }
        }
        
        return $a;
	}
    
    
	public static function CombineFirewallRules()
	{
	    $a = array();
        $folder = WP_CONTENT_DIR.'/siteguarding_firewall/';
        if (!file_exists($folder)) self::InstallFirewallFolder();
        
        $files = array(
            'rules_allowed_ip.txt' => '::ALLOW_ALL_IP::',
            'rules_blocked_ip.txt' => '::BLOCK_ALL_IP::',
            'rules_blocked_files.txt' => '::RULES::',
            'rules_blocked_urls.txt' => '::BLOCK_URLS::',
            'rules_requests.txt' => '::BLOCK_REQUESTS::'
        );
        
        $full_rules_txt = '';
        foreach ($files as $file => $firewall_section)
        {
            if (file_exists($folder.$file))
            {
                $filename = $folder.$file;
                $handle = fopen($filename, "r");
                $txt = fread($handle, filesize($filename));
                fclose($handle);
                
                $full_rules_txt .= $firewall_section."\n";
                
                if ($file == 'rules_blocked_files.txt' && $txt != '')
                {
                    $txt = explode("\n", $txt);
                    if (count($txt))
                    {
                        foreach ($txt as $k => $v)
                        {
                            $txt[$k] = 'allow|file|'.$v;
                        }
                        
                        $txt = implode("\n", $txt);
                    }
                }
                $full_rules_txt .= $txt."\n\n";
            }
        }
        
        $filename = $folder."rules.txt";
        $fp = fopen($filename, 'w');
        fwrite($fp, $full_rules_txt);
        fclose($fp);
	}
    

	public static function HelpBlock()
	{
		?>

		<p>
		For more information and details about Antivirus Site Protection please <a target="_blank" href="https://www.siteguarding.com/en/antivirus-site-protection">click here</a>.<br /><br />
		<a href="http://www.siteguarding.com/livechat/index.html" target="_blank">
			<img src="<?php echo plugins_url('images/livechat.png', __FILE__); ?>"/>
		</a><br />
		For any questions and support please use LiveChat or this <a href="https://www.siteguarding.com/en/contacts" rel="nofollow" target="_blank" title="SiteGuarding.com - Website Security. Professional security services against hacker activity. Daily website file scanning and file changes monitoring. Malware detecting and removal.">contact form</a>.<br>
		<br>
		<a href="https://www.siteguarding.com/" target="_blank">SiteGuarding.com</a> - Website Security. Professional security services against hacker activity.<br />
		</p>
		<?php
	}


    public static function PrintIconMessage($data)
    {
        $rand_id = "id_".rand(1,10000).'_'.rand(1,10000);
        if ($data['type'] == '' || $data['type'] == 'alert') {$type_message = 'negative'; $icon = 'warning sign';}
        if ($data['type'] == 'ok') {$type_message = 'green'; $icon = 'checkmark box';}
        if ($data['type'] == 'info') {$type_message = 'yellow'; $icon = 'info';}
        ?>
        <div class="ui icon <?php echo $type_message; ?> message">
            <i class="<?php echo $icon; ?> icon"></i>
            <div class="msg_block_row">
                <?php
                if ($data['button_text'] != '' || $data['help_text'] != '') {
                ?>
                <div class="msg_block_txt">
                    <?php
                    if ($data['header'] != '') {
                    ?>
                    <div class="header"><?php echo $data['header']; ?></div>
                    <?php
                    }
                    ?>
                    <?php
                    if ($data['message'] != '') {
                    ?>
                    <p><?php echo $data['message']; ?></p>
                    <?php
                    }
                    ?>
                </div>
                <div class="msg_block_btn">
                    <?php
                    if ($data['help_text'] != '') {
                    ?>
                    <a class="link_info edit_post" href="javascript:;" onclick="InfoBlock('<?php echo $rand_id; ?>');"><i class="help circle icon"></i></a>
                    <?php
                    }
                    ?>
                    <?php
                    if ($data['button_text'] != '') {
                        if (!isset($data['button_url_target']) || $data['button_url_target'] == true) $new_window = 'target="_blank"';
                        else $new_window = '';
                    ?>
                    <a class="mini ui green button" <?php echo $new_window; ?> href="<?php echo $data['button_url']; ?>"><?php echo $data['button_text']; ?></a>
                    <?php
                    }
                    ?>
                </div>
                    <?php
                    if ($data['help_text'] != '') {
                    ?>
                        <div style="clear: both;"></div>
                        <div id="<?php echo $rand_id; ?>" style="display: none;">
                            <div class="ui divider"></div>
                            <p><?php echo $data['help_text']; ?></p>
                        </div>
                    <?php
                    }
                    ?>
                <?php
                } else {
                ?>
                    <?php
                    if ($data['header'] != '') {
                    ?>
                    <div class="header"><?php echo $data['header']; ?></div>
                    <?php
                    }
                    ?>
                    <?php
                    if ($data['message'] != '') {
                    ?>
                    <p><?php echo $data['message']; ?></p>
                    <?php
                    }
                    ?>
                <?php
                }
                ?>
            </div> 
        </div>
        <?php
    }
    

    
}

?>