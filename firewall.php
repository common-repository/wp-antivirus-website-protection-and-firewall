<?php
/**
 * ver.: 8.0
 */
define( 'SITEGUARDING_DEBUG', false);
define( 'SITEGUARDING_DEBUG_IP', '1.2.3.4');

error_reporting( 0 );

if( ! ini_get('date.timezone') )
{
    date_default_timezone_set('GMT');
}


if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') $DIRSEP = '\\'; 
else $DIRSEP = '/';

$SITEGUARDING_SCAN_PATH = dirname(dirname(dirname(__FILE__)));
define( 'SITEGUARDING_SCAN_PATH', $SITEGUARDING_SCAN_PATH);

$file_firewall_rules = dirname(__FILE__).$DIRSEP.'rules.txt';


if (!file_exists($file_firewall_rules)) die('File is not loaded: rules.txt');

if (SITEGUARDING_FIREWALL_STATUS === false) return;     // exit if firewall is disabled


// Some init constants
define( 'SITEGUARDING_LOG_FILE_MAX_SIZE', 5);	// log file in Mb
define( 'SITEGUARDING_BLOCK_EMPTY_FILES', true);	// block access to empty files
define( 'SITEGUARDING_UNSET_PASSWORD_DATA', false);	// unset passwords

$firewall = new SiteGuarding_Firewall();

$firewall->scan_path = SITEGUARDING_SCAN_PATH;
$firewall->dirsep = $DIRSEP;
$firewall->log_file_max_size = SITEGUARDING_LOG_FILE_MAX_SIZE;




// Load and parse the rules
if (!$firewall->LoadRules()) die('Rules are not loaded');



// Log the request
// *moved to the end* $firewall->LogRequest();


// Checking if the file is empty
if (SITEGUARDING_BLOCK_EMPTY_FILES === true && file_exists($_SERVER['SCRIPT_FILENAME']) && filesize($_SERVER['SCRIPT_FILENAME']) == 0)
{
    $firewall->Block_This_Session('Access to empty file '.$_SERVER["SCRIPT_FILENAME"]);   // the process will die
    exit;
}

if (isset($_SERVER["HTTP_X_REAL_IP"])) $_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_X_REAL_IP"];

// Checking this request based on the rules
if ($firewall->CheckIP_in_Allowed($_SERVER["REMOTE_ADDR"])) {$firewall->LogRequest(); return;}


if ($firewall->CheckIP_in_Blocked($_SERVER["REMOTE_ADDR"]))
{
    $firewall->Block_This_Session('Not allowed IP '.$_SERVER["REMOTE_ADDR"]);   // the process will die
    exit;
}

// Global RULES
if (strpos( $_SERVER['SCRIPT_FILENAME'], SITEGUARDING_SCAN_PATH) != 0)
{
	$SCRIPT_FILENAME = substr($_SERVER['SCRIPT_FILENAME'], strpos( $_SERVER['SCRIPT_FILENAME'], SITEGUARDING_SCAN_PATH));
}
else $SCRIPT_FILENAME = $_SERVER['SCRIPT_FILENAME'];
$tmp_session_rule = $firewall->Session_Apply_Rules($SCRIPT_FILENAME);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Rules for the file');   // the process will die
    exit;
}




// Check Requests
$tmp_session_rule = $firewall->Session_Check_Requests($_REQUEST);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Request rule => '.$firewall->this_session_reason_to_block, true);   // the process will die
    exit;
}

// Check BLOCK_URLS
$tmp_session_rule = $firewall->Check_URLs($_SERVER['REQUEST_URI']);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Not allowed URL');   // the process will die
    exit;
}



// Log the request (the request passed all the rules)
$firewall->LogRequest();




/**
 * Class Firewall
 */
class SiteGuarding_Firewall
{
    var $rules = array();

    var $scan_path = '';
    var $save_empty_requests = false;
    var $single_log_file = false;
    var $dirsep = '/';
    var $email_for_alerts = '';
    var $this_session_rule = false;
    var $this_session_reason_to_block = '';
    var $float_file_folder = false;
	
	var $log_file_max_size = 5;	// in Mb
    

	public function LoadRules()
	{
        $rules = array(
            'ALLOW_ALL_IP' => array(),
            'BLOCK_ALL_IP' => array(),
            'ALERT_IP' => array(),
            'BLOCK_RULES_IP' => array(),
            'RULES' => array(
                'ALLOW' => array(),
                'BLOCK' => array()
            ),
            'BLOCK_RULES' => array(
                'ALLOW' => array(),
                'BLOCK' => array()
            ),
            'BLOCK_URLS' => array(),
            'ALLOW_REQUESTS' => array(),
            'BLOCK_REQUESTS' => array(),
            'EXCLUDE_REMOTE_ALERT_FILES' => array()
        );
        $this->rules = $rules;

        $rows = file(dirname(__FILE__).$this->dirsep.'rules.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if (count($rows) == 0) return true;


        $section = '';
        foreach ($rows as $row)
        {
            $row = trim($row);
            if ($row == '::ALLOW_ALL_IP::') {$section = 'ALLOW_ALL_IP'; continue;}
            if ($row == '::BLOCK_ALL_IP::') {$section = 'BLOCK_ALL_IP'; continue;}
            if ($row == '::ALERT_IP::') {$section = 'ALERT_IP'; continue;}
            if ($row == '::BLOCK_RULES_IP::') {$section = 'BLOCK_RULES_IP'; continue;}
            if ($row == '::RULES::') {$section = 'RULES'; continue;}
            if ($row == '::BLOCK_RULES::') {$section = 'BLOCK_RULES'; continue;}
            if ($row == '::BLOCK_URLS::') {$section = 'BLOCK_URLS'; continue;}
            if ($row == '::ALLOW_REQUESTS::') {$section = 'ALLOW_REQUESTS'; continue;}
            if ($row == '::BLOCK_REQUESTS::') {$section = 'BLOCK_REQUESTS'; continue;}
            if ($row == '::EXCLUDE_REMOTE_ALERT_FILES::') {$section = 'EXCLUDE_REMOTE_ALERT_FILES'; continue;}

			if (strlen($row) == 0) continue;
            if ($row[0] == '#' || $section == '') continue;

            switch ($section)
            {
                case 'BLOCK_URLS':
                    $rules['BLOCK_URLS'][] = trim($row);
                    break;
                    
                case 'BLOCK_REQUESTS':
                    $tmp = explode("|", $row);
                    $rule_field = trim($tmp[0]);
                    $rule_value = trim($tmp[1]);
                    $rules['BLOCK_REQUESTS'][$rule_field][] = $rule_value;
                    break;
                    
                case 'ALLOW_REQUESTS':
                    $tmp = explode("|", $row);
                    $rule_field = trim($tmp[0]);
                    $rule_value = trim($tmp[1]);
                    $rules['ALLOW_REQUESTS'][$rule_field][] = $rule_value;
                    break;

                case 'ALLOW_ALL_IP':
                case 'BLOCK_ALL_IP':
                case 'ALERT_IP':
                case 'BLOCK_RULES_IP':
                    $rules[$section][] = str_replace(array(".*.*.*", ".*.*", ".*"), ".", trim($row));
                    break;

                case 'RULES':
                case 'BLOCK_RULES':
                    $tmp = explode("|", $row);
                    $rule_kind = strtolower(trim($tmp[0]));
                    $rule_type = strtolower(trim($tmp[1]));
                    $rule_object = str_replace($this->dirsep.$this->dirsep, $this->dirsep, $this->scan_path.trim($tmp[2]));

                    switch ($rule_kind)
                    {
                        case 'allow':
                            $rules[$section]['ALLOW'][] = array('type' => $rule_type, 'object' => $rule_object);
                            break;

                        case 'block':
                            $rules[$section]['BLOCK'][] = array('type' => $rule_type, 'object' => $rule_object);
                            break;
                    }

                    break;
                
                case 'EXCLUDE_REMOTE_ALERT_FILES':
                    $rules['EXCLUDE_REMOTE_ALERT_FILES'][] = trim($row);
                    break;
                    
                default:
                    continue;
                    break;
            }
        }

        $this->rules = $rules;

        return true;
    }



    public function Session_Apply_Rules($file)
    {
        $result_final = '';

        if (count($this->rules['RULES']['BLOCK']))
        {
            foreach ($this->rules['RULES']['BLOCK'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                if ($this->float_file_folder === true) $pattern = dirname($file).$this->dirsep.$pattern;

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'block';
            }
        }

        if (count($this->rules['RULES']['ALLOW']))
        {
            foreach ($this->rules['RULES']['ALLOW'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                if ($this->float_file_folder === true) $pattern = dirname($file).$this->dirsep.$pattern;

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'allow';
            }
        }

        return $result_final;
    }







    public function Session_Check_Requests($requests)
    {
        $result_final = 'allow';

        if (count($requests) == 0) return $result_final;
        
        $requests_flat = self::FlatRequestArray($requests);

        //foreach ($requests_flat as $req_field => $req_value)
        foreach ($requests_flat as $requests_flat_array)
        {
            $req_field = $requests_flat_array['f'];
            $req_value = $requests_flat_array['v'];
			
            
            if (isset($this->rules['BLOCK_REQUESTS'][$req_field]))
            {
                foreach ($this->rules['BLOCK_REQUESTS'][$req_field] as $rule_values)
                {
                    if ($rule_values == '*')
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $req_field.":*";
                        return $result_final;
                    }
                    
                    if ($rule_values[0] == '=')
                    {
                        $tmp_rule_value = substr($rule_values, 1);
                        if ($tmp_rule_value == $req_value)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = $req_field.":".$rule_values;
                            return $result_final;
                        }
                    }
                    else {
                        if (stripos($req_value, $rule_values) !== false)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = $req_field.":".$rule_values;
                            return $result_final;
                        }
						
                        if (stripos(base64_decode($req_value), $rule_values) !== false)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = $req_field.":".$rule_values;
                            return $result_final;
                        }
                    }
                }
            }

            if (isset($this->rules['BLOCK_REQUESTS']['*']))
            {
                foreach ($this->rules['BLOCK_REQUESTS']['*'] as $rule_values)
                {
                    if ($rule_values == '*')
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = "*:*";
                        return $result_final;
                    }

                    if ($rule_values[0] == '=')
                    {
                        $tmp_rule_value = substr($rule_values, 1);
                        if ($tmp_rule_value == $req_value)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = $req_field.":".$rule_values;
                            return $result_final;
                        }
                    }
                    else {
                        if (stripos($req_value, $rule_values) !== false)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = "*:".$rule_values;
                            return $result_final;
                        }
						
                        if (stripos(base64_decode($req_value), $rule_values) !== false)
                        {
                            $result_final = 'block';
                            $this->this_session_reason_to_block = "*:".$rule_values;
                            return $result_final;
                        }
                    }
                }
            }
        }

        return $result_final;
    }
    



    public function FlatRequestArray($requests)
    {
        $a = array();
        
        foreach ($requests as $f => $v)
        {
            if (is_array($v))
            {
                $a[] = array('f' => $f, 'v' => '');
                
                foreach ($v as $f2 => $v2)
                {
                    if (is_array($v2))
                    {
                        $a[] = array('f' => $f2, 'v' => '');
                        
                        foreach ($v2 as $f3 =>$v3)
                        {
                            if (is_array($v3)) $v3 = json_encode($v3);
                            $a[] = array('f' => $f3, 'v' => $v3);
                        }
                    }
                    else $a[] = array('f' => $f2, 'v' => $v2); 
                }
            }
            else {
                $a[] = array('f' => $f, 'v' => $v);
            }
        }    
        
        return $a;
    }
    
    
    
    
    public function Check_URLs($REQUEST_URI)
    {
        $result_final = 'allow';
        
        if (count($this->rules['BLOCK_URLS']) == 0) return $result_final;
        
        foreach ($this->rules['BLOCK_URLS'] as $rule_url)
        {
            $rule_url_clean = str_replace("*", "", $rule_url);
            if ($rule_url[0] == '*')
            {
                if ($rule_url[strlen($rule_url)-1] == '*')  // e.g. *xxx*
                {
                    if (stripos($REQUEST_URI, $rule_url_clean) !== false)
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $rule_url;
                        return $result_final;
                    }
                }
                else {
                    $tmp_pos = stripos($REQUEST_URI, $rule_url_clean);
                    if ($tmp_pos !== false && $tmp_pos + strlen($rule_url_clean) == strlen($REQUEST_URI))     // e.g. *xxx
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $rule_url;
                        return $result_final;
                    }
                }
            }
            else {
                if ($rule_url[strlen($rule_url)-1] == '*')  // e.g. /xxx*
                {
                    $tmp_pos = stripos($REQUEST_URI, $rule_url_clean);
                    if ( $tmp_pos !== false && $tmp_pos == 0)
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $rule_url;
                        return $result_final;
                    }
                }
                else {
                    if ($rule_url == $REQUEST_URI)  // e.g. /xxx/
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $rule_url;
                        return $result_final;
                    }
                }
            }
        }
        
        
        return $result_final;
    }


    public function Block_This_Session($reason = '', $save_request = false)
    {
        $siteguarding_log_line = date("Y-m-d H:i:s")."|".
        	$_SERVER["REMOTE_ADDR"]."|".
        	"http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"."|".
        	$_SERVER['SCRIPT_FILENAME']."|".
			$reason."\n";
        $this->SaveLogs($siteguarding_log_line);
        die('Access is not allowed. Please contact website webmaster or SiteGuarding.com support. Blocked IP address is '.$_SERVER["REMOTE_ADDR"]);
    }




    public function CheckIP_in_Allowed($ip)
    {
        if (count($this->rules['ALLOW_ALL_IP']) == 0) return false;

        foreach ($this->rules['ALLOW_ALL_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                return true;
            }
        }
    }



    public function CheckIP_in_Blocked($ip)
    {
        if (count($this->rules['BLOCK_ALL_IP']) == 0) return false;

        foreach ($this->rules['BLOCK_ALL_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                return true;
            }
        }
    }


	public function SaveLogs($txt)
	{
        $a = $txt."\n";
       
    	$log_file = dirname(__FILE__).$this->dirsep.'logs'.$this->dirsep.'_blocked.log';
        
        if (!file_exists($log_file)) 
		{
			$log_file_new = true;
			$log_filesize = 0;
		}
        else {
			$log_file_new = false;
			$log_filesize = filesize($log_file);
		}

    	if ($log_file_new && $log_filesize > $this->log_file_max_size * 1024 * 1024)
    	{
    	    // Trunc log file
    	    $log_file_tmp = $log_file.".tmp";
            
            $fp1 = fopen($log_file, "rb");
            $fp2 = fopen($log_file_tmp, "wb");
            
            $pos = $log_filesize * 0.7;     // 30%
            fseek($fp1, $pos);
            
            while (!feof($fp1)) {
                $buffer = fread($fp1, 4096 * 32);
                fwrite($fp2, $buffer);
            }
            
            fclose($fp1);
            fwrite($fp2, $a);
            fclose($fp2);
            
            rename($log_file_tmp, $log_file);
    	}
    	else {
            $fp = fopen($log_file, 'a');
            fwrite($fp, $a);
            fclose($fp);
        }
    } 
	

	public function LogRequest($short = false)
	{
		$_REQUEST_tmp = $_REQUEST;
		
        if (!$this->save_empty_requests && count($_REQUEST_tmp) == 0) return;
		


        $log_file = basename($_SERVER['SCRIPT_FILENAME'])."_".md5($_SERVER['SCRIPT_FILENAME']).".log.php";

        $log_file = dirname(__FILE__).$this->dirsep.'logs'.$this->dirsep.$log_file;

        if (!file_exists($log_file)) 
		{
			$log_file_new = true;
			$log_filesize = 0;
		}
        else {
			$log_file_new = false;
			$log_filesize = filesize($log_file);
		}
		
       
    	if (file_exists($log_file) && filesize($log_file) > $this->log_file_max_size * 1024 * 1024)
    	{
    	    // Trunc log file
    	    $log_file_tmp = $log_file.".tmp";
            
            $fp1 = fopen($log_file, "rb");
            $fp2 = fopen($log_file_tmp, "wb");
            fwrite($fp2, '<?php exit; ?>'."\n".$_SERVER['SCRIPT_FILENAME']."\n\n");
            
            $pos = $log_filesize * 0.7;     // 30%
            fseek($fp1, $pos);
            
            while (!feof($fp1)) {
                $buffer = fread($fp1, 4096 * 32);
                fwrite($fp2, $buffer);
            }
            
            fclose($fp1);
            fclose($fp2);
            
            rename($log_file_tmp, $log_file);
    	} 
		
		
        $fp = fopen($log_file, "a");

        
        $siteguarding_log_line = date("Y-m-d H:i:s")."|".
        	$_SERVER["REMOTE_ADDR"]."|".
        	"http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"."|".
        	$_SERVER['SCRIPT_FILENAME']."\n";
        

        if ($log_file_new) fwrite($fp, '<?php exit; ?>'."\n".$_SERVER['SCRIPT_FILENAME']."\n\n");
        fwrite($fp, $siteguarding_log_line);
        fclose($fp);

    }

} 
?>