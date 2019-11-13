<?php
class wfScan {
	public static $debugMode = false;
	public static $errorHandlingOn = true;
	public static $peakMemAtStart = 0;
	
	/**
	 * Returns the stored cronkey or false if not set. If $expired is provided, will set to <timestamp>/false based
	 * on whether or not the cronkey is expired.
	 * 
	 * @param null $expired
	 * @return bool|string
	 */
	private static function storedCronKey(&$expired = null) {
		$currentCronKey = wfConfig::get('currentCronKey', false);
		if (empty($currentCronKey))
		{
			if ($expired !== null) {
				$expired = false;
			}
			return false;
		}
		
		$savedKey = explode(',',$currentCronKey);
		if (time() - $savedKey[0] > 86400) {
			if ($expired !== null) {
				$expired = $savedKey[0];
			}
			return $savedKey[1];
		}
		
		if ($expired !== null) {
			$expired = false;
		}
		return $savedKey[1];
	}
	
	public static function wfScanMain(){
		self::$peakMemAtStart = memory_get_peak_usage(true);
		$db = new wfDB();
		if($db->errorMsg){
			self::errorExit("Could not connect to database to start scan: " . $db->errorMsg);
		}
		if(! wordfence::wfSchemaExists()){
			self::errorExit("Looks like the Wordfence database tables have been deleted. You can fix this by de-activating and re-activating the Wordfence plugin from your Plugins menu.");
		}
		if( isset( $_GET['test'] ) && $_GET['test'] == '1'){
			echo "WFCRONTESTOK:" . wfConfig::get('cronTestID');
			self::status(4, 'info', "Cron test received and message printed");
			exit();
		}
		/* ----------Starting cronkey check -------- */
		self::status(4, 'info', "Scan engine received request.");
		
		self::status(4, 'info', "Fetching stored cronkey for comparison.");
		$expired = false;
		$storedCronKey = self::storedCronKey($expired);
		$displayCronKey_received = (isset($_GET['cronKey']) ? (preg_match('/^[a-f0-9]+$/i', $_GET['cronKey']) && strlen($_GET['cronKey']) == 32 ? $_GET['cronKey'] : __('[invalid]', 'wordfence')) : __('[none]', 'wordfence'));
		$displayCronKey_stored = (!empty($storedCronKey) && !$expired ? $storedCronKey : __('[none]', 'wordfence'));
		self::status(4, 'info', sprintf(__('Checking cronkey: %s (expecting %s)', 'wordfence'), $displayCronKey_received, $displayCronKey_stored));
		if (empty($_GET['cronKey'])) { 
			self::status(4, 'error', "Wordfence scan script accessed directly, or WF did not receive a cronkey.");
			echo "If you see this message it means Wordfence is working correctly. You should not access this URL directly. It is part of the Wordfence security plugin and is designed for internal use only.";
			exit();
		}
		
		if ($expired) {
			self::errorExit("The key used to start a scan expired. The value is: " . $expired . " and split is: " . $storedCronKey . " and time is: " . time());
		} //keys only last 60 seconds and are used within milliseconds of creation
		
		if (!$storedCronKey) {
			wordfence::status(4, 'error', "Wordfence could not find a saved cron key to start the scan so assuming it started and exiting.");
			exit();
		} 
		
		self::status(4, 'info', "Checking saved cronkey against cronkey param");
		if (!hash_equals($storedCronKey, $_GET['cronKey'])) { 
			self::errorExit("Wordfence could not start a scan because the cron key does not match the saved key. Saved: " . $storedCronKey . " Sent: " . $_GET['cronKey'] . " Current unexploded: " . wfConfig::get('currentCronKey', false));
		}
		wfConfig::set('currentCronKey', '');
		/* --------- end cronkey check ---------- */
		
		$scanMode = wfScanner::SCAN_TYPE_STANDARD;
		if (isset($_GET['scanMode']) && wfScanner::isValidScanType($_GET['scanMode'])) {
			$scanMode = $_GET['scanMode'];
		}
		$scanController = new wfScanner($scanMode);

		wfConfig::remove('scanStartAttempt');
		$isFork = ($_GET['isFork'] == '1' ? true : false);

		if(! $isFork){
			self::status(4, 'info', "Checking if scan is already running");
			if(! wfUtils::getScanLock()){
				self::errorExit("There is already a scan running.");
			}
			
			wfIssues::updateScanStillRunning();
			wfConfig::set('wfPeakMemory', 0, wfConfig::DONT_AUTOLOAD);
			wfConfig::set('wfScanStartVersion', wfUtils::getWPVersion());
			wfConfig::set('lowResourceScanWaitStep', false);
			
			if ($scanController->useLowResourceScanning()) {
				self::status(1, 'info', "Using low resource scanning");
			}
		}
		self::status(4, 'info', "Requesting max memory");
		wfUtils::requestMaxMemory();
		self::status(4, 'info', "Setting up error handling environment");
		set_error_handler('wfScan::error_handler', E_ALL);
		register_shutdown_function('wfScan::shutdown');
		if(! self::$debugMode){
			ob_start('wfScan::obHandler');
		}
		@error_reporting(E_ALL);
		wfUtils::iniSet('display_errors','On');
		self::status(4, 'info', "Setting up scanRunning and starting scan");
		try {
			if ($isFork) {
				$scan = wfConfig::get_ser('wfsd_engine', false, false);
				if ($scan) {
					self::status(4, 'info', "Got a true deserialized value back from 'wfsd_engine' with type: " . gettype($scan));
					wfConfig::set('wfsd_engine', '', wfConfig::DONT_AUTOLOAD);
				}
				else {
					self::status(2, 'error', "Scan can't continue - stored data not found after a fork. Got type: " . gettype($scan));
					wfConfig::set('wfsd_engine', '', wfConfig::DONT_AUTOLOAD);
					wfConfig::set('lastScanCompleted', __('Scan can\'t continue - stored data not found after a fork.', 'wordfence'));
					wfConfig::set('lastScanFailureType', wfIssues::SCAN_FAILED_FORK_FAILED);
					wfUtils::clearScanLock();
					self::status(2, 'error', "Scan terminated with error: " . __('Scan can\'t continue - stored data not found after a fork.', 'wordfence'));
					self::status(10, 'info', "SUM_KILLED:Previous scan terminated with an error. See below.");
					exit();
				}
			}
			else {
				$delay = -1;
				$isScheduled = false;
				$originalScanStart = wfConfig::get('originalScheduledScanStart', 0);
				$lastScanStart = wfConfig::get('lastScheduledScanStart', 0);
				$minimumFrequency = ($scanController->schedulingMode() == wfScanner::SCAN_SCHEDULING_MODE_MANUAL ? 1800 : 43200);
				if ($lastScanStart && (time() - $lastScanStart) < $minimumFrequency) {
					$isScheduled = true;
					
					if ($originalScanStart > 0) {
						$delay = max($lastScanStart - $originalScanStart, 0);
					}
				}
				
				wfIssues::statusPrep(); //Re-initializes all status counters
				$scanController->resetStages();
				$scanController->resetSummaryItems();
				
				if ($scanMode != wfScanner::SCAN_TYPE_QUICK) {
					wordfence::status(1, 'info', "Contacting Wordfence to initiate scan");
					$wp_version = wfUtils::getWPVersion();
					$apiKey = wfConfig::get('apiKey');
					$api = new wfAPI($apiKey, $wp_version);
					$response = $api->call('log_scan', array(), array('delay' => $delay, 'scheduled' => (int) $isScheduled, 'mode' => wfConfig::get('schedMode')/*, 'forcedefer' => 1*/));
					
					if ($scanController->schedulingMode() == wfScanner::SCAN_SCHEDULING_MODE_AUTOMATIC && $isScheduled) {
						if (isset($response['defer'])) {
							$defer = (int) $response['defer'];
							wordfence::status(2, 'info', "Deferring scheduled scan by " . wfUtils::makeDuration($defer));
							wfConfig::set('lastScheduledScanStart', 0);
							wfConfig::set('lastScanCompleted', 'ok');
							wfConfig::set('lastScanFailureType', false);
							wfConfig::set_ser('wfStatusStartMsgs', array());
							$scanController->recordLastScanTime();
							$i = new wfIssues();
							wfScanEngine::refreshScanNotification($i);
							wfScanner::shared()->scheduleSingleScan(time() + $defer, $originalScanStart);
							wfUtils::clearScanLock();
							exit();
						}
					}
					
					$malwarePrefixesHash = (isset($response['malwarePrefixes']) ? $response['malwarePrefixes'] : '');
					$coreHashesHash = (isset($response['coreHashes']) ? $response['coreHashes'] : '');
					
					$scan = new wfScanEngine($malwarePrefixesHash, $coreHashesHash, $scanMode);
					$scan->deleteNewIssues();
				}
				else {
					wordfence::status(1, 'info', "Initiating quick scan");
					$scan = new wfScanEngine('', '', $scanMode);
				}
			}
			
			$scan->go();
		}
		catch (wfScanEngineDurationLimitException $e) { //User error set in wfScanEngine
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			exit();
		}
		catch (wfScanEngineCoreVersionChangeException $e) { //User error set in wfScanEngine
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with message: " . $e->getMessage());
			
			$nextScheduledScan = wordfence::getNextScanStartTimestamp();
			if ($nextScheduledScan !== false && $nextScheduledScan - time() > 21600 /* 6 hours */) {
				$nextScheduledScan = time() + 3600;
				wfScanner::shared()->scheduleSingleScan($nextScheduledScan);
			}
			self::status(2, 'error', wordfence::getNextScanStartTime($nextScheduledScan));
			
			exit();
		}
		catch (wfAPICallSSLUnavailableException $e) {
			wfConfig::set('lastScanCompleted', $e->getMessage());
			wfConfig::set('lastScanFailureType', wfIssues::SCAN_FAILED_API_SSL_UNAVAILABLE);
			
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			exit();
		}
		catch (wfAPICallFailedException $e) {
			wfConfig::set('lastScanCompleted', $e->getMessage());
			wfConfig::set('lastScanFailureType', wfIssues::SCAN_FAILED_API_CALL_FAILED);
			
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			exit();
		}
		catch (wfAPICallInvalidResponseException $e) {
			wfConfig::set('lastScanCompleted', $e->getMessage());
			wfConfig::set('lastScanFailureType', wfIssues::SCAN_FAILED_API_INVALID_RESPONSE);
			
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			exit();
		}
		catch (wfAPICallErrorResponseException $e) {
			wfConfig::set('lastScanCompleted', $e->getMessage());
			wfConfig::set('lastScanFailureType', wfIssues::SCAN_FAILED_API_ERROR_RESPONSE);
			
			wfUtils::clearScanLock();
			$peakMemory = self::logPeakMemory();
			self::status(2, 'info', "Wordfence used " . wfUtils::formatBytes($peakMemory - self::$peakMemAtStart) . " of memory for scan. Server peak memory usage was: " . wfUtils::formatBytes($peakMemory));
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			exit();
		}
		catch (Exception $e) {
			wfUtils::clearScanLock();
			self::status(2, 'error', "Scan terminated with error: " . $e->getMessage());
			self::status(10, 'info', "SUM_KILLED:Previous scan terminated with an error. See below.");
			exit();
		}
		wfUtils::clearScanLock();
	}
	public static function logPeakMemory(){
		$oldPeak = wfConfig::get('wfPeakMemory', 0, false);
		$peak = memory_get_peak_usage(true);
		if ($peak > $oldPeak) {
			wfConfig::set('wfPeakMemory', $peak, wfConfig::DONT_AUTOLOAD);
			return $peak;
		}
		return $oldPeak;
	}
	public static function obHandler($buf){
		if(strlen($buf) > 1000){
			$buf = substr($buf, 0, 255);
		}
		if(empty($buf) === false && preg_match('/[a-zA-Z0-9]+/', $buf)){
			self::status(1, 'error', $buf);
		}
	}
	public static function error_handler($errno, $errstr, $errfile, $errline){
		if(self::$errorHandlingOn && error_reporting() > 0){
			if(preg_match('/wordfence\//', $errfile)){
				$level = 1; //It's one of our files, so level 1
			} else {
				$level = 4; //It's someone elses plugin so only show if debug is enabled
			}
			self::status($level, 'error', "$errstr ($errno) File: $errfile Line: $errline");
		}
		return false;
	}
	public static function shutdown(){
		self::logPeakMemory();
	}
	private static function errorExit($msg){
		wordfence::status(1, 'error', "Scan Engine Error: $msg");
		exit();	
	}
	private static function status($level, $type, $msg){
		wordfence::status($level, $type, $msg);
	}
}
