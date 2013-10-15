<?php
/**
 * Facebook strategy for Opauth
 * based on https://developers.facebook.com/docs/authentication/server-side/
 * 
 * More information on Opauth: http://opauth.org
 * 
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.FacebookStrategy
 * @license      MIT License
 */

class FacebookStrategy extends OpauthStrategy{
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 * eg. array('app_id', 'app_secret');
	 */
	public $expects = array('app_id', 'app_secret');
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}int_callback'
	);

	/**
	 * Auth request
	 */
	public function request(){
		$url = 'https://www.facebook.com/dialog/oauth';
		$params = array(
			'client_id' => $this->strategy['app_id'],
			'redirect_uri' => $this->strategy['redirect_uri']
		);

		if (!empty($this->strategy['scope'])) $params['scope'] = $this->strategy['scope'];
		if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];
		if (!empty($this->strategy['response_type'])) $params['response_type'] = $this->strategy['response_type'];
		if (!empty($this->strategy['display'])) $params['display'] = $this->strategy['display'];
		if (!empty($this->strategy['auth_type'])) $params['auth_type'] = $this->strategy['auth_type'];
		
		$this->clientGet($url, $params);
	}
	
	/**
	 * Internal callback, after Facebook's OAuth
	 */
	public function int_callback(){
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
			$url = 'https://graph.facebook.com/oauth/access_token';
			$params = array(
				'client_id' =>$this->strategy['app_id'],
				'client_secret' => $this->strategy['app_secret'],
				'redirect_uri'=> $this->strategy['redirect_uri'],
				'code' => trim($_GET['code'])
			);
			$response = $this->serverGet($url, $params, null, $headers);
			
			parse_str($response, $results);

			if (!empty($results) && !empty($results['access_token'])){
				$me = $this->me($results['access_token']);

				$this->auth = array(
					'provider' => 'Facebook',
					'uid' => $me->id,
					'info' => array(
						'name' => $me->name,
						'image' => 'http://graph.facebook.com/'.$me->id.'/picture?type=large'
					),
					'credentials' => array(
						'token' => $results['access_token'],
						'expires' => date('c', time() + $results['expires'])
					),
					'raw' => $me
				);

				$education = array();
				$work = array();

				if(isset($me->education) && !empty($me->education)) {
					foreach ($me->education as $edu => $cnt) {
						$edu = $me->education[$edu];
						$field_of_study = array();
						if(isset($edu->concentration) && !empty($edu->concentration)) {
							foreach($edu->concentration as $field) {
								array_push($field_of_study, $field->name);
							}
						}

						array_push($education, array(
							'institution' => (isset($edu->school) && !empty($edu->school) ? $edu->school->name : 'Unknown Institution'),
							'field_of_study' => implode(', ', $field_of_study),
							'start_date' => null,
							'end_date' => (isset($edu->year) && !empty($edu->year) ? date('Y-m-d H:i:s', strtotime('01/01/' . $edu->year->name)) : null),
							'currentlyAttendingFlag' => (!isset($edu->year) || (isset($edu->year) && date('Y', $edu->year->name) <= date('Y')) ? 1 : 0)));
					}
				}

				if(isset($me->work) && !empty($me->work)) {
					foreach ($me->work as $job => $cnt) {
						$job = $me->work[$job];
						array_push($work, array(
							'employer' => (isset($job->employer) && !empty($job->employer) ? $job->employer->name : 'Unknown Employer'),
							'position' => (isset($job->position) && !empty($job->position) ? $job->position->name : null),
							'start_date' => (isset($job->start_date) && !empty($job->start_date) ? $job->start_date : null),
							'end_date' => (isset($job->end_date) && !empty($job->end_date) && strToTime($job->end_date) != null ? $job->end_date : null),
							'currentlyWorkingFlag' => (isset($job->end_date) && !empty($job->end_date) && strToTime($job->end_date) != null ? (strToTime(date('Y-m-d')) <= strToTime($job->end_date) ? 1 : 0) : 1)));
					}
				}
				
				if (!empty($me->email)) $this->auth['info']['email'] = $me->email;
				if (!empty($me->username)) $this->auth['info']['username'] = $me->username;
				if (!empty($me->first_name)) $this->auth['info']['first_name'] = $me->first_name;
				if (!empty($me->last_name)) $this->auth['info']['last_name'] = $me->last_name;
				if (!empty($me->location)) $this->auth['info']['location'] = $me->location->name;
				if (!empty($me->link)) $this->auth['info']['urls']['facebook'] = $me->link;
				if (!empty($me->website)) $this->auth['info']['urls']['website'] = $me->website;
				if (!empty($me->education)) $this->auth['info']['education'] = $education;
				if (!empty($me->work)) $this->auth['info']['work'] = $work;
				
				/**
				 * Missing optional info values
				 * - description
				 * - phone: not accessible via Facebook Graph API
				 */
				
				$this->callback();
			}
			else{
				$error = array(
					'provider' => 'Facebook',
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => $headers
				);

				$this->errorCallback($error);
			}
		}
		else{
			$error = array(
				'provider' => 'Facebook',
				'code' => $_GET['error'],
				'message' => $_GET['error_description'],
				'raw' => $_GET
			);
			
			$this->errorCallback($error);
		}
	}
	
	/**
	 * Queries Facebook Graph API for user info
	 *
	 * @param string $access_token 
	 * @return array Parsed JSON results
	 */
	private function me($access_token){
		$me = $this->serverGet('https://graph.facebook.com/me', array('access_token' => $access_token), null, $headers);
		if (!empty($me)){
			return json_decode($me);
		}
		else{
			$error = array(
				'provider' => 'Facebook',
				'code' => 'me_error',
				'message' => 'Failed when attempting to query for user information',
				'raw' => array(
					'response' => $me,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
		}
	}
}