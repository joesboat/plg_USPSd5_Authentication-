<?php
/**
 * @copyright	Copyright (C) 2015 Joseph P. Gibson. All rights reserved.
 * @license		GNU General Public License version 2 or later; see LICENSE.txt
 */
// No direct access
defined('_JEXEC') or die;
/**
 * USPS Authentication plugin
 *
 * @package		Joomla.Plugin
 * @subpackage	Authentication.usps
 * @since 1.5
 */
jimport('usps.tableVHQAB');
jimport('usps.tableD5VHQAB');
jimport('usps.includes.routines');
class plgAuthenticationUsps extends JPlugin
{
	/**
	 * This method should handle front end authentication and report back to the subject
	 *
	 * @access	public
	 * @param	array	Array holding the user credentials
	 * @param	array	Array of extra options
	 * @param	object	Authentication response object
	 * @return	boolean
	 * @since 1.5
	 */
	function onUserAuthenticate($creds, $options, &$response)
	{
		$params = $this->params;
		$debug = $params->get("debug");
		$log = $params->get("log");
		$d5_login = $params->get("d5_login");
		if ($debug) log_it("Entering ".__FILE__, __LINE__);
		//*************   A password must be supplied     ************
		if (empty($creds['password'])) {
			$response->status = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
			return false;
		}
		// Get a database object
		if ($d5_login){
			if ($debug) write_log_array($creds,"USPSd5 Log In.",__LINE__);
			$vhqab = new USPSd5tableVHQAB();  
		} else {
			if ($debug) write_log_array($creds,"USPS Log In.",__LINE__);
			$vhqab = new USPStableVHQAB();  
		}
		if ($debug and $vhqab) log_it("Database Open",__LINE__);
		$session = JFactory::getSession();
		$squad_no = $session->get("squad_no");
		$dist_no = $session->get("dist_no");
		if ((! $squad_no) and (! $dist_no) ){
			if ($d5_login)
				$OK = $vhqab->isValidD5Member($creds['username'],$creds['password']);
			else 
				$OK = $vhqab->isValidMember($creds['username'],$creds['password']);
		}
		elseif ($squad_no){
			$OK = $vhqab->isValidSquadronMember($creds['username'],$creds['password'],$squad_no);
		} 
		else 
		{
			$distno = $session->get("distno");			
			$OK = $vhqab->isValidDistrictMember($creds['username'],$creds['password'],$distno);
		}
		//$usps_member = $vhqab->getMember($creds['username'], $squad_no);
		//if (! $vhqab->isValidMember($creds['username'],$creds['password'],$squad_no))
		if (! $OK)
		{
			// The certificate is not valid.
			$response->status = JAuthentication::STATUS_FAILURE;
			//$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
			$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
		}
		else 
		{
			//  Ok, we have a valid member  
			set_uspscert_cookie($creds, $options['remember']);
			if ($squad_no) 
				set_sss_cookie($squad_no, $creds['username']);
			if ($d5_login){
				$uspsd5_member = $vhqab->getD5Member($creds['username']);
				//if ($debug) write_log_array($uspsd5_member, '$uspsd5_member' ,__LINE__);
				set_uspsd5_cookie($uspsd5_member, $options['remember']);
			}
			//if ($debug) log_it("Opening vhqab ",__LINE__);
			$response->email = $vhqab->getMemberEmail($creds['username']);
			if ($debug) log_it("Email is ".$response->email,__LINE__);
			$response->fullname = $vhqab->getMemberName($creds['username']);
			if ($debug) log_it("Fullname is ".$response->fullname,__LINE__);

			$response->status = JAuthentication::STATUS_SUCCESS;
			$response->type = 'usps';
			$response->username = $creds['username'];
			$response->password = $creds['password'];					
			$response->error_message = '';
			$response->language = NULL;
			$response->groups = $vhqab->get_jobs($creds['username']);
			if ($log) log_it($response->fullname." was authenticated. ");
		} 
	}
}
