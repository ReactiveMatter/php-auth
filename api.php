<?php

/*	Module: User database manager
 *  Description: It contains the web api for user management for an authentication based app
 */

require_once("udb.php");

header("Content-type: application/json; charset=utf-8");

if(isset($_POST['action']))
{	
	$r = new db_result();
	$d = new userdb();
	
	if($_POST['action']=="get_user" && isset($_POST['username']))
	{	
		$r = $d->get_user($_POST['username']);
	}

	else if($_POST['action'] == 'get_all_users')
	{
		$r = $d->get_all_users();
	}
	else if($_POST['action']=='get_logged_in_user')
	{
		$r = $d->get_logged_in_user();
	}
	
	else if($_POST['action']=='login' && isset($_POST['username']) && isset($_POST['password']))
	{
		$r = $d->login($_POST['username'],$_POST['password']);
	}
	
	else if($_POST['action']=='add' && isset($_POST['username']) && isset($_POST['password']) && isset($_POST['role']))
	{	
		$r = $d->add_user($_POST['username'],$_POST['password'],$_POST['role']);
	}
	
	else if($_POST['action']=='delete' && isset($_POST['username']))
	{	
		$r = $d->delete_user($_POST['username']);
	}
	
	else if ($_POST['action']=='logout') {
		
		$r = $d->logout();
	}

	else if ($_POST['action']=='change_password' && isset($_POST['password'])) {
		
		$r = $d->change_password($_POST['password']);
	}
	
	else if($_POST['action']=='change_password_by_admin' && isset($_POST['username']) && isset($_POST['password']))
	{
		$r = $d->change_password_by_admin($_POST['username'],$_POST['password']);
	}
	
	else if($_POST['action']=='change_role_by_admin' && isset($_POST['username']) && isset($_POST['role']))
	{
		$r = $d->change_role_by_admin($_POST['username'],$_POST['role']);
	}
	
	else {
		$r->error_message = "Insufficient parameters";
	}

	echo json_encode($r);

}
