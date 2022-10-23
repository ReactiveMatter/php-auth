<?php


/*	Module: User database manager
 *	Description: It contains the api for user management for an authentication based app
 */

date_default_timezone_set("Asia/Kolkata");
define("DB_DIR_PATH", dirname(__FILE__));

//Class having user properties
class user
{
	public $username;
	public $role; //User can be given multiple roles ('admin' role is reserved for superadmin)
	public $created;	//Datetime of user creation
	public $last_updated;	//Datetime of last updation
	private $password;
	
	function __construct($username, $password, $role, $created, $last_updated)
	{
		$this->username = $username;
		$this->role = $role;
		$this->created = $created;
		$this->last_updated = $last_updated;
		$this->password = $password;
	}

	function get_password()
	{
		return $this->password;
	}

}


/**
 * All responses from functions in this database will be in this format (except for some boolean functions that start check)
 */
class db_result
{
	public $success = false; //boolean was the expected thing done
	public $response_type = 'bool'; //string which determines the class of the response object;
	public $response; //Response object (it can be object of any of the classes or an array of the objects)
	public $error_message; //Error message
}


class userdb
{
	public $connection_status;
	private $connection;
	private $cookie_name = "common";
	function __construct()
	{
		if(file_exists(DB_DIR_PATH."/users.db"))
		{  	
			$this->connection = new SQLite3(DB_DIR_PATH."/users.db");
			if($this->connection)	
			{$this->connection_status = true;}
		}
		else
		{$this->connection_status = false;

		}
	}

//Adds user
function add_user($username, $password, $role)
{
	$result = new db_result();

	//Sanitizing inputs;
	$username = addslashes(trim($username));
	$password = addslashes(trim($password));
	$role = addslashes(trim($role));

	if($this->connection_status)
	{	
		if(!$this->check_if_admin())
		{
			$result->error_message="Action restricted"; 
			return $result;
		}

		if($this->get_user($username)->success)
		{
			$result->error_message = "Username already taken";
			return $result;
		}

		$r = $this->connection->exec('INSERT INTO users VALUES(NULL,"'.$username.'","'.password_hash($password, PASSWORD_DEFAULT).'","'.date("Y-m-d H:i:s").'","'.date("Y-m-d H:i:s").'","'.$role.'")');
		if($r)
		{
			$result->success = true;
		}
	}

	return $result;
}

//Deletes user from the database
function delete_user($username)
{
	$result = new db_result();

	//Sanitizing inputs;
	$username = addslashes(trim($username));


	if($this->connection_status)
	{	
		if(!$this->check_if_admin()){$result->error_message="Action restricted"; return $result;}

		if($this->get_user($username)->success)
		{	//Currently not allowing deleting of admin (Ideally only one admin should be there)
			if($this->get_user($username)->response->role == 'admin')
			{
				$result->error_message="Action restricted: Cannot delete admin."; return $result;
			}
		}

		$r = $this->connection->exec('DELETE from users where username="'.$username.'";');
		if($r)
		{
			$result->success = true;
			$this->connection->exec('DELETE from auth_tokens where username="'.$username.'";');
		}
		else
		{
			$result->error_message = "Cannot delete user";
		}
	}

	return $result;
}

//change password by the currently logged person
function change_password($np)
{
	$result = new db_result();

	//Sanitizing inputs;
	$np = addslashes(trim($np));

	if($this->check_login_status())
	{	$token = $_COOKIE[$this->cookie_name];
		$r = $this->connection->querySingle("SELECT * from auth_tokens WHERE token='".$token."';", true);
			if($r)
			{
				$rr = $this->connection->exec("UPDATE users SET password = '".password_hash($np, PASSWORD_DEFAULT)."', last_updated = '".date("Y-m-d H:i:s")."' WHERE username='".$r['username']."';");
				if($rr)
				{
					$result->success = true;
				}
				else
				{
					$result->error_message = "Cannot update password";
				}
			}
	}
	else
	{
		$result->error_message = "Action restricted to only logged in users";
	}

	return $result;

}

//Forced password change by admin
function change_password_by_admin($u, $np)
{
	$result = new db_result();

	//Sanitizing inputs;
	$np = addslashes(trim($np));

	if($this->check_if_admin())
	{	
		if($this->get_user($u)->success==false) 
			{ 
				$result->error_message = "User not found"; 
				return $result;
			}

		$r = $this->connection->exec("UPDATE users SET password = '".password_hash($np, PASSWORD_DEFAULT)."', last_updated = '".date("Y-m-d H:i:s")."' WHERE username='".$u."';");
		if($r)
		{
			$result->success = true;
		}
		else
		{
			$result->error_message = "Cannot update password";
		}
	
	}
	else
	{
		$result->error_message = "Action restricted";
	}

	return $result;
}

function change_role_by_admin($u, $role)
{
	$result = new db_result();

	//Sanitizing inputs;
	$role = addslashes(strtolower(trim($role)));

	if($this->check_if_admin())
	{	
		if($this->get_user($u)->success==false) 
			{ 
				$result->error_message = "User not found"; 
				return $result;
			}

		$r = $this->connection->exec("UPDATE users SET role = '".$role."', last_updated = '".date("Y-m-d H:i:s")."' WHERE username='".$u."';");
		if($r)
		{
			$result->success = true;
		}
		else
		{
			$result->error_message = "Cannot update password";
		}
	
	}
	else
	{
		$result->error_message = "Action restricted";
	}

	return $result;
}

//Gets data for one user from database
function get_user($name)
{
	$result = new db_result();

	//Sanitizing inputs;
	$name = addslashes(trim($name));


	if($this->connection_status)
	{
		$r = $this->connection->querySingle("SELECT * from users where username='".$this->connection->escapeString(trim($name))."'", true);
		if($r)
		{	
			$result->success = true;
			$result->response_type = "user";
			$result->response= new user($r['username'], $r['password'], $r['role'], $r['created'], $r['last_updated']);
			
		}
		else
		{
			$result->success = false;
			$result->error_message = "No result from database";
		}
	}
	else
	{
		$result->success = false;
		$result->error_message = "Connection error";
	}

	return $result;
}

//Gets the currently logged in user
function get_logged_in_user()
{	
	$result = new db_result();

	if($this->check_login_status())
	{
			$token = $_COOKIE[$this->cookie_name];
			$r = $this->connection->querySingle("SELECT * from auth_tokens JOIN users ON auth_tokens.username=users.username WHERE token='".$token."'  ;", true);
			if($r)
			{
				$result->success = true;
				$result->response_type='user';
				$result->response =  new user($r['username'], $r['password'], $r['role'], $r['created'], $r['last_updated']);
			}
	}

	return $result;
}


//Gets the list of all users
function get_all_users()
{	

	$result = new db_result();

	if($this->connection_status)
	{
		$r = $this->connection->query("SELECT * from users");
		if($r)
		{	
			$r_array = array();
			$result->success = true;
			$result->response_type = "user_array";

			while($a = $r->fetchArray())
			{	
				$u = new user($a['username'], $a['password'], $a['role'], $a['created'], $a['last_updated']);
				array_push($r_array,$u);
			}

			$result->response= $r_array;
		}
		else
		{
			$result->success = false;
			$result->error_message = "No result from database";
		}
	}
	else
	{
		$result->success = false;
		$result->error_message = "Connection error";
	}

	return $result;

}


function check_login_status()
{	
	if(isset($_COOKIE[$this->cookie_name]))
	{
		if($this->connection_status)
		{	$token = $_COOKIE[$this->cookie_name];
			$r = $this->connection->querySingle("SELECT * from auth_tokens WHERE token='".$token."';", true);
			if($r)
			{
				return true;
			}
		}
	}
	return false;
}

function check_if_admin()
{
	if(isset($_COOKIE[$this->cookie_name]))
	{	
		if($this->connection_status)
		{	$token = $_COOKIE[$this->cookie_name];
			$r = $this->connection->querySingle("SELECT * from auth_tokens JOIN users ON auth_tokens.username=users.username WHERE token='".$token."'  ;", true);
			if($r)
			{	
				if ($r['role']=='admin')
				{
					return true;
				}
			}
		}
	}
	return false;
}

function generate_token($username)
{
	$token = bin2hex(openssl_random_pseudo_bytes(32));
	if($this->connection_status)
	{
		$r = $this->connection->exec("INSERT INTO auth_tokens VALUES ('".$token."','".$username."','".date("Y-m-d H:i:s")."')");
		if($r)
		{
			setcookie('common', $token, time() + (86400*7), "/");
			return true;
		}
	}

	return false;
}

//This functions logs in the user if the given username and passoword is correct
function login($u, $p)
{	
	$result = new db_result();

	if($this->check_login_status()){$result->error_message="Already logged in"; return $result;}

	//Sanitizing inputs;
	$u = addslashes(trim($u));
	$p = addslashes(trim($p));

	$r = $this->get_user($u);
	
	if($r->success)
	{	if($r->response_type == 'user')
		{	
			if(password_verify($p, $r->response->get_password()))
				{
					
					if($this->generate_token($u))
					{
						$result->success = true;
					}
					else
					{
						$result->error_message = "Cannot generate token";
					}

				}
				else
				{
					$result->error_message="Incorrect password";
				}
		}
		else
		{
			$result->error_message="Incorrect username";
		}
	}
	else
	{
		$result->error_message="Incorrect username or password";
	}

	return $result;
}

function logout()
	{	
		$result = new db_result();

		if(isset($_COOKIE[$this->cookie_name]))
		{	
			if($this->connection_status)
			{	$token = $_COOKIE[$this->cookie_name];
				$r = $this->connection->exec("DELETE from auth_tokens WHERE token='".$token."';");
				json_encode($r);
				
				if($r)
				{	unset($_COOKIE[$this->cookie_name]);
    				setcookie('common', '', time() - 3600, '/');
					$result->success = true;
				}
			}
		}

		return $result;
	}

}