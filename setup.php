<?php

if(file_exists('users.db'))
{	
	echo "The app is already set up. Cannot use setup again. You should delete 'setup.php'";
}
else
{
	$db = new SQLite3("users.db");

	$create_tables_query =
'CREATE TABLE IF NOT EXISTS users
(id INTEGER PRIMARY KEY AUTOINCREMENT,
username varchar(255) NOT NULL,
password varchar(255) NOT NULL,
created datetime NOT NULL,
last_updated datetime NOT NULL,
role varchar(255) NOT NULL);
CREATE TABLE IF NOT EXISTS auth_tokens
(token varchar(255) NOT NULL PRIMARY KEY,
username varchar(255) NOT NULL,
created datetime NOT NULL
);
INSERT INTO users VALUES (NULL,"admin","'.password_hash("dbadmin", PASSWORD_DEFAULT).'","'.date("Y-m-d H:i:s").'","'.date("Y-m-d H:i:s").'","admin");';
	
	$result = $db->exec($create_tables_query);
	if($result)
	{
		echo "The app is setup. You should delete 'setup.php'.";
	}
	else
	{	
		echo "Error. Could not setup the app.";
		echo $db->lastErrorMsg();
	}
	
}