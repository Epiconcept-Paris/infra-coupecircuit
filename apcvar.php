<?php

$vars = [
    [ 'name' => 'LOAD_AVG',			'ttl' => 43200 ],
    [ 'name' => 'NB_SESSIONS_PHP',		'ttl' => 43200 ],
    [ 'name' => 'COUPURE_CHARGE_SERVEUR',	'ttl' => 43200 ],
]; 

$nbv = count($vars);
foreach ($_GET as $key => $val)
{
    for ($i = 0; $i < $nbv; $i++)
    {
	if ($key == $vars[$i]['name'])
	    break;
    }
    if ($i < $nbv)
    {
	if (empty($val))	// get
	{
	    $apc = false;
	    if (function_exists('apc_fetch'))
		$apc = apc_fetch($key);
	    elseif (function_exists('apcu_fetch'))
		$apc = apcu_fetch($key);
	    if ($apc !== false)
		echo "$key=$apc\n";
	}
	else			// set
	{
	    if (function_exists('apc_store'))
		apc_store($key, $val, $vars[$i]['ttl']);
	    elseif (function_exists('apcu_store'))
		apcu_store($key, $val, $vars[$i]['ttl']);
	}
    }
}
