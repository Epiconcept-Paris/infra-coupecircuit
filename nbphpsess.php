<?php

$vars = [
    [ 'name' => 'LOAD_AVG',			'ttl' => 43200 ],
    [ 'name' => 'NB_SESSIONS_PHP',		'ttl' => 43200 ],
    [ 'name' => 'COUPURE_CHARGE_SERVEUR',	'ttl' => 43200 ],
]; 

$nbv = count($vars);
$out = array();
$fmt = '';
foreach ($_GET as $key => $val)
{
    if ($key == 'fmt' && $val == 'json')
	$fmt = 'json';
}
foreach ($_GET as $key => $val)
{
    if ($key == 'fmt')
	continue;
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
		$out[$key] = preg_replace('/\D/', '', $apc) == $apc ? intval($apc) : $apc;
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
if ($fmt == 'json')
{
    echo json_encode($out)."\n";
}
else
{
    foreach ($out as $key => $val)
	echo "$key=$val\n";
}
