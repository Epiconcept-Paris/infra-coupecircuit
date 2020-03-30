<?php
#simulation, à mettre dans un script autre
apc_store('NB_SESSIONS_PHP', 210);
apc_store('COUPURE_CHARGE_SERVEUR', FALSE);
apc_store('LOAD_AVG', array(1, 1.2, 0.5));

#code proposé par l'infra
#si COUPURE_CHARGE_SERVEUR n'est pas défini, $bCoupureCharge vaudra FALSE
$iNbSessionsPHPMax = intval(getenv('NBMAX_SESSIONS_PHP')) ?: 300;
$maxLoadAvg5 = intval(getenv('MAX_LOAD_AVG_5')) ?: 8;
$maxLoadAvg10 = intval(getenv('MAX_LOAD_AVG_10')) ?: 8;

$bCoupureCharge = boolval(apc_fetch('COUPURE_CHARGE_SERVEUR'));
$aLoadAvg = apc_fetch('LOAD_AVG');
$iNbSessionsPHP = apc_fetch('NB_SESSIONS_PHP');
if($iNbSessionsPHP === FALSE) {
	$iNbSessionsPHP = 0;
	error_log('pas de donnée NB_SESSIONS_PHP disponible');
}

if($iNbSessionsPHP > $iNbSessionsPHPMax || $bCoupureCharge === TRUE || ($aLoadAvg[0] > $maxLoadAvg5 && $aLoadAvg[1] > $maxLoadAvg10)) {
	error_log(sprintf('connection_refused,ip:%s,SESSIONS:%d/%d,LOADAVG:%0.2f/%0.2f/%0.2f,COUPURE:%s', 
		$_SERVER['REMOTE_ADDR'], 
		$iNbSessionsPHP, $iNbSessionsPHPMax, 
		$aLoadAvg[0], $aLoadAvg[1], $aLoadAvg[2], 
		$bCoupureCharge ? 'true' : 'false'));
	echo "Vous êtes déjà très nombreux à utiliser cette application en ce moment...";
}
else {
	echo "chargement habituel";
}
