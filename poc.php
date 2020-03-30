<?php
#simulation, à mettre dans un script autre
apc_store('NB_SESSIONS_PHP', 210);
apc_store('COUPURE_CHARGE_SERVEUR', FALSE);

#code proposé par l'infra
$bCoupureCharge = apc_fetch('COUPURE_CHARGE_SERVEUR');
#si COUPURE_CHARGE_SERVEUR n'est pas défini, $bCoupureCharge vaudra FALSE

$iNbSessionsPHPMax = = intval(getenv('NBMAX_SESSIONS_PHP')) ?: 100;
$loadAvgTTL = intval(getenv('LOAD_AVG_TTL')) ?: 1;
$maxLoadAvg = intval(getenv('MAX_LOAD_AVG')) ?: 6;

$aLoadAvg = apc_fetch('LOAD_AVG');

if($iNbSessionsPHP > $iNbSessionsPHPMax || $bCoupureCharge === TRUE || ($aLoadAvg[0] > $maxLoadAvg && $aLoadAvg[1] > $maxLoadAvg)) {
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
