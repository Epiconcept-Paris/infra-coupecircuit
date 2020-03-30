# CoupeCircuit

## But

* donner l'information aux logiciels sur différents éléments de la charge serveur pour qu'ils commencent à refuser les nouvelles connexions, ou coupent des processus consommateurs
* ne pas faire tomber le frontal ou la bdd, préférer une dégradation gracieuse des fonctionnalités

## Périmètre

* le traitement de la charge est dans les logiciels, ou le framework Voozanoo. Le module ici doit mettre l'information à disposition
* informations nécessaires
  * nombre de sessions actives (entier) : LOAD_AVG
  * load average (pour ne pas le requêter à chaque appel HTTP)
  * blocage manuel activé (drapeau 0 ou 1) : COUPURE_CHARGE_SERVEUR
* éléments techniques
  * idéalement un daemon (pour éviter la cron récurrente)
  * les seuils utilisés par le code applicatif seront fournis comme variable d'environnement Apache (responsabilité team infra)
  * les informations sont à placer dans le cache APC (potentiellement via un appel webservice sur un site accessible uniquement en local à développer)
  * la définition d'une session active doit pouvoir varier dans le temps, mais globalement
    * fichier dans 
