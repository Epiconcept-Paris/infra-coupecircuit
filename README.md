# CoupeCircuit

## Architecture

Le *script shell à la indird* envisagé à la dernière section **Périmètre** ci-dessous a finalement laissé place à un compteur de sessions en C, auquel il a été adjoint un `daemon` de gestion pour relancer au besoin le compteur et/ou le script-shell de rapport, assurer leur bon dialogue, centraliser les logs, etc.

On aboutit ainsi à l'architecture suivante :
```
	compteur ---> script-shell de rapport ---> page PHP servie par Apache

	\_______ daemon de gestion _________/
```

## Installation

Les éléments à installer sur un serveur sont les suivants:
- le binaire du `daemon` : `nbphpsessd`
- le binaire du compteur : `nbphpsess`
- le script-shell de rapport : `nbphpsess.sh`
- le fichier de configuration : `nbphpsess.conf`
- la page PHP de lecture / écriture du cache APC : `nbphpsess.php`

Les binaires et le script-shell peuvent être installés dans un répertoire spécifique, par exemple `/usr/local/lib/nbphpsess`, le fichier de configuration pouvant être installé par exemple dans `/etc/epiconcept`.
Le fichier PHP doit bien sur être installé à l'endroit approprié dans un DocumentRoot du serveur Apache.

## Lancement et utilisation

Bien que le compteur ou le script-shell de rapport puissent chacun être utilisés directement en ligne de commande pour les tests (en détectant spécifiquement un fonctionnement interactif), la manière habituelle de lancer la chaine de comptage des sessions PHP est de lancer le `daemon` :
```
/usr/local/lib/nbphpsessd
```
Cette commande peut-être suffisante si les valeurs par défaut du `daemon` conviennent, sinon voir l'explication détaillée ci-dessous.

### Fonctionnement du `daemon`

Par défaut, ce dernier va :
- chercher son fichier de configuration dans:
  * l'option -f de la ligne de commande (voir ci-dessous)
  * la variable `NBPHPSESS_CONF`
  * le répertoire ou se trouve son propre binaire (`nbphpsessd`)
  * le répertoire de configuration compilé par défaut `/etc/epiconcept`
- charger son fichier de configuration où il trouvera les paramètres `log_dir` et `run_dir` et sinon utilisera pour ces derniers des valeurs compilées par défaut.
- créer/ouvrir un fichier de log comme :
  * indiqué dans l'option -l de la ligne de commande
  * indiqué par `log_dir` avec comme nom `nbphpsess.log`
- créer/ouvrir un fichier optionnel séparé, spécifique pour la sortie standard `stdout` du script-shell de rapport, permettant par exemple de garder un historique de la charge en sessions PHP actives.
  Ce fichier est géré s'il est indiqué dans la ligne de commande par l'option -r, sinon la sortie standar du script de rapport sera centralisée dans le fichier de log avec le préfixe `nbphpsess.sh report`
- créer un fichier `nbphpsessd.pid` dans le répertoire `run_dir`
- lancer les processus compteur et script-shell de rapport tels qu'indiqués par la ligne de commmande ou par défaut `nbphpsess` et `nbphpsess.sh`
- surveiller ces processus et centraliser leurs logs, les relancer au besoin selon les paramètres `child_...` du fichier de configuration
- gérer un signal de rechargement de la configuration et le propager à réception vers le compteur et le script-shell de rapport
- gérer un signal de réouverture des logs après leur `rotation` par le système. Comme le compteur et le script-shell n'ont pas leur log propre, il est inutile de leur propager ce signal.

### Ligne de commande du `daemon`

Sa **forme générique** est :
```
nbphpsessd [options] [compteur [script-shell]]
```
Exemples :
```
nbphpsessd
```
lance le `daemon` avec les exécutables `nbphpsess` et `nbphpsess.sh` comme compteur et script-shell de rapport respectivement

```
nbphpsessd test/npsdtest
```
lance le `daemon` avec les exécutables `test/npsdtest` et `test/npsdtest.sh` comme compteur et script-shell de rapport respectivement

```
nbphpsessd test/npsdtest nbphpsess.sh
```
lance le `daemon` avec les exécutables `test/npsdtest` et `nbphpsess.sh` comme compteur et script-shell de rapport respectivement

Si le nom des éxécutables n'est pas indiqué :
- celui du compteur sera par défaut `nbphpsess`
- celui du script-shell sera par défaut celui du compteur suivi de `.sh`


Si le chemin absolu des exécutables n'est pas indiqué, le `daemon` essaiera de les lancer avec le chemin relatif précédé de :
- le répertoire du binaire du `daemon`
- le répertoire configuré comme `bin_dir` dans le fichier de configuration

Enfin, il faut noter que le binaire du `daemon` ne fige pas la chaine `nbphpsess` et cherche juste si elle se termine par un 'd'. Si donc on renomme le binaire du `daemon` `epicspd` (par exemple pour EPIconcept Compteur de Sessions Php), il cherchera par défaut les binaires `epicsp` et `epicsp.sh`, le fichier de configuration `epicsp.conf` et la variable d'environnement `EPICSP_CONF`

**Options de lancement**

Elle sont les suivantes:
- `-f <fichier de configuration>` permet de spécifier le fichier de configuration (comme mentionné ci-dessus).
  Si le nom par défaut `nbphpsess.conf` ne convient pas, c'est le moyen d'en spécifier un autre
- `-l <fichier de log` permet de spécifier le nom du fichier de log
- `-r <fichier de rapport` permet de spécicier le nom du fichier de rapport où comme mentionné ci-dessus sera écrite la sortie standard `stdout` du script-shell, qui sinon sera centralisée dans le fichier de log
- `-t <masque de trace>` permet d'indiquer au lancement, sous forme d'un nombre entier décimal, un masque de traces optionnelles qui apparaitront dans le fichier de log.
  Ce masque peut être également indiqué dans la configuration par le paramètre `trace_level` (voir ci-dessous)

Les options suivantes sont également reconnues, mais sans lancer le `daemon` :
- `-k` permet d'envoyer un signal SIGTERM au processus indiqué dans le fichier `nbphpsessd.pid`.
  L'envoi du signal est vérifié et le fichier `nbphpsessd.pid` est supprimé, qu'un `daemon` soit en cours d'exécution ou non, sauf dans le seul cas ou l'envoi (`kill`) indique que l`utilisateur de l'option `-k` n'a pas le droit d'envoi de signal sur le `daemon` existant
- `-c` permet de lister les paramètres reconnus du fichier de configuration et leurs valeurs par défaut
- `-h` affiche un court résumé des explications ci-dessus

## Fichier de configuration

Il est commun au trois programmes `daemon`, compteur et script-shell.  
Il se compose de définition simples `<param> = <valeur>`.
La seule contrainte est que les espaces ne sont acceptés ni dans `<param>` (ce qui est courant), **ni dans `<valeur>`**, ce qui pourrait être un obstacle pour la valeur future à donner à certains paramètres, un mécanisme de `quoting` n'étant pas géré.

La plupart des paramètres sont spécifiques à chaque programme, mais quelques-uns sont communs (comme indiqué).
Le fichier de configuration standard fourni indique en commentaire chaque paramètre, sa valeur par défaut et un commentaire résumant brièvement les explications ci-dessous.

### Paramètres du `daemon`

- `trace_level` (par défaut : 0)  
  Le masque de messages de traces optionnelles pour le `daemon` et le compteur
- `bin_dir` (par défaut : `/usr/local/lib/nbphpsess`)  
  Le répertoire dans lequel le `daemon` va chercher en dernier lieu les exécutables du compteur et du script-shell
- `log_dir` (par défaut : `/var/log/nbphpsess`)  
  Le répertoire dans lequel le `daemon` essaiera en dernier lieu d'écrire ses logs
- `run_dir` (par défaut : `/run/nbphpsess`)  
  Le répertoire dans lequel le `daemon` essaiera d'écrire le fichier contenant son PID
- `work_dir` (par défaut : `/usr/local/lib/nbphpsess`)  
  Le répertoire que le `daemon` utilisera comme son répertoire courant (pour ne pas gêner un `umount` par exemple).
- `log_wait` (par défaut : 5)  
  Le délai d'attente en secondes du `daemon` dans la centralisation des logs avant de vérifier si les processus compteur et script-de-rapport sont toujours actifs
- `child_linger` (par défaut : 10)  
  Le délai d'attente en secondes de la fin d'un processus (compteur ou script-de-rapport) après lui avoir envoyé un kill standard (SIGTERM, en général après la fin imprévue de l'autre processus).
  Passé ce délai, le `daemon` envoie un SIGKILL au processus, qui est supposé bloqué
- `child_delay` (par défaut : 10)  
  Le délai d'attente en secondes lors de la fin imprévue d'un processus avant son deuxième redémarrage, pour éviter une charge indue du système avec un défaut d'exécution (par exemple, une erreur de syntaxe dans le script-shell).
  Après s'être exécuté pendant une durée au moins double de ce temps, le processus lancé est considéré comme stable et pourra redémarrer immédiatement après un arrêt imprévu.
- `child_retries` (par défaut : 10)  
  Le nombre de fois qu'un processus s'arrêtant de manière imprévue sera relancé.
  Au bout de la moitié de ce nombre de fois, le délai ci-dessus est doublé.
- `syslog_facility` (par défaut : `LOCAL0`)  
  Paramétrage de l'accès au log système lorsqu'il n'est pas possible d'écrire dans le log du `daemon`.
  Les valeurs reconnues sont : `DAEMON`, `LOCAL0` à `LOCAL7` et `USER`
- `syslog_level` (par défaut : `ERR`)  
  Paramétrage de l'accès au log système lorsqu'il n'est pas possible d'écrire dans le log du `daemon`.
  Les valeurs reconnues sont : `ALERT`,`CRIT`,`ERR` ou `ERROR`,`WARN` ou `WARNING`, `NOTICE`, `INFO` et `DEBUG`
- `conf_reload_sig` (par défaut : `USR1`)  
  Le signal qui provoquera un rechargement de la configuration du `daemon`.
  Ce signal est transmis au compteur et au script-shell pour qu'il fassent de même.
- `log_rotate_sig` (par défaut : `USR2`)  
  Le signal qui provoquera la réouverture des logs du `daemon` après leur rotation.
  Ce signal n'est pas transmis puisque le `daemon` centralise les logs.
  

### Paramètres du compteur
- `sess_dir (par défaut : `/var/lib/php/sessions`)  
  Le chemin (en général absolu) du répertoire dont la surveillance est l'objet de ce projet
- `max_sess_size` (par défaut : 16384)  
  Nombre maximum de sessions **actives**.
  Le nombre total de fichiers sessions peut être supérieur encore.
  Est considérée comme une session active un fichier dont les noms, taille, age et contenu se conforment aux quatre paramètres suivants
- `sess_prefix` (par défaut : `sess_`)  
  Tout fichier dont le nom ne commence pas comme ce préfixe est ignoré
- `sess_minsize` (par défaut : 64)  
  Tout fichier dont la taille est inférieure à ce minimum est ignoré
- `sess_maxage` (par défaut : 1800)  
  Tout fichier dont la date de modification est plus ancienne que ce délai en secondes est ignoré
- `active_string` (par défaut : `s:15:"iConnectionType";`)  
  Tout fichier ne contenant pas cette chaine (caractéristique des applications Voozanoo actives) est ignoré
- `report_freq` (par défaut : 5)  
  Nombre de secondes entre deux envois du nombre de sessions au script-shell de rapport, qui les communiquera à Apache. C'est donc à proprement parler une période.

Pour rappel, les paramètres suivants, déjà expliqués, sont également reconnus par le compteur :  
- `trace_level`
  Le masque de traces; pour les valeurs du masque, utiliser `nbphpsess -c` et `nbphpsessd -c`
- `conf_reload_sig`
  Le signal de rechargement de configuration
  

### Paramètres du script-shell
- `report_curl (par défaut : y)  
  Active le rapport par `curl` vers `nbphpsess.php` (via Apache)
- `report_url (par défaut : 'https://`hostname`.voozanoo.net/localapc')  
  L'URL pour accéder à la page nbsessphp.php
- `ldavg_method (par défaut : php)  
  Si 'php', la charge moyenne (`load average`) du système est lue depuis PHP  
  Si 'sh', elle est lue par la commande `uptime` dans le script-shell
- `curl_timeout (par défaut : 20)  
  Paramètre pour l'option `-m / --max-time` de curl (timeout)
- `report_file (par défaut : '')  
  Si défini indique le chemin d'un fichier ou sera écrit le nombre de sessions
  
Et pour rappel, ce paramètre également utilisé par le `daemon` et le compteur
- `conf_reload_sig (par défaut : USR1)  
  Pour le rechargement de configuration
- `report_freq (par défaut : 5)  
  Pour vérifier faut s'il jeter des valeurs de nombres de session du fait du retard pris par curl.


## Implémentation

### Le compteur de sessions
L'idée d'utiliser des services système de `systemd`, comme pour `indid` a été rapidement abandonnée, car les événements fournis par l'unité de configuration `path` de `systemd` ne correspondaient pas à la tâche à effectuer, c'est à dire non seulement déclencher une action à l'apparition d'une session dans le répertoire de sessions PHP, mais en déclencher aussi à chaque modification de tout fichier session.  
Une implémentation en C a donc été décidée, permettant de choisir les événements `inotify` (le système d'événements de système de fichiers sur Linux) à utiliser.  
Initialement, il avait été prévu des problèmes de saturation des ressources système (`watch` de ìnotify`), mais il s'est avéré au cours des premiers tests que le simple watch du répertoire des sessions PHP détectait toute modification de session, et donc que le problème de saturation n'existait pas, le compteur n'ayant besoin que de très peu de ressources (1 `descripteur de fichier` + 1 'watch` de `inotify`).  
Le compteur est constitué du programme C mono-fichier `nbphpsess.c`, compilé en un binaire exécutable `nbphpsess`.

### Le `daemon` de supervision
L'expérience du développement et de l'administration système montrant que dès qu'un programme comme le compteur fonctionne, il faut prévoir son arrêt inattendu, que ce soit du fait de l'environnement du serveur ou d'erreurs de programmation dans le code du compteur lui-même.  
Un programme de supervision (`daemon`), qui se limite à cette seule tâche, est donc nécessaire pour redémarrer au besoin le compteur et son script-shell associé.  
Le `daemon` charge sa configuration, lance les deux composants compteur-de-session et script-shell-de-rapport, centralise leurs logs, surveille s'ils s'arrêtent et les relance, propage le signal choisi dans la configuration (voir ci-dessous) pour son rechargement dynamique (utilisé par les trois parties `daemon`, compteur et script) et gère la rotation des logs qu'il centralise.  
Le `daemon` est constitué du programme C mono-fichier `nbphpsessd.c`, compilé en un binaire exécutable `nbphpsessd`.

### Le script-shell de rapport (dialogue avec Apache et Voozanoo)
Sa tâche consiste à lire en permanence le nombre de sessions PHP actives que lui envoie périodiquement le compteur de session, et à rendre visible le résultat dans l'environnement PHP de Apache, soit en écrivant cette valeur dans le cache APC, soit simplement dans un fichier, d'où il pourra être lu par les applications Epiconcept.

### La page PHP de lecture / écriture du cache APC
Elle ne se compose comme le shell-script que de quelques dizaines de lignes qui contrôlent les arguments envoyés, et selon la présence ou non de valeur à chaque argument, écrit ou lit dans le cache APC.

---
---
# Spécification initiale

En *italiques*, les éléments *à réaliser*.

## But

* *donner l'information aux logiciels sur différents éléments de la charge serveur pour qu'ils commencent à refuser les nouvelles connexions, ou coupent des processus consommateurs*
* ne pas faire tomber le frontal ou la bdd, préférer une dégradation gracieuse des fonctionnalités

## Périmètre

* le traitement de la charge est dans les logiciels, ou le framework Voozanoo. Le module ici doit mettre l'information à disposition
* informations à fournir
  > *nombre de sessions actives [logées] (entier) NB_SESSIONS_PHP (info principale, reprendre le principe de indird)*
  > *load average (pour ne pas le requêter à chaque appel HTTP) de top / htop : LOAD_AVG (tableau 3 valeurs à 5, 10 et 15 min)*
  * blocage manuel activé (drapeau 0 ou 1) : COUPURE_CHARGE_SERVEUR : permettre de le setter par l'interface php
* livrable :
  > *script php d'injection APC (filtrant les variables) GET OK*
  > *script shell get/set des valeurs par http*
  > *script shell à la indird (une solution en C a finalement été choisie pour des raisons de performances sur une machine chargée)*
* éléments techniques
  * les seuils utilisés par le code applicatif seront fournis comme variable d'environnement Apache (responsabilité team infra)
  * A noter qu'APC n'étant pas accessible en CLI, il faudra forcément appeler un script PHP via HTTP, ne serait-ce que pour faire le apc_store() (par contre les sessions ne sont lisibles que par root, donc le calcul devra se faire en CLI)
  * le dossier : 
    ```
    cedric@profntphp7a1:/var/lib/php/sessions$ ls -lhad /var/lib/php/sessions
    drwx-wx-wt 2 root root 68K Mar 25 14:08 /var/lib/php/sessions
    ```
* Pour le process de mise à jour des informations, on peut penser
  * un cron toutes les mn (bof)
  * un surveillant inotify sur /var/lib/php/sessions (mais il va se déclencher souvent)
  * démon qui tourne en tâche de fond (compatible avec le inotify)
* Sur le comment de l'analyse des sessions
  * prendre la liste des fichiers dans /var/lib/php/sessions dont la date de modification est inférieure à N minutes, et qui contiennent une vraie session
  * déterminer, soit par la taille soit par le contenu si on a là une vraie session ouverte, ou juste qq qui a accédé à la page de login
  * avoir une page apache accessible uniquement en local qui permet de fixer les valeurs dans APC
  * et donc un script qui tourne assez souvent pour mettre à jour les informations nécessaires. Il y a des sessions vides (fichier à 0 octets), et même un appel HTTP non connecté (visiteur, robot indexeur) créé une session. Ces sessions "vides" doivent être ignorées.
* exemple, quelques sessions réelles de profnt2 vzn4
  * une qui mentionne un compte, donc à priori une personne connectée
    `Default|a:1:{s:11:"initialized";b:1;}__ZF|a:1:{s:36:"vzn_a15774ed86e9f3eaebc925162120cec2";a:1:{s:3:"ENT";i:1585155117;}}vzn_xxxxxxxxxxxxxxx|a:1:{s:7:"storage";s:9:"compte_reel";}`
  * Une qui ne le mentionne pas, donc je ne sais pas
    `Default|a:1:{s:11:"initialized";b:1;}__ZF|a:1:{s:36:"vzn_xxxxxxxxxxxxxxx";a:1:{s:3:"ENT";i:1585145718;}}`
  * Une qui ne mentionne rien, donc presque certain que c'est qq de non connecté
    `Default|a:1:{s:11:"initialized";b:1;}`
 
