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
  * avoir un script en CLI qui permet de fixer le ou les seuils aisément, et de (dé)bloquer manuellement au besoin (si le problème est vraiment grave on passera sur vhost maintenance pour tout bloquer)
  * et donc un script qui tourne assez souvent pour mettre à jour les informations nécessaires. Il y a des sessions vides (fichier à 0 octets), et même un appel HTTP non connecté (visiteur, robot indexeur) créé une session. Ces sessions "vides" doivent être ignorées.
* exemple, quelques sessions réelles de profnt2
  * une qui mentionne un compte, donc à priori une personne connectée
    `Default|a:1:{s:11:"initialized";b:1;}__ZF|a:1:{s:36:"vzn_a15774ed86e9f3eaebc925162120cec2";a:1:{s:3:"ENT";i:1585155117;}}vzn_xxxxxxxxxxxxxxx|a:1:{s:7:"storage";s:9:"compte_reel";}`
  * Une qui ne le mentionne pas, donc je ne sais pas
    `Default|a:1:{s:11:"initialized";b:1;}__ZF|a:1:{s:36:"vzn_xxxxxxxxxxxxxxx";a:1:{s:3:"ENT";i:1585145718;}}`
  * Une qui ne mentionne rien, donc presque certain que c'est qq de non connecté
    `Default|a:1:{s:11:"initialized";b:1;}`
 
