# PatchGate — pré-mortem du 26 septembre 2026

**Scénario :** la soumission de demain échoue malgré un prototype qui tourne. Cette note identifie les causes observables et la prochaine action pour chacune. Ne cocher « fait » qu'après avoir vérifié l'artefact réel.

| Priorité | Cause d'échec | Signal vérifiable | Action | État |
| --- | --- | --- | --- | --- |
| P0 | Bob IDE n'a pas réellement contribué au projet | Aucun changement attribuable à une tâche Bob et `bob_sessions/` ne contient qu'un README | Ouvrir ce dépôt dans Bob IDE avec le compte du hackathon, faire implémenter et tester `BOB_TASK.md`, conserver les captures de chaque résumé de session pertinent | Bloqué par l'accès Bob du participant |
| P0 | Mauvaise instance IBM sélectionnée | Bob affiche le compte personnel plutôt que l'instance provisionnée du hackathon (le guide montre `ibm-coding-challenge-uat`, région `us-east`) | Vérifier l'instance dans Bob IDE avant de lancer la tâche ; l'invitation d'accès IBM ne prouve pas à elle seule que Bob IDE est sur le bon compte | À vérifier dans Bob |
| P0 | Aucune soumission accessible au jury | Le dépôt public existe, mais il manque les captures Bob, le lien vidéo et le formulaire final | Pousser les changements Bob et les vraies captures sur le dépôt dédié, tourner une courte démo et renseigner le formulaire avant 15:00 UTC le 27 septembre | Dépôt créé ; reste à faire après Bob |
| P1 | Démonstration trop générique | Le rapport ne montre que quatre expressions régulières et aucun lien entre changement et tests | Faire de l'analyse d'impact la tâche centrale dans Bob. Montrer sur `fixtures/impact.diff` une fonction liée à un test et une fonction sans lien, avec chemins et lignes vérifiables | Cas d'essai prêt ; implémentation Bob attendue |
| P1 | Une sortie donne une impression de sécurité injustifiée | Une alerte « Reviewed » paraît certifier un code sûr | Décrire `--check-decisions` comme un contrôle de revue uniquement ; garder les limites dans l'interface, le README et la présentation | Corrigé dans le texte ; à confirmer dans la vidéo |
| P1 | Le scan déclenche un outil externe configuré dans le dépôt analysé | Le dépôt contient un pilote Git `textconv` ou `external diff` | Utiliser `--no-textconv --no-ext-diff`, vérifier par test sur un dépôt temporaire configuré avec `textconv` | Corrigé et testé |
| P1 | Le code ou la preuve publiés exposent des données privées | Secret, document personnel ou capture de compte dans le dépôt | N'utiliser que les fixtures synthétiques ; examiner `git status`, les captures Bob et l'historique avant publication | Code local inspecté ; captures absentes |
| P1 | Le dépôt ou la vidéo sont préparés trop tard | Échec de téléversement juste avant 15:00 UTC | Viser une soumission terminée à 12:00 UTC le 27 septembre et conserver une marge pour le formulaire et la vidéo | Cible interne |

## Décision de passage à la soumission

Le paquet local et le dépôt public actuel sont des **prototypes préparatoires**. Ne les présenter comme une soumission conforme qu'après : (1) une tâche de développement exécutée dans le véritable Bob IDE du hackathon, (2) ses captures de résumé dans `bob_sessions/`, (3) le dépôt public mis à jour avec les changements réels, (4) une vidéo et (5) le formulaire lablab soumis. Les résultats de tests locaux prouvent des propriétés du prototype, pas l'usage de Bob ou une qualification au concours.

## Source opérationnelle

Guide officiel : https://lablab-ibm-bob-2-hackathon-guide.s3.us.cloud-object-storage.appdomain.cloud/index.html

Page de l'événement et fermeture : https://lablab.ai/ai-hackathons/ibm-bob-2-hackathon/live
