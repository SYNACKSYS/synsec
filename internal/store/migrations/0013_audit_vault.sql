-- De quel coffre parle une ligne du journal.
--
-- Jusqu'ici une entrée ne portait que le nom du secret. Ça suffit pour lire le
-- journal complet, où le contexte est là ; ça ne suffit pas pour répondre à
-- « qui a ouvert CE secret », parce que deux coffres ont parfaitement le droit
-- d'avoir chacun leur « mot_de_passe_mqtt ». Sans le coffre, la page d'un
-- secret montrerait les lectures de celui du voisin.
ALTER TABLE audit_log ADD COLUMN project_id TEXT NOT NULL DEFAULT '';

-- Les lignes déjà écrites sont rattachées quand le nom ne désigne qu'un seul
-- secret sur tout le serveur. Là où le nom est ambigu, on ne devine pas : une
-- ligne rattachée au mauvais coffre serait pire qu'une ligne sans coffre,
-- puisqu'elle s'afficherait avec assurance sur la page de quelqu'un d'autre.
UPDATE audit_log
   SET project_id = COALESCE((
           SELECT s.project_id FROM secrets s
            WHERE s.name = audit_log.target
            GROUP BY s.name
           HAVING COUNT(DISTINCT s.project_id) = 1
       ), '')
 WHERE target <> '' AND action LIKE 'secret.%';

-- La page d'un secret demande toujours les trois : le coffre, le nom, et
-- l'ordre chronologique.
CREATE INDEX idx_audit_target ON audit_log (project_id, target, at);
