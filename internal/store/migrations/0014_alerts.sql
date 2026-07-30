-- Les adresses déjà vues, pour savoir dire « celle-là est nouvelle ».
--
-- Une alerte sur une adresse inhabituelle n'a de sens que si le serveur sait
-- ce qui est habituel. Il l'apprend en regardant passer le journal : la
-- première adresse d'un compte ou d'un appareil est notée sans rien dire,
-- celles d'après sont des nouveautés. Personne n'a de liste à tenir à jour.
--
-- Ce n'est pas une règle d'accès : rien ici n'autorise ni ne refuse quoi que
-- ce soit. C'est une mémoire, et elle sert uniquement à décider s'il y a
-- matière à prévenir.
CREATE TABLE seen_addresses (
    actor_kind TEXT NOT NULL,
    actor_id   TEXT NOT NULL,
    ip         TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (actor_kind, actor_id, ip)
);

-- « Cet acteur a-t-il déjà une adresse connue ? » est la question posée à
-- chaque ligne du journal ; elle doit rester une lecture d'index.
CREATE INDEX idx_seen_actor ON seen_addresses (actor_kind, actor_id);
