-- Les notifications du site (Web Push) : un appareil par ligne, abonné depuis
-- la page « Notifications » par la personne connectée.
--
-- `endpoint` est l'adresse que le navigateur a obtenue de son service de push
-- (Apple, Google, Mozilla) ; `p256dh` et `auth` sont les clés du navigateur,
-- avec lesquelles chaque message est chiffré pour lui seul.
--
-- `events` est un objet JSON « sorte de nouvelle → oui/non ». Une sorte
-- absente vaut oui, pour qu'une sorte ajoutée plus tard arrive à tout le monde.
--
-- Les clés VAPID du serveur sont dans `reglages` (`push_vapid`) : en changer
-- couperait tous les abonnements.
CREATE TABLE push_abonnements (
    endpoint    TEXT PRIMARY KEY NOT NULL,
    p256dh      TEXT NOT NULL,
    auth        TEXT NOT NULL,
    email       TEXT NOT NULL,                 -- en minuscules
    ua          TEXT NOT NULL,                 -- le User-Agent, pour nommer l'appareil
    events      TEXT NOT NULL,                 -- JSON, '{}' quand rien n'a été décoché
    created_at  TEXT NOT NULL
) STRICT;

CREATE INDEX idx_push_abonnements_email ON push_abonnements (email);
