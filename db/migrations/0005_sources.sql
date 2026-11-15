-- Ce qui alimente les affaires sans qu'on le recopie à la main : les fichiers
-- (devis, factures, photos) gardés sur le disque, les messages reçus (e-mails,
-- WhatsApp) et les nouveautés Foncia, et les propositions que Claude en tire.

-- Un fichier, par son contenu : deux envois du même PDF n'en font qu'un. Il
-- est rangé sous --files-dir/<2 premiers caractères>/<sha256>.
CREATE TABLE fichiers (
    sha256      TEXT PRIMARY KEY NOT NULL,
    nom         TEXT NOT NULL,                                   -- Le nom sous lequel il est arrivé la première fois
    mime        TEXT NOT NULL,
    taille      INTEGER NOT NULL,
    origine     TEXT NOT NULL CHECK (origine IN ('envoi', 'gmail', 'whatsapp')),
    auteur      TEXT NOT NULL,                                   -- E-mail de qui l'a envoyé, ou l'expéditeur du message
    created_at  TEXT NOT NULL
) STRICT;

-- Un message ou un évènement à classer dans une affaire.
--
--   gmail     ext_id = id du message Gmail, fil = id du fil (thread)
--   whatsapp  ext_id = id du message, fil = JID de la conversation
--   foncia    ext_id = 'mission:<id>' ou 'depense:<id>', ref = la même chose
--
-- `etat` : a_trier tant que personne ne l'a rattachée ni écartée. Les sources à
-- trier ne sont montrées qu'aux administrateurs (--admin-users) ; une fois
-- rattachée à une affaire, une source se lit dans le dossier de l'affaire.
CREATE TABLE sources (
    id             TEXT PRIMARY KEY NOT NULL,
    canal          TEXT NOT NULL CHECK (canal IN ('gmail', 'whatsapp', 'foncia')),
    ext_id         TEXT NOT NULL,
    fil            TEXT NOT NULL,
    fil_titre      TEXT NOT NULL,                                -- Nom de la conversation WhatsApp
    auteur         TEXT NOT NULL,                                -- « Nom <adresse> » ou nom WhatsApp
    destinataires  TEXT NOT NULL,
    sujet          TEXT NOT NULL,
    texte          TEXT NOT NULL,
    date           TEXT NOT NULL,                                -- Quand le message a été envoyé
    url            TEXT NOT NULL,                                -- Où le lire à l'origine (Gmail…), ou ''
    ref            TEXT NOT NULL,                                -- Pour Foncia : 'mission:<id>' / 'depense:<id>'
    etat           TEXT NOT NULL CHECK (etat IN ('a_trier', 'classee', 'ignoree')),
    traite_par     TEXT NOT NULL,                                -- E-mail, 'auto:fil' ou 'claude', '' si à trier
    traite_le      TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (canal, ext_id)
) STRICT;

CREATE INDEX idx_sources_etat_date ON sources (etat, date);
CREATE INDEX idx_sources_fil ON sources (canal, fil);

-- Les pièces jointes d'une source.
CREATE TABLE sources_fichiers (
    source_id  TEXT NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    sha256     TEXT NOT NULL REFERENCES fichiers (sha256),
    nom        TEXT NOT NULL,
    PRIMARY KEY (source_id, sha256)
) STRICT;

CREATE INDEX idx_sources_fichiers_sha256 ON sources_fichiers (sha256);

-- Ce que Claude propose de faire d'une ou plusieurs sources. Rien n'est
-- appliqué tant qu'un administrateur n'a pas accepté.
--
--   rattacher      affaire_id + source_ids
--   creer_affaire  donnees = {titre, localisation, action_foncia, responsable, date_signalement}
--   commenter      affaire_id + donnees = {texte}
--   relancer       affaire_id + donnees = {date, note}
--   lever          affaire_id
--   ignorer        source_ids
--
-- Pas de clé étrangère sur affaire_id : une affaire supprimée ne doit pas
-- effacer l'historique de ce qui a été proposé.
CREATE TABLE propositions (
    id             TEXT PRIMARY KEY NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('rattacher', 'creer_affaire', 'commenter', 'relancer', 'lever', 'ignorer')),
    affaire_id     TEXT NOT NULL,
    source_ids     TEXT NOT NULL,                                -- Tableau JSON
    donnees        TEXT NOT NULL,                                -- Objet JSON
    justification  TEXT NOT NULL,
    citation       TEXT NOT NULL,                                -- Le passage de la source qui la justifie
    etat           TEXT NOT NULL CHECK (etat IN ('en_attente', 'acceptee', 'refusee')),
    auteur         TEXT NOT NULL,                                -- 'claude'
    decide_par     TEXT NOT NULL,
    decide_le      TEXT NOT NULL,
    resultat       TEXT NOT NULL,                                -- Ce que l'acceptation a fait, ou pourquoi elle a échoué
    created_at     TEXT NOT NULL
) STRICT;

CREATE INDEX idx_propositions_etat ON propositions (etat, created_at);

-- Petits états persistants : la clé des liens de partage, les curseurs des
-- collectes.
CREATE TABLE reglages (
    cle     TEXT PRIMARY KEY NOT NULL,
    valeur  TEXT NOT NULL
) STRICT;

-- affaires_liens accepte deux nouvelles sortes de pièces :
--
--   fichier  ref = fichiers.sha256
--   source   ref = sources.id
--
-- SQLite ne sait pas modifier une contrainte CHECK : la table est reconstruite.
-- Le trigger sur expenses la nomme, il est donc retiré avant et remis après.
DROP TRIGGER trg_expenses_id_changed;

CREATE TABLE affaires_liens_new (
    id          TEXT PRIMARY KEY NOT NULL,
    affaire_id  TEXT NOT NULL REFERENCES affaires (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('depense', 'document', 'mission', 'remboursement', 'email', 'lien', 'fichier', 'source')),
    ref         TEXT NOT NULL,
    titre       TEXT NOT NULL,
    url         TEXT NOT NULL,
    note        TEXT NOT NULL,
    auteur      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

INSERT INTO affaires_liens_new (id, affaire_id, kind, ref, titre, url, note, auteur, created_at)
SELECT id, affaire_id, kind, ref, titre, url, note, auteur, created_at FROM affaires_liens;

DROP TABLE affaires_liens;
ALTER TABLE affaires_liens_new RENAME TO affaires_liens;

CREATE INDEX idx_affaires_liens_affaire_id ON affaires_liens (affaire_id);
CREATE INDEX idx_affaires_liens_ref ON affaires_liens (kind, ref);
CREATE UNIQUE INDEX idx_affaires_liens_unique ON affaires_liens (affaire_id, kind, ref) WHERE ref <> '';

CREATE TRIGGER trg_expenses_id_changed AFTER UPDATE OF id ON expenses
BEGIN
    UPDATE OR IGNORE affaires_liens SET ref = NEW.id WHERE kind = 'depense' AND ref = OLD.id;
END;
