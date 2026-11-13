-- Affaires du conseil syndical.
--
-- Ces lignes ne viennent pas de l'API Foncia : c'est la table de suivi que le
-- conseil tient en parallèle (anciennement un fichier Excel « Suivi désordre
-- Terranostra 2 »). Chaque ligne décrit un désordre, une action à mener ou une
-- décision à prendre, avec l'action demandée au syndic, un copropriétaire
-- responsable, un lien ou un devis, et deux colonnes d'observations (copro et
-- syndic). `statut` sépare les affaires en cours des affaires levées.
--
-- Les dates sont stockées en TEXT, pas en INTEGER : l'Excel contenait régulièrement
-- des valeurs textuelles (« 09/11/2026 (réunion) », « ~17/10/2026 ») qu'il ne faut
-- pas perdre. Un champ vide (chaîne vide) signifie « pas de date ».

CREATE TABLE affaires (
    id                TEXT PRIMARY KEY NOT NULL,                     -- UUID
    numero            INTEGER NOT NULL,                              -- Numéro affiché dans la table
    titre             TEXT NOT NULL,                                 -- « Mur à repeindre »
    localisation      TEXT NOT NULL,                                 -- « Extérieur jardin »
    action_foncia     TEXT NOT NULL,                                 -- Action demandée au syndic
    responsable       TEXT NOT NULL,                                 -- Copropriétaire en charge
    date_signalement  TEXT NOT NULL,                                 -- Vide ou libellé de date
    lien_devis        TEXT NOT NULL,                                 -- Référence devis ou URL
    obs_copro         TEXT NOT NULL,                                 -- Observation côté copro
    obs_syndic        TEXT NOT NULL,                                 -- Observation côté syndic
    date_levee        TEXT NOT NULL,                                 -- Vide si en cours
    statut            TEXT NOT NULL CHECK (statut IN ('en_cours', 'levee')),
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
) STRICT;

CREATE INDEX idx_affaires_statut ON affaires (statut);
CREATE INDEX idx_affaires_numero ON affaires (numero);

-- Une affaire peut recevoir plusieurs relances. Dans l'Excel il n'y en avait
-- que deux par ligne ; ici on en autorise autant qu'il en faut.
CREATE TABLE affaires_relances (
    id          TEXT PRIMARY KEY NOT NULL,
    affaire_id  TEXT NOT NULL REFERENCES affaires (id) ON DELETE CASCADE,
    date        TEXT NOT NULL,                                       -- Libellé de date
    note        TEXT NOT NULL                                        -- Précision facultative
) STRICT;

CREATE INDEX idx_affaires_relances_affaire_id ON affaires_relances (affaire_id);

-- Le fil de discussion d'une affaire. `auteur` est l'e-mail donné par le
-- reverse proxy (--auth-header), ou « inconnu » sans proxy.
CREATE TABLE affaires_commentaires (
    id          TEXT PRIMARY KEY NOT NULL,
    affaire_id  TEXT NOT NULL REFERENCES affaires (id) ON DELETE CASCADE,
    auteur      TEXT NOT NULL,
    texte       TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE INDEX idx_affaires_commentaires_affaire_id ON affaires_commentaires (affaire_id);

-- Tout ce qu'on rattache à une affaire. `kind` dit ce que `ref` désigne :
--
--   depense        expenses.id
--   document       account_documents.id
--   mission        missions.id
--   remboursement  remboursements.id
--   email, lien    rien (ref = ''), tout est dans titre / url / note
--
-- Pas de clé étrangère sur `ref` : il pointe vers quatre tables différentes, et
-- les lignes Foncia peuvent disparaître de l'API sans qu'on veuille perdre le
-- lien. `titre` garde donc une copie lisible du libellé au moment du lien.
CREATE TABLE affaires_liens (
    id          TEXT PRIMARY KEY NOT NULL,
    affaire_id  TEXT NOT NULL REFERENCES affaires (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('depense', 'document', 'mission', 'remboursement', 'email', 'lien')),
    ref         TEXT NOT NULL,
    titre       TEXT NOT NULL,
    url         TEXT NOT NULL,
    note        TEXT NOT NULL,
    auteur      TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE INDEX idx_affaires_liens_affaire_id ON affaires_liens (affaire_id);
CREATE INDEX idx_affaires_liens_ref ON affaires_liens (kind, ref);
-- La même facture ne se rattache qu'une fois à la même affaire.
CREATE UNIQUE INDEX idx_affaires_liens_unique ON affaires_liens (affaire_id, kind, ref) WHERE ref <> '';

-- L'identifiant d'une dépense est dérivé de son contenu et change le jour où
-- Foncia lui attache un PDF (voir promoteExpense dans db.go). Les liens suivent.
CREATE TRIGGER trg_expenses_id_changed AFTER UPDATE OF id ON expenses
BEGIN
    UPDATE OR IGNORE affaires_liens SET ref = NEW.id WHERE kind = 'depense' AND ref = OLD.id;
END;

-- Achats avancés par un copropriétaire pour la copropriété, à se faire
-- rembourser par le syndic (anciennement la feuille « Suivi Remboursements »).
CREATE TABLE remboursements (
    id                  TEXT PRIMARY KEY NOT NULL,
    objet               TEXT NOT NULL,
    vendeur             TEXT NOT NULL,
    montant             INTEGER NOT NULL,   -- Centimes.
    date_achat          TEXT NOT NULL,      -- AAAA-MM-JJ, ou '' si inconnue.
    demandeur           TEXT NOT NULL,      -- Qui a avancé l'argent.
    date_demande        TEXT NOT NULL,      -- Texte libre : « Email 23/07/2025 ».
    statut              TEXT NOT NULL CHECK (statut IN ('a_demander', 'demande', 'rembourse', 'abandonne')),
    date_remboursement  TEXT NOT NULL,      -- Texte libre.
    preuve              TEXT NOT NULL,      -- Ticket, lien vers le justificatif...
    detail              TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
) STRICT;

CREATE INDEX idx_remboursements_statut ON remboursements (statut);

-- Budget prévisionnel voté, pour le comparer au réalisé. `annee` est l'année
-- où commence l'exercice (1er juillet) : 2025 pour l'exercice 2025-2026.
CREATE TABLE budgets (
    annee       INTEGER PRIMARY KEY NOT NULL,
    montant     INTEGER NOT NULL,           -- Centimes.
    note        TEXT NOT NULL,
    updated_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;
