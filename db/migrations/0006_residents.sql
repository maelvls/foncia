-- Les personnes de la résidence et leur téléphone : qui habite où, qui est
-- propriétaire sans y habiter, qui est parti.
--
-- Ces lignes ne viennent pas de Foncia (qui ne donne que les copropriétaires et
-- leur adresse postale, voir /coowners) : elles viennent des contacts du
-- téléphone d'un membre du conseil, dont le nom porte l'appartement entre
-- parenthèses, « Camille MARTIN (C01) », et de ce qui est saisi sur le site.
--
-- `qualite` dit le lien avec l'appartement :
--
--   resident      y habite (propriétaire occupant ou locataire)
--   proprietaire  en est propriétaire sans y habiter
--   ancien        n'y est plus (ancien locataire, vendeur)
--   autre         tout le reste, précisé par `detail`
--
-- `telephone` et `email` peuvent en contenir plusieurs, séparés par une virgule.
--
-- `origine` dit qui tient la ligne à jour : 'contacts' pour celles qu'un import
-- des contacts a créées ou reconnues (le prochain import les met à jour),
-- 'site' pour celles saisies à la main. `note` n'appartient qu'au site : un
-- import n'y touche jamais.
CREATE TABLE residents (
    id           TEXT PRIMARY KEY NOT NULL,
    appartement  TEXT NOT NULL,                 -- « C01 »
    nom          TEXT NOT NULL,
    qualite      TEXT NOT NULL CHECK (qualite IN ('resident', 'proprietaire', 'ancien', 'autre')),
    detail       TEXT NOT NULL,                 -- « compagnon », « ancien locataire », « vendeur »...
    telephone    TEXT NOT NULL,                 -- « 06 12 34 56 78 », ou '' si inconnu.
    email        TEXT NOT NULL,
    note         TEXT NOT NULL,
    origine      TEXT NOT NULL CHECK (origine IN ('contacts', 'site')),
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE INDEX idx_residents_appartement ON residents (appartement);
