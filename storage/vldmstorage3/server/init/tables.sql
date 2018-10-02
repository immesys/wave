-- 
-- CREATE TABLE IF NOT EXISTS CertifiedRoots(
--   TreeId                  BIGINT NOT NULL,
--   Identity                VARCHAR(60) NOT NULL,
--   Revision                BIGINT NOT NULL,
--   DBSMR                   LONGBLOB,
--   PRIMARY KEY(TreeId, Identity, Revision),
--   FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
-- );

CREATE TABLE IF NOT EXISTS ValueMapping(
  Hash                  VARCHAR(60) NOT NULL,
  Value                 LONGBLOB,
  PRIMARY KEY(Hash)
);
