
CREATE TABLE IF NOT EXISTS ValueMapping(
  Hash                  VARCHAR(60) NOT NULL,
  Value                 LONGBLOB,
  PRIMARY KEY(Hash)
);
