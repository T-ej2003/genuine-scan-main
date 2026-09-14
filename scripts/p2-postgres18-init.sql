-- Model the production broker without PostgreSQL 18's automatic CREATEROLE ADMIN memberships.
CREATE ROLE "certification-administrator"
  LOGIN
  SUPERUSER
  CREATEDB
  CREATEROLE
  NOINHERIT
  NOBYPASSRLS;
