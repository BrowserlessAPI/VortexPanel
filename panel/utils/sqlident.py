"""MySQL/MariaDB identifiers in GRANT ... ON `db`.*

In a database-level GRANT, `_` and `%` in the database name are wildcards:
GRANT ON `shop_a`.* also matches a database called `shopXa`. Escaping them
gives the grant to exactly this database."""


def grant_db(name):
    return str(name).replace('`', '').replace('\\', '\\\\').replace('_', '\\_').replace('%', '\\%')
