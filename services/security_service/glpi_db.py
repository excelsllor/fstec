"""Read-only inventory lookups directly from the GLPI database."""
import asyncio
import re

from security_service.cmdb import InventoryItem
from security_service.versioning import match_product, product_search_terms
from shared.config import (GLPI_DB_CHARSET, GLPI_DB_HOST, GLPI_DB_NAME,
                           GLPI_DB_PASSWORD, GLPI_DB_PORT, GLPI_DB_PREFIX,
                           GLPI_DB_USER, GLPI_MAX_SOFTWARE, GLPI_MAX_VERSIONS)


class GlpiDBError(RuntimeError):
    pass


def _matches_product(candidate: str, target: str) -> bool:
    return match_product(candidate, target)


class GlpiDB:
    def __init__(self, *, host: str = GLPI_DB_HOST, port: int = GLPI_DB_PORT,
                 database: str = GLPI_DB_NAME, user: str = GLPI_DB_USER,
                 password: str = GLPI_DB_PASSWORD, charset: str = GLPI_DB_CHARSET,
                 prefix: str = GLPI_DB_PREFIX, max_software: int = GLPI_MAX_SOFTWARE,
                 max_versions: int = GLPI_MAX_VERSIONS):
        if not host or not database or not user:
            raise GlpiDBError(
                "GLPI_DB_HOST/GLPI_DB_NAME/GLPI_DB_USER обязательны для CMDB_PROVIDER=glpi с БД"
            )
        if not re.fullmatch(r"[A-Za-z0-9_]+", prefix or ""):
            raise GlpiDBError("GLPI_DB_PREFIX содержит недопустимые символы")
        self.host = host
        self.port = int(port)
        self.database = database
        self.user = user
        self.password = password
        self.charset = charset
        self.prefix = prefix
        self.max_software = max(1, int(max_software))
        self.max_versions = max(1, int(max_versions))

    def _connect(self):
        try:
            import pymysql
        except ImportError as exc:
            raise GlpiDBError("Для GLPI DB установите PyMySQL (pip install PyMySQL)") from exc
        return pymysql.connect(
            host=self.host, port=self.port, user=self.user, password=self.password,
            database=self.database, charset=self.charset, cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5, read_timeout=10, write_timeout=10, autocommit=True,
        )

    def _find_sync(self, product: str) -> list[InventoryItem]:
        product = (product or "").strip()
        if not product:
            return []
        terms = product_search_terms(product)
        software_table = f"{self.prefix}software"
        versions_table = f"{self.prefix}softwareversions"
        installs_table = f"{self.prefix}computers_softwareversions"
        computers_table = f"{self.prefix}computers"
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                clauses = " OR ".join(["LOWER(name) LIKE LOWER(%s)"] * len(terms))
                params = [f"%{term}%" for term in terms]
                params.append(self.max_software * 10)
                cur.execute(  # nosec B608
                    f"SELECT id, name FROM {software_table} "  # nosec B608
                    f"WHERE is_deleted = 0 AND ({clauses}) "
                    "ORDER BY name LIMIT %s",
                    tuple(params),
                )
                software_rows = [
                    row for row in cur.fetchall()
                    if _matches_product(str(row.get("name") or ""), product)
                ][:self.max_software]
                if not software_rows:
                    return []
                ids = [int(row["id"]) for row in software_rows]
                placeholders = ",".join(["%s"] * len(ids))
                cur.execute(  # nosec B608
                    f"SELECT s.name AS software_name, sv.name AS version, "  # nosec B608
                    f"COUNT(DISTINCT c.id) AS assets, MAX(csv.date_install) AS last_seen "
                    f"FROM {installs_table} csv "
                    f"JOIN {versions_table} sv ON sv.id = csv.softwareversions_id "
                    f"JOIN {software_table} s ON s.id = sv.software_id "
                    f"JOIN {computers_table} c ON c.id = csv.computers_id "
                    "WHERE s.id IN (" + placeholders + ") "
                    "AND s.is_deleted = 0 AND c.is_deleted = 0 AND csv.is_deleted = 0 "
                    "AND sv.is_deleted = 0 "
                    "AND (csv.date_uninstall IS NULL OR CAST(csv.date_uninstall AS CHAR) LIKE '0000-00-00%') "
                    "GROUP BY s.id, s.name, sv.id, sv.name "
                    "ORDER BY last_seen DESC, version DESC LIMIT %s",
                    (*ids, self.max_versions),
                )
                rows = cur.fetchall()
        finally:
            conn.close()

        out = []
        for row in rows:
            out.append(InventoryItem(
                name=str(row.get("software_name") or ""),
                version=str(row.get("version") or ""),
                server=f"{int(row.get('assets') or 0)} ПК",
                last_seen=str(row.get("last_seen") or ""),
                installed=True,
                assets=int(row.get("assets") or 0),
            ))
        return out

    async def find_many(self, product: str) -> list[InventoryItem]:
        return await asyncio.to_thread(self._find_sync, product)
