import os

from psycopg.rows import dict_row       # how app will return query results
from psycopg_pool import ConnectionPool # how app will connect to the database

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://miniapp:miniapp@localhost:5432/miniapp"
)

pool = ConnectionPool(
    DATABASE_URL,
    min_size=2,
    max_size=30,
    kwargs={"row_factory": dict_row, "autocommit": True},
    open=False,
)
