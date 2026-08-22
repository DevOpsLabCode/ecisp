from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Importing containment_models (not just app.db) is what actually registers
# ResponseRule/ResponseCommand on Base.metadata -- db.py itself never
# imports the models eagerly, to avoid a circular import (see its docstring).
from app.db import DATABASE_URL, Base
from app.runtimedefender import containment_models  # noqa: F401

config = context.config

# DATABASE_URL is app/db.py's own source of truth (env var, defaulting to a
# local SQLite file) -- read it from there instead of alembic.ini's
# `sqlalchemy.url` placeholder, so the two never drift apart.
config.set_main_option("sqlalchemy.url", DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
