import pytest
from app.core.database import init_db


@pytest.fixture(autouse=True)
async def setup_database():
    await init_db()

