import pytest

from app import store as store_mod


@pytest.fixture()
def tmp_store(tmp_path):
    s = store_mod.Store(tmp_path / "test.db")
    store_mod.set_store(s)
    yield s
    store_mod.set_store(None)
