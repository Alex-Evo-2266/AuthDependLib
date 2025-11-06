import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from fastapi import status, Depends
from httpx import AsyncClient
from fastapi.exceptions import HTTPException

from auth_dep_lib.depends.auth import auth_privilege_dep, split_privilege  # ← замени your_module на имя файла


@pytest.mark.asyncio
async def test_split_privilege():
    assert split_privilege("admin,user") == ["admin", "user"]
    assert split_privilege(" admin , user , test ") == ["admin", "user", "test"]
    assert split_privilege("") == [""]


@pytest.mark.asyncio
async def test_auth_privilege_dep_success():
    """Тест успешной проверки привилегий"""
    dep = auth_privilege_dep("admin")
    app = FastAPI()

    @app.get("/test", dependencies=[Depends(dep)])
    async def test_endpoint(request: Request):
        return {"ok": True}

    headers = {
        "authorization": "Bearer token",
        "x-status-auth": "ok",
        "x-forwarded-for": "127.0.0.1",
        "x-user-id": "123",
        "x-user-role": "user",
        "host": "localhost",
        "x-user-privilege": "admin,user",
    }

    request = Request(
        {
            "type": "http",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
    )

    user_id = await dep(request)
    assert user_id == "123"


@pytest.mark.asyncio
async def test_auth_privilege_dep_invalid_privilege():
    """Тест с неправильными привилегиями"""
    dep = auth_privilege_dep("admin")
    headers = {
        "authorization": "Bearer token",
        "x-status-auth": "ok",
        "x-forwarded-for": "127.0.0.1",
        "x-user-id": "123",
        "x-user-role": "user",
        "host": "localhost",
        "x-user-privilege": "viewer,editor",
    }

    request = Request(
        {
            "type": "http",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
    )

    with pytest.raises(HTTPException) as exc:
        await dep(request)
    assert exc.value.status_code == 403
    assert exc.value.detail == "invalid privilege"


@pytest.mark.asyncio
async def test_auth_privilege_dep_missing_headers():
    """Тест при отсутствии нужных заголовков"""
    dep = auth_privilege_dep("admin")
    headers = {
        "authorization": "Bearer token",
        "x-status-auth": "ok",
        "host": "localhost",
    }

    request = Request(
        {
            "type": "http",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
    )

    with pytest.raises(HTTPException) as exc:
        await dep(request)
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid auth data"


@pytest.mark.asyncio
async def test_auth_privilege_dep_exception_handling(monkeypatch):
    """Тест, если внутри возникает непредвиденная ошибка"""
    dep = auth_privilege_dep("admin")

    def bad_headers_get(key):
        raise ValueError("boom")
    
    class BadRequest:
        headers = {"authorization": bad_headers_get}

    request = BadRequest()

    with pytest.raises(HTTPException) as exc:
        await dep(request)
    assert exc.value.status_code == 400
    assert exc.value.detail == "invalid data"
