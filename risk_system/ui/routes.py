from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from risk_system.config import settings

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(settings.paths.templates_dir))


@router.get("/", response_class=HTMLResponse)
def root_page(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "title": settings.api.title,
            "version": settings.api.version,
        },
    )


@router.get("/ui", response_class=HTMLResponse)
def ui_page(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "title": settings.api.title,
            "version": settings.api.version,
        },
    )


@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return templates.TemplateResponse(
        "about.html",
        {
            "request": request,
            "title": settings.api.title,
            "version": settings.api.version,
        },
    )