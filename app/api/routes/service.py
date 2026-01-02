from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/metrics")
def metrics() -> dict[str, str]:
    # Placeholder; integrate Prometheus if needed
    return {"metrics": "todo"}
