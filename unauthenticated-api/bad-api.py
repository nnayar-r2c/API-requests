from fastapi import Security
from pydantic import BaseModel
from my_api import security

router = APIRouter(route_class=ApiRoute)

# ruleid:unauthenticated_endpoints_write
@router.post(
    "/scope/{scope:path}",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Security(),
    ],
)
async def new_scope(response: Response, storageDepends=get_storage(), scope: str = Path(regex=SCOPE_REGEX)):
    try:
        res = await storage.create_or_update_scope(scope)
    except sqlalchemy.exc.IntegrityError as ei:
        logger.error(f"Trying to create scope that is invalid {ei}.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scope")
    if not res:
        response.status_code = status.HTTP_200_OK
        logger.warning(f"create(scope): scope existed and was active")

# ruleid:unauthenticated_endpoints_write
@router.post(
    "/scope/{scope:path}",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Security(security.authz.has_scopes, scopes=[security.ProjectScope.READ.value]),
    ],
)
async def new_scope(response: Response, storageDepends=get_storage(), scope: str = Path(regex=SCOPE_REGEX)):
    try:
        res = await storage.create_or_update_scope(scope)
    except sqlalchemy.exc.IntegrityError as ei:
        logger.error(f"Trying to create scope that is invalid {ei}.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scope")
    if not res:
        response.status_code = status.HTTP_200_OK
        logger.warning(f"create(scope): scope existed and was active")

# ok:unauthenticated_endpoints_write
@router.post(
    "/scope/{scope:path}",
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Security(security.authz.has_scopes, scopes=[security.ProjectScope.WRITE.value]),
    ],
)
async def new_scope(response: Response, storageDepends=get_storage(), scope: str = Path(regex=SCOPE_REGEX)):
    try:
        res = await storage.create_or_update_scope(scope)
    except sqlalchemy.exc.IntegrityError as ei:
        logger.error(f"Trying to create scope that is invalid {ei}.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scope")
    if not res:
        response.status_code = status.HTTP_200_OK
        logger.warning(f"create(scope): scope existed and was active")

