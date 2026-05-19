import asyncio
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.db.session import init_db


async def main() -> None:
    await init_db()
    print("Initialized database tables.")


if __name__ == "__main__":
    asyncio.run(main())
