"""Allow offline usage with python -m slipcage_engine."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
