import sys
from pathlib import Path


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from backend.app.orchestration.graph import get_case_workflow_mermaid

    docs_dir = repo_root / "docs"
    docs_dir.mkdir(exist_ok=True)

    mermaid_text = get_case_workflow_mermaid()
    mermaid_file = docs_dir / "workflow.mmd"
    markdown_file = docs_dir / "workflow.md"

    mermaid_file.write_text(mermaid_text + "\n", encoding="utf-8")
    markdown_file.write_text(
        "# Workflow Diagram\n\n"
        "This file is generated from `backend/app/orchestration/graph.py`.\n\n"
        "```mermaid\n"
        f"{mermaid_text}\n"
        "```\n",
        encoding="utf-8",
    )

    print(f"Wrote {mermaid_file}")
    print(f"Wrote {markdown_file}")


if __name__ == "__main__":
    main()
