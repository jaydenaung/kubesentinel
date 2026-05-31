# Entry point module for pip install — delegates to the kubectl-sentinel script.
import runpy, sys
from pathlib import Path

def main():
    script = Path(__file__).parent / "kubectl-sentinel"
    runpy.run_path(str(script), run_name="__main__")
