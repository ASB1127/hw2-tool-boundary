import io
import os
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


class Kernel:
    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.namespace = {"WORKSPACE": str(self.workspace)}

    def run(self, script: str) -> dict:
        output = io.StringIO()
        stderr = io.StringIO()
        try:
            with redirect_stdout(output), redirect_stderr(stderr):
                original_directory = os.getcwd()
                try:
                    os.chdir(self.workspace)
                    exec(script, self.namespace)
                finally:
                    os.chdir(original_directory)
        except Exception:
            return {"ok": False, "output": output.getvalue(),
                    "stderr": stderr.getvalue(), "error": traceback.format_exc()}
        return {"ok": True, "output": output.getvalue(),
                "stderr": stderr.getvalue(), "error": ""}
