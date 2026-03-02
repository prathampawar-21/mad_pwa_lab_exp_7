"""Build script for C acceleration libraries."""

import platform
import subprocess
import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent
LIB_DIR = SRC_DIR / "lib"


def get_lib_suffix() -> str:
    system = platform.system()
    return {"Windows": ".dll", "Darwin": ".dylib"}.get(system, ".so")


def check_gcc() -> bool:
    try:
        subprocess.run(["gcc", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def compile_library(src_files: list[str], output: str) -> bool:
    suffix = get_lib_suffix()
    lib_path = LIB_DIR / f"{output}{suffix}"
    src_paths = [str(SRC_DIR / f) for f in src_files]

    cmd = [
        "gcc", "-O3", "-Wall", "-shared", "-fPIC",
        "-o", str(lib_path),
    ] + src_paths

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Built {lib_path}")
            return True
        else:
            print(f"Failed to build {output}: {result.stderr}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"Error building {output}: {e}", file=sys.stderr)
        return False


def build_all() -> bool:
    if not check_gcc():
        print("gcc not found, skipping C acceleration build", file=sys.stderr)
        return False

    LIB_DIR.mkdir(exist_ok=True)
    success = True
    success &= compile_library(["ntt.c", "poly.c"], "libntt")
    success &= compile_library(["keccak.c"], "libkeccak")
    return success


if __name__ == "__main__":
    sys.exit(0 if build_all() else 1)
