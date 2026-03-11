from engines.taint import run_taint


def test_taint_finds_input_to_os_system() -> None:
    code = """
import os

def main():
    user = input("name? ")
    cmd = user
    os.system(cmd)
"""
    report = run_taint(code)
    assert report.findings, "Expected at least one taint finding"
    names = {f.sink_func for f in report.findings}
    assert "os.system" in names

