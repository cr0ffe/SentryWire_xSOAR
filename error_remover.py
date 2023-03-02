"""
Removes some missing function errors from integration
"""
from typing import Any, Dict, Tuple, List, Optional, Union, cast

def set_integration_context(x):
    return 0


def return_error(x):
    raise Exception(x)


def CommandResults(readable_output: str, outputs_prefix: str, outputs_key_field: str, outputs: any) -> str:
    b = ""
    for i in range(int(len(readable_output)/3)):
        b += "="
    pretty = f"" \
             f"{outputs_prefix}\n{b}\n" \
             f"Readable Output:\n{readable_output}\n{b}\n" \
             f"Key:\n{outputs_key_field}\n{b}\n" \
             f"Raw:\n{outputs}"
    return pretty


def get_integration_context() -> str:
    return ""


def return_results(x: str) -> None:
    print(x)
    return None

def fileResult(*args):
    return ''
