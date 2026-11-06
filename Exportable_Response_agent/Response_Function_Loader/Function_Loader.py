import json
import importlib
from pathlib import Path


def load_functions(folder_name, json_name):
    """
    Loads functions from a JSON registry.

    Returns:
        Dictionary mapping action names to Python functions.
    """

    functions = {}

    # Location of Function_Loader.py
    base_path = Path(__file__).resolve().parent

    # Location of requested JSON registry
    json_path = base_path / folder_name / json_name

    # Read registry
    with open(json_path, "r", encoding="utf-8") as file:
        function_info = json.load(file)

    # Import each function
    for name, info in function_info.items():

        module = importlib.import_module(info["module"])

        function = getattr(module, info["function"])

        if not callable(function):
            raise TypeError(f"{name} is not callable")

        functions[name] = function

    return functions

if __name__ == "__main__":

    Actions = load_functions("Actions", "Actions_List.json")

    print(Actions.keys())

    print(callable(Actions["restrict_ingress_egress_baseline"]))
