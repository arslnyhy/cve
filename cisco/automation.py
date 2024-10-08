import os
import re

def update_function_and_decorator_name(file_path):
    # Extract the base name of the file without extension
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    new_name = f"rule_{base_name}"

    with open(file_path, 'r') as file:
        lines = file.readlines()

    with open(file_path, 'w') as file:
        for line in lines:
            # Update the function name
            if line.strip().startswith("def rule_"):
                line = re.sub(r"def rule_\w+", f"def {new_name}", line)
            # Update the name in the decorator
            if line.strip().startswith("name="):
                line = re.sub(r"name='rule_\w+'", f"name='{new_name}'", line)
            file.write(line)

def update_all_files_in_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                update_function_and_decorator_name(file_path)

# Specify the directory containing the Python files
directory_path = '/root/cve/cisco/nx-os'
update_all_files_in_directory(directory_path)