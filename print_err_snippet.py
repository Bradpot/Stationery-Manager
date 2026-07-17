import subprocess

result = subprocess.run(['node', 'check_vm_syntax.js'], capture_output=True, text=True)
output = result.stdout + "\n" + result.stderr

lines = output.split('\n')
for idx, line in enumerate(lines):
    # Print the line and its length
    print(f"Line {idx} (length: {len(line)}): {repr(line[:100])}")
    if '^' in line:
        print("Caret is at index:", line.find('^'))
