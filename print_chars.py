with open("static/assets/index-6WLwG8wz.js", "r", encoding="utf-8") as f:
    content = f.read()

idx = content.find('Create Item"')
if idx != -1:
    print("Found 'Create Item' at:", idx)
    for i in range(idx, idx+70):
        print(f"Index {i}: {repr(content[i])}")
