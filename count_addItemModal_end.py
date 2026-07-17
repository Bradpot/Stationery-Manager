with open("static/assets/index-6WLwG8wz.js", "r", encoding="utf-8") as f:
    content = f.read()

idx = content.find('children:h?"Save Changes":"Create Item"')
if idx != -1:
    sub = content[idx:idx+150]
    print("Rep of characters after 'Create Item':")
    print(repr(sub))
