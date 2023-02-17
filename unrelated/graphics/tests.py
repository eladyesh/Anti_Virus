import yara

rule = yara.compile(source=rule_text)

executable_file = "virus.exe"

matches = rule.match(executable_file)

for match in matches:
    param = match.meta["param"]
    value = match.meta["value"]
    print(f"Matched 'open' call with parameter '{param}': {value}")