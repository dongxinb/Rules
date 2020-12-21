import os
from os import path

def convert_rules(surge_rule_path: str):
    f = open(surge_rule_path)
    new_rule = ["payload:", ]

    for line in f.readlines():
        line = line.strip()

        if line.startswith("#"):
            new_rule.append("  " + line)
            continue
        elif line == "":
            new_rule.append("")
            continue

        parts = line.split(",", 1)
        if len(parts) < 2:
            print(f"[{surge_rule_path}] Line `{line}` is invalid")
            new_rule.append(f"  # Unrecognized rule: {line}")
            continue

        if parts[0] in ["IP-CIDR"]:
            new_rule.append(f"  - {line}")
        elif parts[0] in ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"]:
            # Clash doesn't support force-remote-dns
            sub_parts = parts[1].split(",", 1)
            rule = f"  - {parts[0]},{sub_parts[0]}"
            if len(sub_parts) > 1:
                rule += " # ," + sub_parts[1]
            new_rule.append(rule)
        else: 
            new_rule.append(f"  # Unsupported rule: {line}")

    print(f"Converted: {surge_rule_path}")
    return "\n".join(new_rule)


surge_rule_folder = "SurgeRules"
clash_rule_folder = "Rules"

surge_rule_files = [filename for filename in os.listdir(surge_rule_folder) if filename.endswith(".list")]
if len(surge_rule_files) == 0:
    exit()

if not path.isdir(clash_rule_folder):
    os.mkdir(clash_rule_folder)

for rule_file in surge_rule_files:
    clash_rules = convert_rules(path.join(surge_rule_folder, rule_file))
    f = open(path.join(clash_rule_folder, path.splitext(rule_file)[0] + ".yaml"), "w")
    f.write(clash_rules)
    f.close()