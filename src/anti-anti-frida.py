import lief
import sys
import random
import os
 
def log_color(msg):
    print(f"\033[1;31;40m{msg}\033[0m")
 
def replacer(input_file):
    # generate random "frida-agent-arm/64.so" name
    log_color(f"[*] Patch frida-agent: {input_file}")
    random_name = "".join(random.sample("ABCDEFGHIJKLMNOPQ", 5)) 
    log_color(f"[*] Patch `frida` to `{random_name}``")
 
    binary = lief.parse(input_file)
 
    if not binary:
        exit()
 
    for symbol in binary.symbols:  # Modify symbol name
        if symbol.name == "frida_agent_main":
            log_color(symbol.name)
            symbol.name = "banana_main"
 
        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)
            log_color(symbol.name)
 
        if "FRIDA" in symbol.name:
            log_color(symbol.name)
            symbol.name = symbol.name.replace("FRIDA", random_name)

 
    all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]  # Modify string characteristics and try to be the same as the source characters
    for section in binary.sections:
        log_color(section.name)
        if section.name != ".rodata":
            continue
        for patch_str in all_patch_string:
            addr_all = section.search_all(patch_str)  #Patch memory string
            for addr in addr_all:
                patch = [ord(n) for n in list(patch_str)[::-1]]
                log_color(f"[*] Current section name={section.name} offset={hex(section.file_offset  addr)} {patch_str}-{"".join(list(patch_str)[::-1])}")
                binary.patch_address(section.file_offset  addr, patch)
 
    binary.write(input_file)
 
    # gum-js-loop thread
    random_name = "".join(random.sample("abcdefghijklmn", 11))
    log_color(f"[*] Patch `gum-js-loop` to `{random_name}`")
    os.system(f"sed -b -i s/gum-js-loop/{random_name}/g {input_file}")
 
    # gmain thread
    random_name = "".join(random.sample("abcdefghijklmn", 5))
    log_color(f"[*] Patch `gmain` to `{random_name}`")
    os.system(f"sed -b -i s/gmain/{random_name}/g {input_file}")
 
    # gdbus thread
    random_name = "".join(random.sample("abcdefghijklmn", 5))
    log_color(f"[*] Patch `gdbus` to `{random_name}`")
    os.system(f"sed -b -i s/gdbus/{random_name}/g {input_file}")

if __name__ == "__main__":
    replacer(sys.argv[1])