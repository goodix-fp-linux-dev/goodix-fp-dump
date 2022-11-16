from driver_53x5 import DEFAULT_CONFIG


def get_sections(config):
    sections = []

    section_table = config[1:0x11]
    for section_table_offt in range(0, 0x10, 2):
        section_base = section_table[section_table_offt]
        section_size = section_table[section_table_offt + 1]

        section = config[section_base : section_base + section_size]
        sections.append(section)

    return sections


def parse_section(section):
    entries = []
    for entry_offt in range(0, len(section), 4):
        addr = int.from_bytes(section[entry_offt : entry_offt + 2], byteorder="little")
        value = int.from_bytes(
            section[entry_offt + 2 : entry_offt + 4], byteorder="little"
        )
        entries.append((addr, value))
    return entries


def main():
    sections = get_sections(DEFAULT_CONFIG)
    for section_idx, section in enumerate(sections):
        print()
        print(f"Section {section_idx}:")

        entries = parse_section(section)
        for entry in entries:
            addr, value = entry
            print(f"  {addr:x}:\t{value:x}")


if __name__ == "__main__":
    main()
