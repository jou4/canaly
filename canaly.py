import sys
import argparse
import re
import datetime
import json
import bits as b

def load_stbl(file: str):
    """Load signal definition from .json file
    Args:
        file    file path of signal definition table in JSON format

    Returns:
        dict    dignal definition table
    """
    fp = open(file, "r", encoding="utf-8")
    json_list = json.load(fp)

    stbl = {}

    for r in json_list:
        canid = int(r["id"], 16)

        # continue if the ID is already appended
        # the same ID is possible to exists in signal table JSON file
        # because signal with the same ID but different length flows due to Gateway
        # the length depends on format (Classic/FD) supported by BUS
        # multiple definitions are necessary to support for different length signal
        if canid in stbl:
            continue

        multi_mode = False
        mode = None
        mode_dependent_values = {}

        for v in r["values"]:
            if v["mode_signal"] == 1:
                multi_mode = True
                mode = v

            if v["mode_dependent"] != "":
                mode_dependent_signal = int(v["mode_dependent"], 16)
                if mode_dependent_signal not in mode_dependent_values:
                    mode_dependent_values[mode_dependent_signal] = []
                mode_dependent_values[mode_dependent_signal].append(v)

        if multi_mode:
            stbl[canid] = {
                "id": canid,
                "name": r["name"],
                "mode": mode,
                "mode_dependent_values": mode_dependent_values,
                "multi_mode": multi_mode,
            }
        else:
            stbl[canid] = {
                "id": canid,
                "name": r["name"],
                "values": r["values"],
                "multi_mode": multi_mode,
            }

    return stbl


def analyze_data(bs: bytes, stbl: dict):
    """Analyze bytes as signal data based on definition
    Args:
        bs      array of byte
        stbl    table of signal definition

    Returns:
        list    fields data decoded with stbl
    """
    # initialize result
    fields = []

    # read value definition
    # if union-typed definition, read value definitions corresponding to mode
    if stbl["multi_mode"]:
        # identify mode
        mode_def = stbl["mode"]
        mode = b.extract_bits(bs, mode_def["start"], mode_def["length"])

        # append mode value to result signal
        fields.append({
            "name": mode_def["name"],
            "bits": mode,
            "value": mode,
            "desc": mode_def["desc"],
        })

        ds = stbl["mode_dependent_values"][mode]
    else:
        ds = stbl["values"]

    # read start positions
    ss = []
    for d in ds:
        ss.append(d["start"])

    # split bytes into bits by start position of each field
    bits_list = b.split_bits(bs, ss)

    # convert bits to value
    # possible to length of bits_list is smaller than length of ds
    # it may occur when Classic signal is processed by FD definition
    i = 0
    for bits in bits_list:
        d = ds[i]

        value = bits
        if(d["type"] == "float"):
            value = float(bits) * d["resolution"] + d["minimum"]

        fields.append({
            "name": d["name"],
            "bits": bits,
            "value": value,
            "unit": d["unit"],
            "desc": d["desc"],
        })

        i += 1


    return fields


PAT_CLASSIC = r'^\((?P<datetime>[A-Za-z0-9.]+)\) (?P<interface>[A-Za-z0-9]+) (?P<id>[A-Za-z0-9]+)#(?P<data>[A-Za-z0-9]+)'
PAT_FD = r'^\((?P<datetime>[A-Za-z0-9.]+)\) (?P<interface>[A-Za-z0-9]+) (?P<id>[A-Za-z0-9]+)##[0-9](?P<data>[A-Za-z0-9]+)'


def analyze(text, stbl):
    """Analyze CAN signal of CAN frame logfile format
    Args:
        text    signal text
        stbl    table of signal definition

    Returns:
        bool    True if decode with stbl succeeded, False if stbl does not have the definition of the CAN ID
        dict    data decoded from a line of CAN logfile format
    """
    # initialize result
    # store the original text
    result = False
    signal = {"text": text}

    # pattern matching
    match = re.search(PAT_CLASSIC, text)
    if not match:
        match = re.search(PAT_FD, text)

    if match:
        timestamp = float(match.group("datetime"))
        dt = datetime.datetime.fromtimestamp(timestamp)
        signal["timestamp"] = timestamp
        signal["dt"] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        signal["if"] = match.group("interface")
        signal["id"] = int(match.group("id"), 16)

        if signal["id"] in stbl:
            signal["fields"] = analyze_data(b.hexstr_to_bytes(match.group("data")), stbl[signal["id"]])
            result = True

    return result, signal


def find_field(name, fields):
    """Find a field data by name specified
    Args:
        name    field name
        fields  array of data in signal

    Returns:
        dict    field data, None if not found
    """
    for f in fields:
        if name == f["name"]:
            return f

    return None


def find_fields(names, fields):
    """Find fields data by name specified
    Args:
        names   array of field name
        fields  array of data in signal

    Returns:
        dict    fields data, key is name, value is dict of a field data
    """
    fs = {}

    for name in names:
        f = find_field(name, fields)
        if f:
            fs[name] = f

    return fs


def format_name_and_value(item: tuple):
    return f"{item[0]}={item[1]['value']}"


def format_name_and_bits(item: tuple):
    return "%s=0x%X" % (item[0], item[1]['bits'])


def main():
    # get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", action="store_true", help="show all values in the signal")
    parser.add_argument("-b", "--bits", action="store_true", help="show values as bits of data")
    parser.add_argument("--fd", action="store_true", help="process as CAN-FD format (@Depreciated)")
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
    parser.add_argument("stbl", help="JSON file of signal definition table")
    parser.add_argument("fields", nargs="*", help="fields to show values in the signal")
    args = parser.parse_args()

    # CAN signal definition table
    stbl = load_stbl(args.stbl)

    # process each line in CAN frame logfile format
    while True:
        # read a line
        line = sys.stdin.readline()

        if not line:
            break

        # analyze text using stbl
        # res will be True if stbl has a definition of the CAN ID
        res, signal = analyze(line.rstrip('\r\n'), stbl)

        # print text then go to next if CAN ID is not found in stbl
        if not res:
            print(signal["text"])
            continue

        # identify field data to be detailed in remark
        field_names = args.fields
        if args.all:
            field_names = list(map(lambda f: f["name"], signal["fields"]))

        fields = find_fields(field_names, signal["fields"])

        # generate remark text
        formatter = format_name_and_value
        if args.bits:
            formatter = format_name_and_bits

        remark_items = list(map(formatter, fields.items()))
        if args.verbosity >= 1:
            remark_items = list(map(
                lambda x, item: f"{x} ({item['unit']} | {item['desc']})",
                remark_items,
                fields.values()))

        # print text according to verbosity level
        if args.verbosity >= 3:
            print(signal)
        else:
            ex = ", ".join(remark_items)
            if len(ex) > 0:
                print("%s : %s" % (signal["text"], ex))
            else:
                print(signal["text"])

    return 0


if __name__ == '__main__':
    sys.exit(main())

