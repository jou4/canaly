import sys
import argparse
import re
import datetime
import json
import dbc
import bits as b


def read_json(file: str):
    """Read JSON file of signal definition
    Args:
        file    file path of signal definition table in JSON format

    Returns:
        list    signal definition table
    """
    json_list = []
    with open(file, "r", encoding="utf-8") as fp:
        json_list = json.load(fp)
    return json_list


def load_stbl(json_list: list):
    """Load signal definition table
    Args:
        json_list   signal definition table

    Returns:
        dict    signal definition table optimized for analysis
    """
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

        mux = False
        mux_indicator = None
        mux_mode_map = {}

        for v in r["values"]:
            if v["mux_indicator"]:
                mux = True
                mux_indicator = v

            if v["mux_mode"] != "":
                mux_mode = int(v["mux_mode"], 16)
                if mux_mode not in mux_mode_map:
                    mux_mode_map[mux_mode] = []
                mux_mode_map[mux_mode].append(v)

        if mux:
            stbl[canid] = {
                "id": canid,
                "name": r["name"],
                "mux_indicator": mux_indicator,
                "mux_mode_map": mux_mode_map,
                "mux": mux,
            }
        else:
            stbl[canid] = {
                "id": canid,
                "name": r["name"],
                "values": r["values"],
                "mux": mux,
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
    # if multiplexer definition, read value definitions corresponding to mode
    if stbl["mux"]:
        # identify mode
        mux_ind = stbl["mux_indicator"]
        mux_mode = b.extract_bits(bs, mux_ind["start"], mux_ind["length"])

        # append mode value to result signal
        fields.append({
            "name": mux_ind["name"],
            "bits": mux_mode,
            "value": mux_mode,
            "unit": mux_ind["unit"],
            "desc": mux_ind["desc"],
        })

        ds = stbl["mux_mode_map"][mux_mode]
    else:
        ds = stbl["values"]

    # TODO: consider byte_order

    # read start positions
    ss = []
    for d in ds:
        ss.append((d["start"], d["length"]))

    # split bytes into bits by start position and length of each field
    bits_list = b.slice_bits(bs, ss)

    # convert bits to value
    # possible to length of bits_list is smaller than length of ds
    # it may occur when Classic signal is processed by FD definition
    i = 0
    for bits in bits_list:
        d = ds[i]

        # TODO(?) transform bits as signed decimal when d["signed"] = True

        value = bits * d["factor"] + d["offset"]

        fields.append({
            "name": d["name"],
            "bits": bits,
            "value": value,
            "unit": d["unit"],
            "desc": d["desc"],
        })

        i += 1


    return fields


PAT_CLASSIC = re.compile(r'^\((?P<datetime>[\w.]+)\)\s+(?P<interface>\w+)\s+(?P<id>\w+)#(?P<data>\w+)')
PAT_FD = re.compile(r'^\((?P<datetime>[\w.]+)\)\s+(?P<interface>\w+)\s+(?P<id>\w+)##\d(?P<data>\w+)')


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
    match = PAT_CLASSIC.search(text)
    if not match:
        match = PAT_FD.search(text)

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


def match_fields(patterns, fields):
    """Find fields data by pattern specified
    Args:
        patterns    array of field name
        fields      array of data in signal

    Returns:
        dict    fields data, key is name, value is dict of a field data
    """
    fs = {}

    for f in fields:
        if any(list(map(lambda p: p.search(f["name"]), patterns))):
            fs[f["name"]] = f

    return fs


def format_name_and_value(delim="="):
    def wrapper(item: dict):
        return f"{item['name']}{delim}{item['value']}"
    return wrapper


def format_name_and_bits(delim="="):
    def wrapper(item: dict):
        return "%s%s0x%X" % (item['name'], delim, item['bits'])
    return wrapper


def clear_lines(n):
    for _ in range(n):
        sys.stdout.write("\033[F")   # move cursor to one above
        sys.stdout.write("\033[K")   # clear a line


def main():
    # get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", action="store_true", help="show all values in the signal")
    parser.add_argument("-b", "--bits", action="store_true", help="show values as raw data")
    parser.add_argument("-v", "--verbosity", action="count", default=0, help="increase output verbosity")
    parser.add_argument("-j", "--stbl", help="JSON file of signal definition table")
    parser.add_argument("-d", "--dbc", help="DBC file")
    parser.add_argument("-e", "--regexp", action="store_true", help="use fields as regular expression")
    parser.add_argument("-m", "--monitor", action="store_true", help="monitor focusing on specified fields")
    parser.add_argument("fields", nargs="*", help="fields to show values in the signal")
    args = parser.parse_args()

    # CAN signal definition table
    json_list = []
    if args.stbl:
        json_list = read_json(args.stbl)
    elif args.dbc:
        json_list = dbc.parse([args.dbc])
    else:
        print("either option of --stbl or --dbc is required.")
        parser.print_help()
        return 1

    stbl = load_stbl(json_list)

    monitoring_fields = {}

    # formatter for signal
    delim = "="
    if args.monitor:
        delim = "\t"

    formatter = format_name_and_value(delim)
    if args.bits:
        formatter = format_name_and_bits(delim)

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
        if args.regexp:
            # use regex patterns
            field_patterns = list(map(lambda f: re.compile(f), args.fields))
            fields = match_fields(field_patterns, signal["fields"])
        else:
            field_names = args.fields
            if args.all:
                field_names = list(map(lambda f: f["name"], signal["fields"]))
            fields = find_fields(field_names, signal["fields"])

        if args.monitor:
            line_num = len(monitoring_fields.keys())
            updated = False
            for k, v in fields.items():
                if k in monitoring_fields:
                    if monitoring_fields[k]["bits"] != v["bits"]:
                        monitoring_fields[k] = v
                        updated = True
                else:
                    monitoring_fields[k] = v
                    updated = True

            if updated:
                # generate remark text
                remark_items = map(formatter, monitoring_fields.values())
                if args.verbosity >= 1:
                    remark_items = map(
                        lambda x, item: "%s (%s)" % (x, "|".join(filter(lambda x: x, [item['unit'], item['desc']]))),
                        remark_items,
                        monitoring_fields.values())

                # print text
                clear_lines(line_num)
                print("\n".join(remark_items))

        else:
            # generate remark text
            remark_items = list(map(formatter, fields.values()))
            if args.verbosity >= 1:
                remark_items = list(map(
                    lambda x, item: "%s (%s)" % (x, "|".join(filter(lambda x: x, [item['unit'], item['desc']]))),
                    remark_items,
                    fields.values()))

            # print text according to verbosity level
            if args.verbosity >= 3:
                print(signal)
            else:
                ex = "\t".join(remark_items)
                if len(ex) > 0:
                    print("%s\t%s" % (signal["text"], ex))
                else:
                    print(signal["text"])

    return 0


if __name__ == '__main__':
    sys.exit(main())

