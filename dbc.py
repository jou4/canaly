import sys
import argparse
import re
import json
import pprint
import bits as b


def is_integer(n):
    try:
        float(n)
    except ValueError:
        return False
    else:
        return float(n).is_integer()


def hex2dec(s, bit):
    dec = int(s, 16)
    if dec >> bit:
        raise ValueError
    return dec - (dec >> (bit - 1) << bit)


PAT_BO = r'^ *BO_ +(?P<id>\d+) +(?P<msg_name>\w+) *: *(?P<dlc>\d+) +(?P<tx_ecu>\w+) *'
PAT_SG = r'^ *SG_ +(?P<sig_name>\w+) +((?P<mux_ind>M)|m(?P<mux_mode>\d+))* *: *(?P<start_bit>\d+)\|(?P<length>\d+)@(?P<byte_order>(0|1))(?P<signed>(\+|\-)) +\((?P<factor>[\d.]+),(?P<offset>[\d.]+)\) +\[(?P<min>\-?[\d.]+)\|(?P<max>\-?[\d.]+)\] +\"(?P<unit>[^\"]*)\" *(?P<rx_ecus>[\w,]+)*'
PAT_VAL = r'^ *VAL_ +(?P<id>\d+) +(?P<sig_name>\s+) +(?P<mapping>[^;]+);'
PAT_MAPPING = r'(\d+) \"([^\"]*)\"'


def bit_pos(start):
    byte_index = start >> 3
    bit_col = 7 - (start % 8)
    return (byte_index << 3) + bit_col


def parse(dbc_files):
    """Parse multiple DBC files
    Args:
        dbc_files   array of file path

    Returns:
        list   signal definition table
    """
    stbl = {}
    tmp_id = ""

    for file in dbc_files:
        with open(file, "r", encoding="utf-8") as fp:
            for line in fp:

                # BO record
                match = re.search(PAT_BO, line)
                if match:
                    id = format(int(match["id"]), 'X')
                    msg_name = match["msg_name"]
                    dlc = int(match["dlc"])
                    tx_ecu = match["tx_ecu"]

                    stbl[id] = {
                        "id": id,
                        "name": msg_name,
                        "values": []
                    }
                    tmp_id = id

                # SG record
                match = re.search(PAT_SG, line)
                if match:
                    sig_name = match["sig_name"]
                    mux_indicator = (match["mux_ind"] == 'M')
                    mux_mode = ""
                    if match["mux_mode"] is not None:
                        mux_mode = format(int(match["mux_mode"]), 'X')
                    start_bit = int(match["start_bit"])
                    length = int(match["length"])
                    byte_order = int(match["byte_order"])  # 0: BE, 1: LE
                    signed = (match["signed"] == '-')
                    factor = float(match["factor"])
                    if factor.is_integer():
                        factor = int(factor)
                    offset = float(match["offset"])
                    if offset.is_integer():
                        offset = int(offset)
                    min = float(match["min"])
                    max = float(match["max"])
                    unit = match["unit"]
                    rx_ecus = match["rx_ecus"]

                    stbl[tmp_id]["values"].append({
                        "start": bit_pos(start_bit),
                        "length": length,
                        "name": sig_name,
                        "byte_order": byte_order,
                        "signed": signed,
                        "mux_indicator": mux_indicator,
                        "mux_mode": mux_mode,
                        "factor": factor,
                        "offset": offset,
                        "min": min,
                        "max": max,
                        "unit": unit,
                        "desc": ""
                    })

                # VAL record
                match = re.search(PAT_VAL, line)
                if match:
                    id = format(int(match["id"]), 'X')
                    sig_name = match["sig_name"]
                    mapping = re.findall(PAT_MAPPING, match["mapping"])
                    desc = ", ".join(map(lambda x: "%s: %s" % x, mapping))

                    for sig_row in stbl[id]["values"]:
                        if sig_row["name"] == sig_name:
                            sig_row["desc"] = desc
                            break

    stbl_list = list(stbl.values())
    stbl_sort(stbl_list)
    return stbl_list


def merge(json_files):
    """Merge multiple JSON files of signal table
    Args:
        json_files  array of file path

    Returns:
        list   signal definition table
    """
    stbl = {}

    for file in json_files:
        with open(file, "r", encoding="utf-8") as fp:
            json_list = json.load(fp)

            for r in json_list:
                stbl[r["id"]] = r

    stbl_list = list(stbl.values())
    stbl_sort(stbl_list)
    return stbl_list


def stbl_sort(stbl):
    # sort by id
    stbl.sort(key=lambda x: int(x["id"], 16))
    # sort by start pos
    for r in stbl:
        r["values"].sort(key=lambda x: "%08s_%04d" % (x["mux_mode"], x["start"]))


def main():
    # get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="p(arse)|m(erge)")
    parser.add_argument("-O", "--output", help="output file")
    parser.add_argument("files", nargs="*", help="DBC files for parse, JSON files for merge")
    args = parser.parse_args()

    stbl = []
    command = args.command
    if command == 'p' or command == 'parse':
        stbl = parse(args.files)
    elif command == 'm' or command == 'merge':
        stbl = merge(args.files)
    else:
        parser.print_help()
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fp:
            json.dump(stbl, fp)
    else:
        pprint.pprint(stbl)

    return 0


if __name__ == '__main__':
    sys.exit(main())

