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


PAT_BO = r'^ *BO_ +(?P<id>[0-9]+) +(?P<msg_name>[A-Za-z0-9_\-]+) *: *(?P<dlc>[0-9]+) +(?P<tx_ecu>[A-Za-z0-9_\-]+) *'

PAT_SG = r'^ *SG_ +(?P<sig_name>[A-Za-z0-9_\-]+) +((?P<mux_ind>M)|m(?P<mux_mode>[0-9]+))* *: *(?P<start_bit>[0-9]+)\|(?P<length>[0-9]+)@(?P<byte_order>(0|1))(?P<signed>(\+|\-)) +\((?P<factor>[0-9.]+),(?P<offset>[0-9.]+)\) +\[(?P<min>\-?[0-9.]+)\|(?P<max>\-?[0-9.]+)\] +\"(?P<unit>[^\"]*)\" *(?P<rx_ecus>[A-Za-z0-9_\-,]+)*'

PAT_VAL = r'^ *VAL_ +(?P<id>[0-9]+) +(?P<sig_name>[A-Za-z0-9_\-]+) +(?P<mapping>[^;]+);'
PAT_MAPPING = r'([0-9]+) \"([^\"]*)\"'

MSB_POS_TABLE_BE = [
   7,  6,  5,  4,  3,  2,  1,  0
 ,15, 14, 13, 12, 11, 10,  9,  8
 ,23, 22, 21, 20, 19, 18, 17, 16
 ,31, 30, 29, 28, 27, 26, 25, 24
 ,39, 38, 37, 36, 35, 34, 33, 32
 ,47, 46, 45, 44, 43, 42, 41, 40
 ,55, 54, 53, 52, 51, 50, 49, 48
 ,63, 62, 61, 60, 59, 58, 57, 56
]

MSB_POS_TABLE_LE = [
  63, 62, 61, 60, 59, 58, 57, 56
 ,55, 54, 53, 52, 51, 50, 49, 48
 ,47, 46, 45, 44, 43, 42, 41, 40
 ,39, 38, 37, 36, 35, 34, 33, 32
 ,31, 30, 29, 28, 27, 26, 25, 24
 ,23, 22, 21, 20, 19, 18, 17, 16
 ,15, 14, 13, 12, 11, 10,  9,  8
 , 7,  6,  5,  4,  3,  2,  1,  0
]


def parse(dbc_files):
    """Parse multiple DBC files
    Args:
        dbc_files   array of file path

    Returns:
        stbl_dict   signal table as a dict of key=id
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
                    if byte_order == 0:
                        # BE
                        msb_pos = MSB_POS_TABLE_BE[start_bit]
                    else:
                        # LE
                        msb_pos = MSB_POS_TABLE_LE[start_bit + length - 1]
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
                        "start": msb_pos,
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

    return stbl


def merge(json_files):
    """Merge multiple JSON files of signal table
    Args:
        json_files  array of file path

    Returns:
        stbl_dict   signal table as a dict of key=id
    """
    stbl = {}

    for file in json_files:
        with open(file, "r", encoding="utf-8") as fp:
            json_list = json.load(fp)

            for r in json_list:
                stbl[r["id"]] = r

    return stbl


def main():
    # get arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="p(arse)|m(erge)")
    parser.add_argument("-O", "--output", help="output file")
    parser.add_argument("files", nargs="*", help="DBC files for parse, JSON files for merge")
    args = parser.parse_args()

    stbl_dict = {}
    command = args.command
    if command == 'p' or command == 'parse':
        stbl_dict = parse(args.files)
    elif command == 'm' or command == 'merge':
        stbl_dict = merge(args.files)
    else:
        parser.print_help()
        return 1

    stbl = list(stbl_dict.values())
    stbl.sort(key=lambda x: int(x["id"], 16))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fp:
            json.dump(stbl, fp)
    else:
        pprint.pprint(stbl)

    return 0


if __name__ == '__main__':
    sys.exit(main())

