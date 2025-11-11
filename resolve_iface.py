import re

def normalize_npf(s: str) -> str:
    # collapse doubled backslashes from shell
    s = s.replace('\\\\', '\\')
    # if already full NPF path, just fix braces
    m = re.match(r'^\\Device\\NPF_\{?([0-9A-Fa-f\-]+)\}?$', s)
    if m:
        guid = m.group(1).strip('{}')
        return f"\\Device\\NPF_{{{guid}}}"
    return s  # not an NPF path; may be a name or index

def resolve_iface(arg):
    # allow index, friendly name, or NPF path
    try:
        from scapy.arch.windows import get_windows_if_list
        lst = get_windows_if_list()
    except Exception:
        lst = None

    # NPF path provided
    if arg.startswith('\\') or arg.startswith('\\\\'):
        return normalize_npf(arg)

    # numeric index
    if arg.isdigit() and lst:
        idx = int(arg) - 1
        guid = lst[idx]['guid'].strip('{}')
        return f"\\Device\\NPF_{{{guid}}}"

    # friendly name -> NPF
    if lst:
        for itf in lst:
            if itf['name'].lower() == arg.lower():
                guid = itf['guid'].strip('{}')
                return f"\\Device\\NPF_{{{guid}}}"

    return arg
